/***************************************************************
 *
 * Copyright (C) 1990-2007, Condor Team, Computer Sciences Department,
 * University of Wisconsin-Madison, WI.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

#include "condor_common.h"
#include "condor_debug.h"
#include "condor_config.h"
#include "condor_string.h"
#include "string_list.h"
#include "condor_attributes.h"
#include "condor_classad.h"
#include "condor_daemon_core.h"
#include "MyString.h"
#include "gahp_common.h"
#include "my_popen.h"
#include "vmgahp_common.h"
#include "vm_request.h"
#include "vmgahp.h"
#include "vmgahp_error_codes.h"
#include "condor_vm_universe_types.h"
#include "../condor_privsep/condor_privsep.h"
#include "sig_install.h"
#include "../condor_privsep/privsep_fork_exec.h"

// FreeBSD 6, OS X 10.4, Solaris 5.9 don't automatically give you environ to work with
extern DLL_IMPORT_MAGIC char **environ;

MyString caller_name;
MyString job_user_name;

uid_t caller_uid = ROOT_UID;
gid_t caller_gid = ROOT_UID;
uid_t job_user_uid = ROOT_UID;
uid_t job_user_gid = ROOT_UID;

const char *support_vms_list[] = {
#if defined(LINUX)
CONDOR_VM_UNIVERSE_XEN,
CONDOR_VM_UNIVERSE_KVM,
#endif
#if defined(LINUX) || defined(WIN32)
CONDOR_VM_UNIVERSE_VMWARE,
#endif
NULL
};

// parse raw string into args
bool parse_vmgahp_command(const char* raw, Gahp_Args& args) 
{
	if (!raw) {
		vmprintf(D_ALWAYS,"ERROR parse_vmgahp_command: empty command\n");
		return false;
	}

	args.reset();

	int len=strlen(raw);

	char * buff = (char*)malloc(len+1);
	ASSERT( buff != NULL );
	int buff_len = 0;

	for (int i = 0; i<len; i++) {

		if ( raw[i] == '\\' ) {
			i++; 			//skip this char
			if (i<(len-1)) {
				buff[buff_len++] = raw[i];
			}
			continue;
		}

		/* Check if charcater read was whitespace */
		if ( raw[i]==' ' || raw[i]=='\t' || raw[i]=='\r' || raw[i] == '\n') {

			/* Handle Transparency: we would only see these chars
			if they WEREN'T escaped, so treat them as arg separators
			*/
			buff[buff_len++] = '\0';
			args.add_arg( strdup(buff) );
			buff_len = 0;	// re-set temporary buffer

		} else {
			// It's just a regular character, save it
			buff[buff_len++] = raw[i];
		}
	}

	/* Copy the last portion */
	buff[buff_len++] = '\0';
	args.add_arg(strdup(buff) );

	free (buff);
	return true;
}

// Check whether the given vmtype is in supported vmtype list
bool 
verify_vm_type(const char *vmtype)
{
	int i=0;
	while(support_vms_list[i] != NULL) {
		if(strcasecmp(vmtype, support_vms_list[i]) == 0 ) {
			return true;
		}
		i++;
	}
	vmprintf(D_ALWAYS, "Not supported VM TYPE(%s)\n", vmtype);
	return false;
}


bool
check_vm_read_access_file(const char *file, bool is_root /*false*/)
{
	if( (file == NULL) || (file[0] == '\0') ) {
		return false;
	}

	priv_state priv = PRIV_UNKNOWN;
	if( is_root ) {
		priv = set_root_priv();
	}
	int ret = access(file, R_OK);
	if( is_root ) {
		set_priv(priv);
	}

	if( ret < 0 ) {
		vmprintf(D_ALWAYS, "File(%s) can't be read\n", file);
		return false;
	}
	return true;
}

bool
check_vm_write_access_file(const char *file, bool is_root /*false*/)
{
	if( (file == NULL) || (file[0] == '\0') ) {
		return false;
	}

	priv_state priv = PRIV_UNKNOWN;
	if( is_root ) {
		priv = set_root_priv();
	}
	int ret = access(file, W_OK);
	if( is_root ) {
		set_priv(priv);
	}

	if( ret < 0 ) {
		vmprintf(D_ALWAYS, "File(%s) can't be modified\n", file);
		return false;
	}
	return true;
}

bool
check_vm_execute_file(const char *file, bool is_root /*false*/)
{
	if( (file == NULL) || (file[0] == '\0') ) {
		return false;
	}

	priv_state priv = PRIV_UNKNOWN;
	if( is_root ) {
		priv = set_root_priv();
	}
	int ret = access(file, X_OK);
	if( is_root ) {
		set_priv(priv);
	}

	if( ret < 0 ) {
		vmprintf(D_ALWAYS, "File(%s) can't be executed\n", file);
		return false;
	}
	return true;
}

bool
write_local_settings_from_file(FILE* out_fp,
                               const char* param_name,
                               const char* start_mark,
                               const char* end_mark)
{
	char* tmp = param(param_name);
	if (tmp == NULL) {
		return true;
	}
	MyString local_settings_file = tmp;
	free(tmp);
	if (start_mark != NULL) {
		if (fprintf(out_fp, "%s\n", start_mark) < 0) {
			vmprintf(D_ALWAYS,
			         "fprintf error writing start marker: %s\n",
			         strerror(errno));
			return false;
		}
	}
	FILE* in_fp = safe_fopen_wrapper_follow(local_settings_file.Value(), "r");
	if (in_fp == NULL) {
		vmprintf(D_ALWAYS,
		         "fopen error on %s: %s\n",
		         local_settings_file.Value(),
		         strerror(errno));
		return false;
	}
	MyString line;
	while (line.readLine(in_fp)) {
		if (fputs(line.Value(), out_fp) == EOF) {
			vmprintf(D_ALWAYS,
			         "fputs error copying local settings: %s\n",
			         strerror(errno));
			fclose(in_fp);
			return false;
		}
	}
	fclose(in_fp);
	if (end_mark != NULL) {
		if (fprintf(out_fp, "%s\n", end_mark) == EOF) {
			vmprintf(D_ALWAYS,
			         "fputs error writing end marker: %s\n",
			         strerror(errno));
			return false;
		}
	}
	return true;
}

// extract the n-th field string from string result.
// field_num starts from 1.
// For example, if result_string is "10 0 internal_error",
// field_num = 1 will return "10";
// field_num = 2 will return "0";
// field_num = 3 will return "internal_error"
MyString parse_result_string( const char *result_string, int field_num)
{
	StringList result_list(result_string, " ");
	if( result_list.isEmpty() ) {
		return "";
	}

	if( field_num > result_list.number() ) {
		return "";
	}

	char *arg = NULL;
	int field = 0;
	result_list.rewind();
	while( (arg = result_list.next()) != NULL ) {
		field++;
		if( field == field_num ) {
			return arg;
		}
	}
	return "";
}

bool verify_digit_arg(const char *s)
{
	if( !s ) {
		return false;
	}
	unsigned int i = 0;
	for(i=0;i<strlen(s);i++) {
		if(!isdigit(s[i])) {
			vmprintf(D_ALWAYS, "Arg(%s) is not digit\n", s);
			return false;
		}
	}
	return true;
}

bool verify_number_args(const int is, const int should_be) 
{
	if( is != should_be) {
		vmprintf(D_ALWAYS, "Wrong # of args %d, should be %d\n", is, should_be);
		return false;
	}
	return true;
}

// Validate a result string
bool validate_vmgahp_result_string(const char *result_string)
{
	StringList result_list(result_string, " ");
	if( result_list.isEmpty() ) {
		return false;
	}

	// Format: <req_id> 0 <result1> ..
	// Format: <req_id> 1 <result1> ..

	if(result_list.number() < 3 ) {
		return false;
	}

	char *arg = NULL;
	result_list.rewind();

	// first arg must be digit
	arg = result_list.next();
	if( !arg || !verify_digit_arg(arg)) {
		vmprintf(D_ALWAYS, "First arg in result must be digit: %s\n", result_string);
		return false;
	}

	// second arg must be either 0 or 1
	arg = result_list.next();
	if( !arg || ( strcmp(arg, "0") && strcmp(arg, "1") ) ) {
		vmprintf(D_ALWAYS, "Second arg in result must be either 0 or 1: %s\n", result_string);
		return false;
	}

	return true;
}

void
write_to_daemoncore_pipe(int pipefd, const char* str, int len)
{
	if( pipefd == -1 || !str || len <= 0 || !daemonCore ) {
		return;
	}

	// Now flush:
	daemonCore->Write_Pipe( pipefd, str, len);
}

void
write_to_daemoncore_pipe(const char* fmt, ... )
{
	if( vmgahp_stdout_pipe == -1 ) {
		return;
	}

	MyString output;
	va_list args;
	va_start(args, fmt);
	output.vsprintf(fmt, args);
	write_to_daemoncore_pipe(vmgahp_stdout_pipe, 
			output.Value(), output.Length());
	va_end(args);
}

void
write_stderr_to_pipe()
{
	if( vmgahp_stderr_pipe == -1 ) {
		return;
	}

	vmgahp_stderr_buffer.Write();

	if( vmgahp_stderr_buffer.IsError() ) { 
		if( vmgahp_stderr_tid != -1 ) {
			daemonCore->Cancel_Timer(vmgahp_stderr_tid);
			vmgahp_stderr_tid = -1;
			vmgahp_stderr_pipe = -1;
		}
	}
}

#ifndef vmprintf
void vmprintf( int flags, const char *fmt, ... ) 
{
	int saved_flags = 0;
	static pid_t mypid = 0;

	if( !mypid ) {
		mypid = daemonCore->getpid();
	}

	if( !fmt ) {
		return;
	}

	if( !(flags & oriDebugFlags) ) {
		return;
	}

	saved_flags = oriDebugFlags;	/* Limit recursive calls */
	oriDebugFlags = 0;

	MyString output;
	va_list args;
	va_start(args, fmt);
	output.vsprintf(fmt, args);
	va_end(args);
	if( output.IsEmpty() ) {
		oriDebugFlags = saved_flags;
		return;
	}

	if( Termlog ) {
		if( (vmgahp_mode == VMGAHP_TEST_MODE) ||
				(vmgahp_mode == VMGAHP_KILL_MODE) ) {
			fprintf(stderr, "VMGAHP[%d]: %s", (int)mypid, output.Value());
			oriDebugFlags = saved_flags;
			return;
		}

		if( (vmgahp_stderr_tid != -1 ) &&
				(vmgahp_stderr_pipe != -1 )) {
			vmgahp_stderr_buffer.Write(output.Value());
			daemonCore->Reset_Timer(vmgahp_stderr_tid, 0, 2);
		}
	}else {
		dprintf(flags, "VMGAHP[%d]: %s", (int)mypid, output.Value());
	}
	oriDebugFlags = saved_flags;
}
#endif

void 
initialize_uids(void)
{
#if defined(WIN32)
#include "my_username.h"

	char *name = NULL;
	char *domain = NULL;

	name = my_username();
	domain = my_domainname();

	caller_name = name;
	job_user_name = name;

	if ( !init_user_ids(name, domain ) ) {
		// shouldn't happen - we always can get our own token
		vmprintf(D_ALWAYS, "Could not initialize user_priv with our own token!\n");
	}

	vmprintf(D_ALWAYS, "Initialize Uids: caller=%s@%s, job user=%s@%s\n", 
			caller_name.Value(), domain, job_user_name.Value(), domain);

	if( name ) {
		free(name);
	}
	if( domain ) {
		free(domain);
	}
	return;
#else
	// init_user_ids was called in main_pre_dc_init()
	vmprintf(D_ALWAYS, "Initial UID/GUID=%d/%d, EUID/EGUID=%d/%d, "
			"Condor UID/GID=%d,%d\n", (int)getuid(), (int)getuid(), 
			(int)geteuid(), (int)getegid(), 
			(int)get_condor_uid(), (int)get_condor_gid());

	vmprintf(D_ALWAYS, "Initialize Uids: caller=%s, job user=%s\n", 
			caller_name.Value(), job_user_name.Value());
	
	return;
#endif
}

uid_t 
get_caller_uid(void)
{
	return caller_uid;
}

gid_t 
get_caller_gid(void)
{
	return caller_gid;
}

uid_t 
get_job_user_uid(void)
{
	return job_user_uid;
}

gid_t 
get_job_user_gid(void)
{
	return job_user_gid;
}

const char* 
get_caller_name(void)
{
	return caller_name.Value();
}

const char* 
get_job_user_name(void)
{
	return job_user_name.Value();
}

bool canSwitchUid(void)
{
	return can_switch_ids();
}

/**
 * merge_stderr_with_stdout is intended for clients of this function
 * that wish to have the old behavior, where stderr and stdout were
 * both added to the same StringList.
 */
int systemCommand( ArgList &args, priv_state priv, StringList *cmd_out, StringList * cmd_in,
		   StringList *cmd_err, bool merge_stderr_with_stdout)
{
	int result = 0;
	FILE *fp = NULL;
	FILE * fp_for_stdin = NULL;
	FILE * childerr = NULL;
	MyString line;
	char buff[1024];
	StringList *my_cmd_out = cmd_out;

	priv_state prev = PRIV_UNKNOWN;

	int stdout_pipes[2];
	int stdin_pipes[2];
	int pid;
	bool use_privsep = false;
	switch ( priv ) {
	case PRIV_ROOT:
		prev = set_root_priv();
		break;
	case PRIV_USER:
	case PRIV_USER_FINAL:
		prev = set_user_priv();
#if !defined(WIN32)
		if ( privsep_enabled() && (job_user_uid != get_condor_uid()) ) {
			use_privsep = true;
		}
#endif
		break;
	default:
		// Stay as Condor user
		;
	}
#if defined(WIN32)
	if((cmd_in != NULL) || (cmd_err != NULL))
	  {
	    vmprintf(D_ALWAYS, "Invalid use of systemCommand() in Windows.\n");
	    return -1;
	  }
	//if ( use_privsep ) {
	//	fp = privsep_popen(args, "r", want_stderr, job_user_uid);
	//}
	//else {
	fp = my_popen( args, "r", merge_stderr_with_stdout );
	//}
#else
	// The old way of doing things (and the Win32 way of doing
	//	things)
	// fp = my_popen( args, "r", want_stderr );
	if((cmd_err != NULL) && merge_stderr_with_stdout)
	  {
	    vmprintf(D_ALWAYS, "Invalid use of systemCommand().\n");
	    return -1;
	  }

	PrivSepForkExec psforkexec;
	char ** args_array = args.GetStringArray();
	int error_pipe[2];
		// AIX 5.2, Solaris 5.9, HPUX 11 don't have AF_LOCAL

	if(pipe(stdin_pipes) < 0)
	  {
	    vmprintf(D_ALWAYS, "Error creating pipe: %s\n", strerror(errno));
		deleteStringArray( args_array );
	    return -1;
	  }
	if(pipe(stdout_pipes) < 0)
	  {
	    vmprintf(D_ALWAYS, "Error creating pipe: %s\n", strerror(errno));
	    close(stdin_pipes[0]);
	    close(stdin_pipes[1]);
		deleteStringArray( args_array );
	    return -1;
	  }

	if ( use_privsep ) {
	  if(!psforkexec.init())
	    {
	      vmprintf(D_ALWAYS,
		       "my_popenv failure on %s\n",
		       args_array[0]);
	      close(stdin_pipes[0]);
	      close(stdin_pipes[1]);
	      close(stdout_pipes[0]);
	      close(stdout_pipes[1]);
		  deleteStringArray( args_array );
	      return -1;
	    }
	}

	if(cmd_err != NULL)
	  {
	    if(pipe(error_pipe) < 0)
	      {
		vmprintf(D_ALWAYS, "Could not open pipe for error output: %s\n", strerror(errno));
		close(stdin_pipes[0]);
		close(stdin_pipes[1]);
		close(stdout_pipes[0]);
		close(stdout_pipes[1]);
		deleteStringArray( args_array );
		return -1;
	      }
	  }
	// Now fork and do what my_popen used to do
	pid = fork();
	if(pid < 0)
	  {
	    vmprintf(D_ALWAYS, "Error forking: %s\n", strerror(errno));
		close(stdin_pipes[0]);
		close(stdin_pipes[1]);
		close(stdout_pipes[0]);
		close(stdout_pipes[1]);
		if(cmd_err != NULL) {
			close(error_pipe[0]);
			close(error_pipe[1]);
		}
		deleteStringArray( args_array );
	    return -1;
	  }
	if(pid == 0)
	  {
	    close(stdout_pipes[0]);
	    close(stdin_pipes[1]);
	    dup2(stdout_pipes[1], STDOUT_FILENO);
	    dup2(stdin_pipes[0], STDIN_FILENO);

	    if(merge_stderr_with_stdout) dup2(stdout_pipes[1], STDERR_FILENO);
	    else if(cmd_err != NULL) 
	      {
		close(error_pipe[0]);
		dup2(error_pipe[1], STDERR_FILENO);
	      }


	    uid_t euid = geteuid();
	    gid_t egid = getegid();
	    seteuid( 0 );
	    setgroups( 1, &egid );
	    setgid( egid );
	    setuid( euid );
	    
	    install_sig_handler(SIGPIPE, SIG_DFL);
	    sigset_t sigs;
	    sigfillset(&sigs);
	    sigprocmask(SIG_UNBLOCK, &sigs, NULL);


	    MyString cmd = args_array[0];

	    if ( use_privsep ) {
	    
	      ArgList al;
	      psforkexec.in_child(cmd, al);
          deleteStringArray( args_array );
	      args_array = al.GetStringArray();
	    }


	    execvp(cmd.Value(), args_array);
	    vmprintf(D_ALWAYS, "Could not execute %s: %s\n", args_array[0], strerror(errno));
	    exit(-1);
	  }
	close(stdin_pipes[0]);
	close(stdout_pipes[1]);
	fp_for_stdin = fdopen(stdin_pipes[1], "w");
	fp = fdopen(stdout_pipes[0], "r");
	if(cmd_err != NULL)
	  {
	    close(error_pipe[1]);
	    childerr = fdopen(error_pipe[0],"r");
	    if(childerr == 0)
	      {
		vmprintf(D_ALWAYS, "Could not open pipe for reading child error output: %s\n", strerror(errno));
		close(error_pipe[0]);
		close(stdin_pipes[1]);
		close(stdout_pipes[0]);
	    fclose(fp);
		fclose(fp_for_stdin);
		deleteStringArray( args_array );
		return -1;
	      }
	  }

	if ( use_privsep ) {
	  FILE* _fp = psforkexec.parent_begin();
	  privsep_exec_set_uid(_fp, job_user_uid);
	  privsep_exec_set_path(_fp, args_array[0]);
	  privsep_exec_set_args(_fp, args);
	  Env env;
	  env.MergeFrom(environ);
	  privsep_exec_set_env(_fp, env);
	  privsep_exec_set_iwd(_fp, ".");

	  privsep_exec_set_inherit_fd(_fp, 1);
	  privsep_exec_set_inherit_fd(_fp, 2);
	  privsep_exec_set_inherit_fd(_fp, 0);
	
	  if (!psforkexec.parent_end()) {
	    vmprintf(D_ALWAYS,
		     "my_popenv failure on %s\n",
		     args_array[0]);
	    fclose(fp);
		fclose(fp_for_stdin);
		if (childerr) {
			fclose(childerr);
		}
		deleteStringArray( args_array );
	    return -1;
	  }
	}

	deleteStringArray( args_array );
#endif
	set_priv( prev );
	if ( fp == NULL ) {
		MyString args_string;
		args.GetArgsStringForDisplay( &args_string, 0 );
		vmprintf( D_ALWAYS, "Failed to execute command: %s\n",
				  args_string.Value() );
		if (childerr)
			fclose(childerr);
		return -1;
	}

	if(cmd_in != NULL) {
	  cmd_in->rewind();
	  char * tmp;
	  while((tmp = cmd_in->next()) != NULL)
	    {
	      fprintf(fp_for_stdin, "%s\n", tmp);
	      fflush(fp_for_stdin);
	    }
	}
	if (fp_for_stdin) {
	  // So that we will not be waiting for output while the
	  // script waits for stdin to be closed.
	  fclose(fp_for_stdin);
	}

	if ( my_cmd_out == NULL ) {
		my_cmd_out = new StringList();
	}

	while ( fgets( buff, sizeof(buff), fp ) != NULL ) {
		line += buff;
		if ( line.chomp() ) {
			my_cmd_out->append( line.Value() );
			line = "";
		}
	}

	if(cmd_err != NULL)
	  {
	    while(fgets(buff, sizeof(buff), childerr) != NULL)
	      {
		line += buff;
		if(line.chomp())
		  {
		    cmd_err->append(line.Value());
		    line = "";
		  }
	      }
	    fclose(childerr);
	  }
#if defined(WIN32)
	result = my_pclose( fp );
#else
	// Why close first?  Just in case the child process is waiting
	// on a read, and we have nothing more to send it.  It will
	// now receive a SIGPIPE.
	fclose(fp);
	if(waitpid(pid, &result, 0) < 0)
	  {
	    vmprintf(D_ALWAYS, "Unable to wait: %s\n", strerror(errno));
		if ( cmd_out == NULL ) {
			delete my_cmd_out;
		}
	   
	    return -1;
	  }
#endif
	if( result != 0 ) {
		MyString args_string;
		args.GetArgsStringForDisplay(&args_string,0);
		vmprintf(D_ALWAYS,
		         "Command returned non-zero: %s\n",
		         args_string.Value());
		my_cmd_out->rewind();
		const char *next_line;
		while ( (next_line = my_cmd_out->next()) ) {
			vmprintf( D_ALWAYS, "  %s\n", next_line );
		}
	}
	if ( cmd_out == NULL ) {
		delete my_cmd_out;
	}
	return result;
}

MyString
makeErrorMessage(const char* err_string)
{
	MyString buffer;

	if( err_string ) {
		for( int i = 0; err_string[i] != '\0'; i++ ) {
			switch( err_string[i] ) {
				case ' ':
				case '\\':
				case '\r':
				case '\n':
					buffer += '\\';
				default:
					buffer += err_string[i];
			}
		}
	}

	return buffer;
}
