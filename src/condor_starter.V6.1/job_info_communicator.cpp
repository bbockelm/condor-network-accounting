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
#include "condor_attributes.h"
#include "job_info_communicator.h"
#include "starter.h"
#include "condor_config.h"
#include "domain_tools.h"
#include "basename.h"
#include "../condor_privsep/condor_privsep.h"
#include "condor_vm_universe_types.h"
#include "hook_utils.h"
#include "classad_visa.h"
#include "subsystem_info.h"


extern CStarter *Starter;


JobInfoCommunicator::JobInfoCommunicator()
{
	job_ad = NULL;
	mach_ad = NULL;
	job_universe = CONDOR_UNIVERSE_VANILLA;
	job_cluster = -1;
	job_proc = -1;
	job_subproc = -1;
	u_log = new LocalUserLog( this );
	orig_job_name = NULL;
	job_input_name = NULL;
	job_output_name = NULL;
	job_error_name = NULL;
	job_iwd = NULL;
	job_remote_iwd = NULL;
	job_output_ad_file = NULL;
	job_output_ad_is_stdout = false;
	requested_exit = false;
	fast_exit = false;
	graceful_exit = false;
	had_remove = false;
	had_hold = false;
	change_iwd = false;
	user_priv_is_initialized = false;
	m_dedicated_execute_account = NULL;
#if HAVE_JOB_HOOKS
    m_hook_mgr = NULL;
	m_exit_hook_timer_tid = -1;
#endif
	m_periodic_job_update_tid = -1;
	m_allJobsDone_finished = false;
	m_enforce_limits = false;
}


JobInfoCommunicator::~JobInfoCommunicator()
{
	if( job_ad ) {
		delete job_ad;
	}
	if( mach_ad ) {
		delete mach_ad;
	}
	if( u_log ) {
		delete u_log;
	}
	if( orig_job_name ) {
		free( orig_job_name );
	}
	if( job_input_name ) {
		free( job_input_name);
	}
	if( job_output_name ) {
		free( job_output_name);
	}
	if( job_error_name ) {
		free( job_error_name);
	}
	if( job_iwd ) {
		free( job_iwd);
	}
	if( job_remote_iwd ) {
		free( job_remote_iwd );
	}
	if( job_output_ad_file ) {
		free( job_output_ad_file );
	}
#if HAVE_JOB_HOOKS
    if (m_hook_mgr) {
        delete m_hook_mgr;
    }
	if (m_exit_hook_timer_tid != -1) {
		daemonCore->Cancel_Timer(m_exit_hook_timer_tid);
		m_exit_hook_timer_tid = -1;
	}
#endif
	cancelUpdateTimer();
}


void
JobInfoCommunicator::setStdin( const char* path )
{
	if( job_input_name ) {
		free( job_input_name );
	}
	job_input_name = strdup( path );
}


void
JobInfoCommunicator::setStdout( const char* path )
{
	if( job_output_name ) {
		free( job_output_name );
	}
	job_output_name = strdup( path );
}


void
JobInfoCommunicator::setStderr( const char* path )
{
	if( job_error_name ) {
		free( job_error_name );
	}
	job_error_name = strdup( path );
}


const char*
JobInfoCommunicator::jobInputFilename( void )
{
	return (const char*) job_input_name;
}


const char*
JobInfoCommunicator::jobOutputFilename( void )
{
	return (const char*) job_output_name;
}


const char*
JobInfoCommunicator::jobErrorFilename( void )
{
	return (const char*) job_error_name;
}

bool
JobInfoCommunicator::streamInput()
{
	return false;
}

bool
JobInfoCommunicator::streamOutput()
{
	return false;
}

bool
JobInfoCommunicator::streamError()
{
	return false;
}

bool
JobInfoCommunicator::streamStdFile( const char *which )
{
	if(!strcmp(which,ATTR_JOB_INPUT)) {
		return streamInput();
	} else if(!strcmp(which,ATTR_JOB_OUTPUT)) {
		return streamOutput();
	} else if(!strcmp(which,ATTR_JOB_ERROR)) {
		return streamError();
	} else {
		return false;
	}
}


const char*
JobInfoCommunicator::jobIWD( void )
{
	return (const char*) job_iwd;
}

const char*
JobInfoCommunicator::jobRemoteIWD( void )
{
	if(!job_remote_iwd) return jobIWD();
	return (const char*) job_remote_iwd;
}


const char*
JobInfoCommunicator::origJobName( void )
{
	return (const char*) orig_job_name;
}


ClassAd*
JobInfoCommunicator::jobClassAd( void )
{
	return job_ad;
}


ClassAd*
JobInfoCommunicator::machClassAd( void )
{
	return mach_ad;
}


int
JobInfoCommunicator::jobUniverse( void )
{
	return job_universe;
}


int
JobInfoCommunicator::jobCluster( void )
{
	return job_cluster;
}


int
JobInfoCommunicator::jobProc( void )
{
	return job_proc;
}


int
JobInfoCommunicator::jobSubproc( void )
{
	return job_subproc;
}


void
JobInfoCommunicator::allJobsSpawned( void )
{
		// Now that everything is running, start a timer to handle
		// periodic job updates.
	startUpdateTimer();
}


bool
JobInfoCommunicator::allJobsDone( void )
{
		// Make sure we only call this once so that in case we need to
		// retry the job cleanup process, we don't repeat this step.
	if (m_allJobsDone_finished) {
		return true;
	}

		// Now that all the jobs are gone, we can stop our periodic updates.
		// It's safe to call this multiple times since it's just a no-op if
		// the timer is already canceled.
	cancelUpdateTimer();

#if HAVE_JOB_HOOKS
	if (m_hook_mgr) {
		static ClassAd* job_exit_ad = NULL;
		if (!job_exit_ad) {
			job_exit_ad = new ClassAd(*job_ad);
			Starter->publishJobExitAd(job_exit_ad);
		}
		const char* exit_reason = getExitReasonString();
		int rval = m_hook_mgr->tryHookJobExit(job_exit_ad, exit_reason);
		switch (rval) {
		case -1:   // Error
				// TODO: set a timer to retry allJobsDone()
			return false;
			break;

		case 0:    // Hook not configured
				// Nothing to do, break out and finish.
			break;

		case 1:    // Spawned the hook.
				// We need to bail now, and let the handler call
				// finishAllJobsDone() when the hook returns.
			// Create a timer to exit is the hook takes too long
			m_exit_hook_timer_tid = daemonCore->Register_Timer(m_hook_mgr->getExitHookTimeout(),
							(TimerHandlercpp)&JobInfoCommunicator::hookTimeout,
							"finishAllJobsDone",
							this);
			return false;
			break;
		}
	}
#endif /* HAVE_JOB_HOOKS */

		// If we're here, there was no hook and we're definitely done
		// with this step, so remember that in case of retries.
	m_allJobsDone_finished = true;
	return true;
}


#if HAVE_JOB_HOOKS
void
JobInfoCommunicator::hookTimeout( void )
{
	dprintf(D_FULLDEBUG, "Timed out waiting for hook to exit\n");
	finishAllJobsDone();
}


void
JobInfoCommunicator::finishAllJobsDone( void )
{
	if (m_exit_hook_timer_tid != -1) {
		daemonCore->Cancel_Timer(m_exit_hook_timer_tid);
		m_exit_hook_timer_tid = -1;
	}

		// Record the fact the hook finished.
	m_allJobsDone_finished = true;
		// Tell the starter to try job cleanup again so it can move on.
	Starter->allJobsDone();
}
#endif /* HAVE_JOB_HOOKS */


void
JobInfoCommunicator::gotShutdownFast( void )
{
		// Set our flag so we know we were asked to vacate.
	requested_exit = true;
	fast_exit = true;
}


void
JobInfoCommunicator::gotShutdownGraceful( void )
{
		// Set our flag so we know we were asked to vacate.
	requested_exit = true;
	graceful_exit = true;
}


void
JobInfoCommunicator::gotRemove( void )
{
		// Set our flag so we know we were asked to vacate.
	requested_exit = true;
	had_remove = true;
}


void
JobInfoCommunicator::gotHold( void )
{
		// Set our flag so we know we were asked to vacate.
	requested_exit = true;
	had_hold = true;
}


void
JobInfoCommunicator::setOutputAdFile( const char* path )
{
	if( job_output_ad_file ) {
		free( job_output_ad_file );
	}
	job_output_ad_file = strdup( path );
}


bool
JobInfoCommunicator::writeOutputAdFile( ClassAd* ad )
{
	if( ! job_output_ad_file ) {
		return false;
	}

	FILE* fp;
	if( job_output_ad_is_stdout ) {
		dprintf( D_ALWAYS, "Will write job output ClassAd to STDOUT\n" );
		fp = stdout;
	} else {
		fp = safe_fopen_wrapper_follow( job_output_ad_file, "a" );
		if( ! fp ) {
			dprintf( D_ALWAYS, "Failed to open job output ClassAd "
					 "\"%s\": %s (errno %d)\n", job_output_ad_file, 
					 strerror(errno), errno ); 
			return false;
		} else {
			dprintf( D_ALWAYS, "Writing job output ClassAd to \"%s\"\n", 
					 job_output_ad_file );

		}
	}
		// append a delimiter?
	ad->fPrint( fp );

	if( job_output_ad_is_stdout ) {
		fflush( fp );
	} else {
		fclose( fp );
	}
	return true;
}


// This has to be called after we know what the working directory is
// going to be, so we can make sure this is a full path...
void
JobInfoCommunicator::initOutputAdFile( void )
{
	if( ! job_output_ad_file ) {
		return;
	}
	if( job_output_ad_file[0] == '-' && job_output_ad_file[1] == '\0' ) {
		job_output_ad_is_stdout = true;
	} else if( ! fullpath(job_output_ad_file) ) {
		MyString path = Starter->GetWorkingDir();
		path += DIR_DELIM_CHAR;
		path += job_output_ad_file;
		free( job_output_ad_file );
		job_output_ad_file = strdup( path.Value() );
	}
	dprintf( D_ALWAYS, "Will write job output ClassAd to \"%s\"\n",
			 job_output_ad_is_stdout ? "STDOUT" : job_output_ad_file );
}



bool
JobInfoCommunicator::userPrivInitialized( void )
{
	return user_priv_is_initialized;
}

bool
JobInfoCommunicator::usingFileTransfer( void )
{
	return false;
}

bool
JobInfoCommunicator::updateX509Proxy( int /*cmd*/, ReliSock *  )
{
	return false;
}


bool
JobInfoCommunicator::initUserPrivNoOwner( void ) 
{
		// first, bale out if we really need ATTR_OWNER...
#ifdef WIN32
	return false;
#else
		// if we're root, we need ATTR_OWNER...
	if( getuid() == 0 ) {
		return false;
	}
#endif

		// if we're using PrivSep, we need ATTR_OWNER
	if (Starter->privSepHelper() != NULL) {
		return false;
	}

		// otherwise, we can't switch privs anyway, so consider
		// ourselves done. :) 
	dprintf( D_FULLDEBUG, 
			 "Starter running as '%s', no uid switching possible\n",
			 get_real_username() );
	user_priv_is_initialized = true;
	return true;
}

int JobInfoCommunicator::getStackSize(void)
{
	int value=0; // Return 0 by default
	if(job_ad && !job_ad->LookupInteger(ATTR_STACK_SIZE,value))
		value = 0;
	return value;
}

bool
JobInfoCommunicator::allowRunAsOwner( bool default_allow, bool default_request )
{
	ASSERT( job_ad );

		// First check if our policy allows RunAsOwner
		// Eval as an expression so a policy such as this can be specified:
		// TARGET.RunAsOwner =?= True

	bool run_as_owner = param_boolean( "STARTER_ALLOW_RUNAS_OWNER",
                                       default_allow, true, NULL, job_ad );

		// Next check if the job has requested runas_owner
	if( run_as_owner ) {
		bool user_wants_runas_owner = default_request;
		job_ad->LookupBool(ATTR_JOB_RUNAS_OWNER,user_wants_runas_owner);
		if ( !user_wants_runas_owner ) {
			run_as_owner = false;
		}
	}

	return run_as_owner;
}

bool
JobInfoCommunicator::checkDedicatedExecuteAccounts( char const *name )
{
	char const *EXECUTE_LOGIN_IS_DEDICATED = "EXECUTE_LOGIN_IS_DEDICATED";
	char const *DEDICATED_EXECUTE_ACCOUNT_REGEXP = "DEDICATED_EXECUTE_ACCOUNT_REGEXP";

	char *old_param_val = param(EXECUTE_LOGIN_IS_DEDICATED);
	char *pattern_string = param(DEDICATED_EXECUTE_ACCOUNT_REGEXP);

	if( !pattern_string || !*pattern_string ) {
		free(pattern_string);

		if( old_param_val ) {
			dprintf(D_ALWAYS,
					"WARNING: %s is deprecated.  Please use %s instead.\n",
					EXECUTE_LOGIN_IS_DEDICATED,
					DEDICATED_EXECUTE_ACCOUNT_REGEXP);
			free(old_param_val);
			return param_boolean(EXECUTE_LOGIN_IS_DEDICATED,false);
		}
		return false;
	}

	if( old_param_val ) {
		free( old_param_val );
		dprintf(D_ALWAYS,
				"WARNING: You have defined both %s and %s. "
				"Ignoring %s.\n",
				EXECUTE_LOGIN_IS_DEDICATED,
				DEDICATED_EXECUTE_ACCOUNT_REGEXP,
				EXECUTE_LOGIN_IS_DEDICATED);
	}

		// force the matching of the whole string
	MyString full_pattern;
	full_pattern.sprintf("^%s$",pattern_string);

	Regex re;
	char const *errstr = NULL;
	int erroffset = 0;

	if( !re.compile( full_pattern.Value(), &errstr, &erroffset, 0 ) ) {
		EXCEPT("Invalid regular expression for %s (%s): %s",
			   DEDICATED_EXECUTE_ACCOUNT_REGEXP,
			   pattern_string,
			   errstr);
	}
	free( pattern_string );

	if( re.match( name ) ) {
		return true;
	}
	return false;
}

void
JobInfoCommunicator::setExecuteAccountIsDedicated( char const *name )
{
	if( name == NULL ) {
		m_dedicated_execute_account_buf = "";
		m_dedicated_execute_account = NULL;
	}
	else {
		m_dedicated_execute_account_buf = name;
		m_dedicated_execute_account = m_dedicated_execute_account_buf.Value();
	}
}

#ifdef WIN32
#include "my_username.h"
bool
JobInfoCommunicator::initUserPrivWindows( void )
{
	// Win32
	// taken origionally from OsProc::StartJob.  Here we create the
	// user and initialize user_priv.

	// By default, assume execute login may be shared by other processes.
	setExecuteAccountIsDedicated( NULL );

	// we support running the job as other users if the user
	// is specifed in the config file, and the account's password
	// is properly stored in our credential stash.

	char *name = NULL;
	char *domain = NULL;
	bool init_priv_succeeded = true;
	bool run_as_owner = allowRunAsOwner( false, false );

	// TODO.. 
	// Currently vmgahp for VMware VM universe can't run as user on Windows.
	// It seems like a bug of VMware. VMware command line tool such as "vmrun" 
	// requires Administrator privilege.
	// So here we set name and domain with my_username and my_domainname
	// -jaeyoung 06/15/07
	if( job_universe == CONDOR_UNIVERSE_VM ) {
#if 0
		// If "VM_UNIV_NOBODY_USER" is defined in Condor configuration file, 
		// wee will use it.
		char *vm_jobs_as = param("VM_UNIV_NOBODY_USER");
		if (vm_jobs_as) {		
			getDomainAndName(vm_jobs_as, domain, name);
			/* 
			 * name and domain are now just pointers into vm_jobs_as
			 * buffer.  copy these values into their own buffer so we
			 * deallocate below.
			 */
			if ( name ) {
				name = strdup(name);
			}
			if ( domain ) {
				domain = strdup(domain);
			}
			free(vm_jobs_as);
		}
#endif
		MyString vm_type;
		job_ad->LookupString(ATTR_JOB_VM_TYPE, vm_type);

		if( strcasecmp(vm_type.Value(), CONDOR_VM_UNIVERSE_VMWARE) == MATCH ) {
			name = my_username();
			domain = my_domainname();
		}
	}

	if( !name ) {	
		if ( run_as_owner ) {
			job_ad->LookupString(ATTR_OWNER,&name);
			job_ad->LookupString(ATTR_NT_DOMAIN,&domain);
		}
	}

	if ( !name ) {
		char slot_user[255];
		MyString slotName = "";
		slotName = Starter->getMySlotName();

		slotName.upper_case();
		sprintf(slot_user, "%s_USER", slotName);
		char *run_jobs_as = param(slot_user);
		if (run_jobs_as) {		
			getDomainAndName(run_jobs_as, domain, name);
				/* 
				 * name and domain are now just pointers into run_jobs_as
				 * buffer.  copy these values into their own buffer so we
				 * deallocate below.
				 */
			if ( name ) {
				name = strdup(name);
			}
			if ( domain ) {
				domain = strdup(domain);
			}
			free(run_jobs_as);
		}
	}

	if ( name ) {
		
		if (!init_user_ids(name, domain)) {

			dprintf(D_ALWAYS, "Could not initialize user_priv as \"%s\\%s\".\n"
				"\tMake sure this account's password is securely stored "
				"with condor_store_cred.\n", domain, name );
			init_priv_succeeded = false;			
		} 
		else {
			MyString login_name;
			joinDomainAndName(name, domain, login_name);
			if( checkDedicatedExecuteAccounts( login_name.Value() ) ) {
				setExecuteAccountIsDedicated( login_name.Value() );
			}
		}

	} else if ( !can_switch_ids() ) {
		char *u = my_username();
		char *d = my_domainname();

		if ( !init_user_ids(u, d) ) {
			// shouldn't happen - we always can get our own token
			dprintf(D_ALWAYS, "Could not initialize user_priv with our own token!\n");
			init_priv_succeeded = false;
		}
		free(u);
		free(d);
	} else if( init_user_ids("nobody", ".") ) {
		// just init a new nobody user; dynuser handles the rest.
		// the "." means Local Machine to LogonUser

		setExecuteAccountIsDedicated( get_user_loginname() );
	}
	else {
		
		dprintf( D_ALWAYS, "ERROR: Could not initialize user_priv "
				 "as \"nobody\"\n" );
		init_priv_succeeded = false;
	
	}

	if ( name ) free(name);
	if ( domain ) free(domain);

	user_priv_is_initialized = init_priv_succeeded;
	return init_priv_succeeded;
}
#endif // WIN32


bool
JobInfoCommunicator::initJobInfo( void )
{
#if HAVE_JOB_HOOKS
	m_hook_mgr = new StarterHookMgr;
	return m_hook_mgr->initialize(job_ad);
#endif
	return true;
}


void
JobInfoCommunicator::checkForStarterDebugging( void )
{
	if( ! job_ad ) {
		EXCEPT( "checkForStarterDebugging() called with no job ad!" );
	}

		// For debugging, see if there's a special attribute in the
		// job ad that sends us into an infinite loop, waiting for
		// someone to attach with a debugger
	int starter_should_wait = 0;
	job_ad->LookupInteger( ATTR_STARTER_WAIT_FOR_DEBUG,
						  starter_should_wait );
	if( starter_should_wait ) {
		dprintf( D_ALWAYS, "Job requested starter should wait for "
				 "debugger with %s=%d, going into infinite loop\n",
				 ATTR_STARTER_WAIT_FOR_DEBUG, starter_should_wait );
		while( 1 ) {
			if ( !starter_should_wait ) {
				break;
			}
		}
	}

		// Also, if the starter has D_JOB turned on, we want to dump
		// out the job ad to the log file...
	if( IsDebugLevel( D_JOB ) ) {
		dprintf( D_JOB, "*** Job ClassAd ***\n" );  
		job_ad->dPrint( D_JOB );
        dprintf( D_JOB, "--- End of ClassAd ---\n" );
	}
}


void
JobInfoCommunicator::writeExecutionVisa( ClassAd& visa_ad )
{
	int value;
	if (!job_ad->EvalBool(ATTR_WANT_STARTER_EXECUTION_VISA, NULL, value) ||
	    !value)
	{
		return;
	}
	MyString iwd;
	if (!job_ad->LookupString(ATTR_JOB_IWD, iwd)) {
		dprintf(D_ALWAYS,
		        "writeExecutionVisa error: no IWD in job ad!\n");
		return;
	}
	priv_state priv = set_user_priv();
	MyString filename;
	bool ok = classad_visa_write(&visa_ad,
	                             get_mySubSystem()->getName(),
	                             daemonCore->InfoCommandSinfulString(),
	                             iwd.Value(),
	                             &filename);
	set_priv(priv);
	if (ok) {
		addToOutputFiles(filename.Value());
	}
}


void
JobInfoCommunicator::setupJobEnvironment( void )
{
#if HAVE_JOB_HOOKS
	if (m_hook_mgr) {
		int rval = m_hook_mgr->tryHookPrepareJob();
		switch (rval) {
		case -1:   // Error
			Starter->RemoteShutdownFast(0);
			return;
			break;

		case 0:    // Hook not configured
				// Nothing to do, break out and finish.
			break;

		case 1:    // Spawned the hook.
				// We need to bail now, and let the handler call
				// jobEnvironmentReady() when the hook returns.
			return;
			break;
		}
	}
#endif /* HAVE_JOB_HOOKS */

		// If we made it here, either we're not compiled for hook
		// support, or we didn't spawn a hook.  Either way, we're
		// done and should tell the starter we're ready.
	Starter->jobEnvironmentReady();
}


void
JobInfoCommunicator::cancelUpdateTimer( void )
{
	if (m_periodic_job_update_tid >= 0) {
		daemonCore->Cancel_Timer(m_periodic_job_update_tid);
		m_periodic_job_update_tid = -1;
	}
}


void
JobInfoCommunicator::startUpdateTimer( void )
{
	if( m_periodic_job_update_tid >= 0 ) {
			// already registered the timer...
		return;
	}

	Timeslice interval;

	// default interval is 5 minutes, with 8 seconds as the initial value.
	interval.setDefaultInterval( param_integer( "STARTER_UPDATE_INTERVAL", 300, 0 ) );
	interval.setTimeslice( param_double( "STARTER_UPDATE_INTERVAL_TIMESLICE", 0.1, 0, 1 ) );
	interval.setInitialInterval( param_integer( "STARTER_INITIAL_UPDATE_INTERVAL", 8 ) );

	if( interval.getDefaultInterval() < interval.getInitialInterval() ) {
		interval.setInitialInterval( interval.getDefaultInterval() );
	}
	m_periodic_job_update_tid = daemonCore->
		Register_Timer(interval,
	      (TimerHandlercpp)&JobInfoCommunicator::periodicJobUpdateTimerHandler,
		  "JobInfoCommunicator::periodicJobUpdateTimerHandler", this);
	if( m_periodic_job_update_tid < 0 ) {
		EXCEPT( "Can't register DC Timer!" );
	}
}


/* 
   We can't just have our periodic timer call periodicJobUpdate()
   directly, since it passes in arguments that screw up the default
   bool that determines if we want to ensure the update works.  So,
   the periodic updates call this function instead, which calls the
   non-ensure version.
*/
int
JobInfoCommunicator::periodicJobUpdateTimerHandler( void )
{
	if( periodicJobUpdate(NULL, false) ) {
		return TRUE;
	}
	return FALSE;
}


bool
JobInfoCommunicator::periodicJobUpdate(ClassAd* update_ad, bool)
{
#if HAVE_JOB_HOOKS
	if (m_hook_mgr) {
		ClassAd ad;
		ClassAd* update_ad_ptr = NULL;
		if (update_ad) {
			update_ad_ptr = update_ad;
		}
		else {
			publishUpdateAd(&ad);
			update_ad_ptr = &ad;
		}
		m_hook_mgr->hookUpdateJobInfo(update_ad_ptr);
	}
#endif

	return true;
}


const char*
JobInfoCommunicator::getExitReasonString( void )
{
	if (requested_exit == true) {
		if (had_hold) {
			return "hold";
		}
		else if (had_remove) {
			return "remove";
		}
		return "evict";
	}
	return "exit";
}
