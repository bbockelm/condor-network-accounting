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



/************************************************************************
**
**	Set up the various dprintf variables based on the configuration file.
**
************************************************************************/
#include "condor_common.h"
#include "condor_debug.h"
#include "condor_string.h" 
#include "condor_sys_types.h"
#include "dprintf_internal.h"

#if HAVE_BACKTRACE
#include "sig_install.h"
#endif

#include <string>
using std::string;

int		Termlog = 0;

//extern int		DebugFlags;
//#ifdef D_CATEGORY_MASK
//extern int		DebugVerbose;
//#else
//extern FILE		*DebugFPs[D_NUMLEVELS+1];
//#endif
extern std::vector<DebugFileInfo> *DebugLogs;
extern char		*DebugLock;
#ifdef D_CATEGORY_MASK
extern const char		*_condor_DebugFlagNames[D_CATEGORY_COUNT];
#else
extern const char		*_condor_DebugFlagNames[D_NUMLEVELS];
#endif
extern int		_condor_dprintf_works;
extern time_t	DebugLastMod;
extern int		DebugUseTimestamps;
extern int		DebugContinueOnOpenFailure;
extern int		log_keep_open;
extern char*	DebugTimeFormat;
extern int		DebugLockIsMutex;
extern char*	DebugLogDir;

extern void		_condor_set_debug_flags( const char *strflags, int cat_and_flags );
extern void		_condor_dprintf_saved_lines( void );
extern bool debug_check_it(struct DebugFileInfo& it, bool fTruncate, bool dont_panic);

param_functions *dprintf_param_funcs = NULL;

#if HAVE_BACKTRACE
static void
sig_backtrace_handler(int signum)
{
	dprintf_dump_stack();

		// terminate for the same reason.
	struct sigaction sa;
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(signum, &sa, NULL);
	sigprocmask(SIG_SETMASK, &sa.sa_mask, NULL);

	raise(signum);
}

static void
install_backtrace_handler(void)
{
	sigset_t fullset;
	sigfillset( &fullset );
	install_sig_handler_with_mask(SIGSEGV, &fullset, sig_backtrace_handler);
	install_sig_handler_with_mask(SIGABRT, &fullset, sig_backtrace_handler);
	install_sig_handler_with_mask(SIGILL, &fullset, sig_backtrace_handler);
	install_sig_handler_with_mask(SIGFPE, &fullset, sig_backtrace_handler);
	install_sig_handler_with_mask(SIGBUS, &fullset, sig_backtrace_handler);
}
#endif

int
dprintf_config_ContinueOnFailure ( int fContinue )
{
	int fOld = DebugContinueOnOpenFailure;
	DebugContinueOnOpenFailure = fContinue;
	return fOld;
}

int
dprintf_config( const char *subsys, param_functions *p_funcs, struct dprintf_output_settings *p_info /* = NULL*/, int c_info /*= 0*/)
{
	char pname[ BUFSIZ ];
	char *pval = NULL;
	//static int first_time = 1;
	int log_open_default = TRUE;

	/*
	**  We want to initialize this here so if we reconfig and the
	**	debug flags have changed, we actually use the new
	**  flags.  -Derek Wright 12/8/97 
	*/
	unsigned int HeaderOpts = 0;
	DebugOutputChoice verbose = 0;
	PRAGMA_REMIND("TJ: move verbose into choice")

	std::vector<struct dprintf_output_settings> DebugParams(1);
	DebugParams[0].choice = 1<<D_ALWAYS | 1<<D_ERROR;
	DebugParams[0].accepts_all = true;

	/*
	 * The duplication of the param_function instance is to ensure no one else can change
	 * the data structure out from under dprintf.  It is also to prevent transfer of ownership/
	 * responsibility for the block of memory used to store the function pointers.
	 */
	if(!dprintf_param_funcs)
		dprintf_param_funcs = new param_functions();
	if(p_funcs)
	{
		dprintf_param_funcs->set_param_func(p_funcs->get_param_func());
		dprintf_param_funcs->set_param_bool_int_func(p_funcs->get_param_bool_int_func());
		dprintf_param_funcs->set_param_wo_default_func(p_funcs->get_param_wo_default_func());
		dprintf_param_funcs->set_param_int_func(p_funcs->get_param_int_func());
	}


	/*
	** First, add the debug flags that are shared by everyone.
	*/
	pval = dprintf_param_funcs->param("ALL_DEBUG");
	if( pval ) {
		_condor_parse_merge_debug_flags( pval, 0, HeaderOpts, DebugParams[0].choice, verbose);
		free( pval );
	}

	/*
	**  Then, add flags set by the subsys_DEBUG parameters
	*/
	(void)sprintf(pname, "%s_DEBUG", subsys);
	pval = dprintf_param_funcs->param(pname);
	if ( ! pval) {
		pval = dprintf_param_funcs->param("DEFAULT_DEBUG");
	}
	if( pval ) {
		_condor_parse_merge_debug_flags( pval, 0, HeaderOpts, DebugParams[0].choice, verbose);
		free( pval );
	}

	if(DebugLogDir)
		free(DebugLogDir);
	DebugLogDir = dprintf_param_funcs->param( "LOG" );

	PRAGMA_REMIND("TJ: dprintf_config should not set globals if p_info != NULL")
#ifdef WIN32
		/* Two reasons why we need to lock the log in Windows
		 * (when a lock is configured)
		 * 1) File rotation requires exclusive access in Windows.
		 * 2) O_APPEND doesn't guarantee atomic writes in Windows
		 */
	DebugShouldLockToAppend = 1;
	DebugLockIsMutex = dprintf_param_funcs->param_boolean_int("FILE_LOCK_VIA_MUTEX", TRUE);
#else
	DebugShouldLockToAppend = dprintf_param_funcs->param_boolean_int("LOCK_DEBUG_LOG_TO_APPEND",0);
	DebugLockIsMutex = FALSE;
#endif

	(void)sprintf(pname, "%s_LOCK", subsys);
	if (DebugLock) {
		free(DebugLock);
	}
	DebugLock = dprintf_param_funcs->param(pname);

#ifndef WIN32
	if((strcmp(subsys, "SHADOW") == 0) || (strcmp(subsys, "GRIDMANAGER") == 0))
	{
		log_open_default = FALSE;
	}
#endif

	if(!DebugLock) {
		(void)sprintf(pname, "%s_LOG_KEEP_OPEN", subsys);
		log_keep_open = dprintf_param_funcs->param_boolean_int(pname, log_open_default);
	}

	/*
	If LOGS_USE_TIMESTAMP is enabled, we will print out Unix timestamps
	instead of the standard date format in all the log messages
	*/
	DebugUseTimestamps = dprintf_param_funcs->param_boolean_int( "LOGS_USE_TIMESTAMP", FALSE );
	if (DebugUseTimestamps) HeaderOpts |= D_TIMESTAMP;
	char * time_format = dprintf_param_funcs->param( "DEBUG_TIME_FORMAT" );
	if (time_format) {
		if(DebugTimeFormat)
			free(DebugTimeFormat);
		DebugTimeFormat = time_format;
		// Skip enclosing quotes
		if (*time_format == '"') {
			DebugTimeFormat = strdup(&time_format[1]);
			free(time_format);
			char * p = DebugTimeFormat;
			while (*p++) {
				if (*p == '"') *p = '\0';
			}
		}
	}

	/*
	**	pick up the name of the log file, maximum log size, and the name of the
	**	lock file (if it is specified).
	*/
	for (int debug_level = 0; debug_level < (int)COUNTOF(_condor_DebugFlagNames); ++debug_level) {

		std::string logPath;
		std::string subsys_and_level = subsys;
		int param_index = 0;

		if (debug_level != D_ALWAYS) {
			/*
			** the level 0 file gets all debug messages; thus, the
			** offset into DebugFlagNames is off by one, since the
			** first level-specific file goes into the other arrays at
			** index 1
			*/
			subsys_and_level += _condor_DebugFlagNames[debug_level]+1;
			param_index = DebugParams.size();
		}

		(void)sprintf(pname, "%s_LOG", subsys_and_level.c_str());

		char *logPathParam = NULL;
		if(debug_level == D_ALWAYS)
		{
			if (Termlog) {
				logPath = "2>";
			} else {
				logPathParam = dprintf_param_funcs->param(pname);
				if (logPathParam) {
					logPath.insert(0, logPathParam);
				} else {
					// No default value found, so use $(LOG)/$(SUBSYSTEM)Log
					char *lsubsys = dprintf_param_funcs->param("SUBSYSTEM");
					if ( ! DebugLogDir || ! lsubsys) {
						EXCEPT("Unable to find LOG or SUBSYSTEM.\n");
					}

					sprintf(logPath, "%s%c%sLog", DebugLogDir, DIR_DELIM_CHAR, lsubsys);

					free(lsubsys);
				}
			}

			DebugParams[0].accepts_all = true;
			DebugParams[0].want_truncate = false;
			DebugParams[0].logPath = logPath;
			DebugParams[0].maxLog = 1024*1024;
			DebugParams[0].maxLogNum = 1;
			DebugParams[0].HeaderOpts = HeaderOpts;
			DebugParams[0].VerboseCats = verbose;
		}
		else
		{
			// This is looking up configuration options that I can't
			// find documentation for, so instead of coding in an
			// incorrect default value, I'm gonna use
			// param_without_default.
			// tristan 5/29/09
			logPathParam = dprintf_param_funcs->param_without_default(pname);
			if(logPathParam)
				logPath.insert(0, logPathParam);

			if(!DebugParams.empty())
			{
				for (int jj = 0; jj < (int)DebugParams.size(); ++jj)
				{
					if (DebugParams[jj].logPath == logPath)
					{
						DebugParams[jj].choice |= 1<<debug_level;
						param_index = jj;
						break;
					}
				}
			}

			if (param_index >= (int)DebugParams.size())
			{
				struct dprintf_output_settings info;
				info.accepts_all = false;
				info.want_truncate = false;
				info.choice = 1<<debug_level;
				info.logPath = logPath;
				info.maxLog = 1024*1024;
				info.maxLogNum = 1;

				DebugParams.push_back(info);
				param_index = (int)DebugParams.size() -1;
			}
		}

		if(logPathParam)
		{
			free(logPathParam);
			logPathParam = NULL;
		}

		(void)sprintf(pname, "TRUNC_%s_LOG_ON_OPEN", subsys_and_level.c_str());
		DebugParams[param_index].want_truncate = dprintf_param_funcs->param_boolean_int(pname, DebugParams[param_index].want_truncate) ? 1 : 0;

		PRAGMA_REMIND("TJ: move initialization of DebugLock")
		if (debug_level == D_ALWAYS) {
			(void)sprintf(pname, "%s_LOCK", subsys);
			if (DebugLock) {
				free(DebugLock);
			}
			DebugLock = param(pname);
		}

		(void)sprintf(pname, "MAX_%s_LOG", subsys_and_level.c_str());
		pval = param(pname);
		if (pval != NULL) {
			// because there is nothing like param_long_long() or param_off_t()
			int64_t maxlog = 0;
			bool r = lex_cast(pval, maxlog);
			if (!r || (maxlog < 0)) {
				std::string m;
				sprintf(m, "Invalid config %s = %s: %s must be an integer literal >= 0\n", pname, pval, pname);
				_condor_dprintf_exit(EINVAL, m.c_str());
			}
			DebugParams[param_index].maxLog = maxlog;
			free(pval);
		}

		(void)sprintf(pname, "MAX_NUM_%s_LOG", subsys_and_level.c_str());
		pval = param(pname);
		if (pval != NULL) {
			DebugParams[param_index].maxLogNum = param_integer(pname, 1, 0);
			free(pval);
		}
	}

	// if a p_info array was supplied, return the parsed params, but don't operate
	// on them
	// if it was not supplied, then use the params to configure dprintf outputs.
	//
	if (p_info)
	{
		for (int ii = 0; ii < c_info && ii < (int)DebugParams.size(); ++ii)
		{
			p_info[ii].accepts_all   = DebugParams[ii].accepts_all;
			p_info[ii].want_truncate = DebugParams[ii].want_truncate;
			p_info[ii].choice        = DebugParams[ii].choice;
			p_info[ii].logPath       = DebugParams[ii].logPath;
			p_info[ii].maxLog        = DebugParams[ii].maxLog;
			p_info[ii].maxLogNum     = DebugParams[ii].maxLogNum;
			p_info[ii].HeaderOpts    = DebugParams[ii].HeaderOpts;
			p_info[ii].VerboseCats   = DebugParams[ii].VerboseCats;
		}
		// return the NEEDED size of the p_info array, even if it is bigger than c_info
		return DebugParams.size();
	}
	else
	{
		dprintf_set_outputs(&DebugParams[0], DebugParams.size());
	}
	return 0;
}

void dprintf_set_outputs(const struct dprintf_output_settings *p_info, int c_info)
{
	static int first_time = 1;

	std::vector<DebugFileInfo> *debugLogsOld = DebugLogs;
	DebugLogs = new std::vector<DebugFileInfo>();

	/*
	**  We want to initialize this here so if we reconfig and the
	**	debug flags have changed, we actually use the new
	**  flags.  -Derek Wright 12/8/97
	*/
	DebugBasic = 1<<D_ALWAYS | 1<<D_ERROR;
	DebugVerbose = 0;
	DebugHeaderOptions = 0;

	if ( ! p_info || ! c_info || p_info[0].logPath == "2>" || p_info[0].logPath == "CON:" || p_info[0].logPath == "\\dev\\tty") {
		Termlog = true;
	} else {
		// DebugShouldLockToAppend = p_info[0].lock_to_append;
	}

	/*
	**	If this is not going to the terminal, pick up the name
	**	of the log file, maximum log size, and the name of the
	**	lock file (if it is specified).
	*/
	if ( ! Termlog )
	{
		std::vector<DebugFileInfo>::iterator it;	//iterator indicating the file we got to.
		for (int ii = 0; ii < c_info; ++ii)
		{
			std::string logPath = p_info[ii].logPath;

			if(!logPath.empty())
			{
				// merge flags if we see the same log file name more than once.
				// we don't really expect this to happen, but things get wierd of
				// it does happen and we don't check for it.
				//
				for(it = DebugLogs->begin(); it != DebugLogs->end(); ++it)
				{
					if(it->logPath != logPath)
						continue;
					it->choice |= p_info[ii].choice;
					break;
				}

				if(it == DebugLogs->end()) // We did not find the logPath in our DebugLogs
				{
					it = DebugLogs->insert(DebugLogs->end(),p_info[ii]);
					it->outputTarget = ((ii == 0) && Termlog) ? STD_OUT : FILE_OUT;
					it->logPath = logPath;
				}

				if (ii == 0) {
					if(first_time) {
						struct stat stat_buf;
						if ( stat( logPath.c_str(), &stat_buf ) >= 0 ) {
							DebugLastMod = stat_buf.st_mtime > stat_buf.st_ctime ? stat_buf.st_mtime : stat_buf.st_ctime;
						} else {
							DebugLastMod = -errno;
						}
					}
					PRAGMA_REMIND("TJ: fix this when choice includes verbose.")
					DebugBasic = p_info[0].choice;
					DebugVerbose = p_info[0].VerboseCats;
					DebugHeaderOptions = p_info[0].HeaderOpts;
				}

				// check to see if we can open the log file.
				bool dont_panic = true;
				bool fOk = debug_check_it(*it, (first_time && it->want_truncate), dont_panic);
				if( ! fOk && ii == 0 )
				{
			       #ifdef WIN32
					/*
					** If we could not open the log file, we might want to keep running anyway.
					** If we do, then set the log filename to NUL so we don't keep trying
					** (and failing) to open the file.
					*/
					if (DebugContinueOnOpenFailure) 
					{
						// change the debug file to point to the NUL device.
						it->logPath.insert(0, NULL_FILE);
					} else
			       #endif
					{
						EXCEPT("Cannot open log file '%s'", logPath.c_str());
					}
				}
			}
		}
	} else {

		if (p_info && (c_info > 0)) {
			PRAGMA_REMIND("TJ: fix this when choice includes verbose.")
			DebugBasic = p_info[0].choice;
			DebugVerbose = p_info[0].VerboseCats;
			DebugHeaderOptions = p_info[0].HeaderOpts;
		}

#if !defined(WIN32)
		setlinebuf( stderr );
#endif

		(void)fflush( stderr );	/* Don't know why we need this, but if not here
							   the first couple dprintf don't come out right */
	}

	first_time = 0;
	_condor_dprintf_works = 1;

#if HAVE_BACKTRACE
	install_backtrace_handler();
#endif

	if(debugLogsOld)
	{
		delete debugLogsOld;
	}

	_condor_dprintf_saved_lines();
}

