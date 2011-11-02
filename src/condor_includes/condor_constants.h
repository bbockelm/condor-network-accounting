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

#ifndef CONDOR_CONSTANTS_H
#define CONDOR_CONSTANTS_H

/*
	Set up a boolean variable type.  Since this definition could conflict
	with other reasonable definition of BOOLEAN, i.e. using an enumeration,
	it is conditional.
*/
#ifndef BOOLEAN_TYPE_DEFINED
#if defined(WIN32)
typedef unsigned char BOOLEAN;
typedef unsigned char BOOL_T;
#else
typedef int BOOLEAN;
typedef int BOOL_T;
#endif
#define BOOLEAN_TYPE_DEFINED
#endif

#ifndef _CONDOR_NO_TRUE_FALSE
#if defined(TRUE)
#	undef TRUE
#	undef FALSE
#endif
enum { FALSE=0, TRUE=1 };
#endif /* ifndef(_CONDOR_NO_TRUE_FALSE) */

/*
	Useful constants for turning seconds into larger units of time.  Since
	these constants may have already been defined elsewhere, they are
	conditional.
*/
#if !defined(MINUTE) && !defined(TIME_CONSTANTS_DEFINED)
static const int	MINUTE = 60;
static const int	HOUR = 60 * 60;
static const int	DAY = 24 * 60 * 60;
#endif

/*
  This is for use with strcmp() and related functions which will return
  0 upon a match.
*/
#ifndef MATCH
static const int	MATCH = 0;
#endif

/*
  These are the well known file descriptors used for remote system call and
  logging functions.
*/
#ifndef CLIENT_LOG
static const int CLIENT_LOG = 18;
static const int RSC_SOCK = 17;
#endif
static const int REQ_SOCK = 16;
static const int RPL_SOCK = 17;

#if defined(WIN32)
static const char DIR_DELIM_CHAR = '\\';
static const char DIR_DELIM_STRING[] = "\\";
static const char PATH_DELIM_CHAR = ';';
static const char NULL_FILE[] = "NUL";
/* CONDOR_EXEC is name the used for the user's executable */
static const char CONDOR_EXEC[] = "condor_exec.exe";
#else
static const char DIR_DELIM_CHAR = '/';
static const char DIR_DELIM_STRING[] = "/";
static const char PATH_DELIM_CHAR = ':';
static const char NULL_FILE[] = "/dev/null";
static const char CONDOR_EXEC[] = "condor_exec.exe";
#endif

/* condor_submit canonicalizes all NULLFILE's to the UNIX_NULL_FILE */
static const char WINDOWS_NULL_FILE[] = "NUL";
static const char UNIX_NULL_FILE[] = "/dev/null";

/* This is the username of the NiceUser (i.e., dirt user) */
static const char NiceUserName[] = "nice-user";

/* This is a compiler-specific type-modifer to request
 * a variable be stored as thread-local-storage.
 */
#if defined(WIN32)
	/* We know Windows has TLS and it works well */
	#define THREAD_LOCAL_STORAGE __declspec( thread ) 
#else
	/* On Unix-like platforms, we have had very bad luck w/ TLS.
	 * For example, when using TLS, we could not build binaries
	 * on 32bit RHEL3 that would not crash on 64bit RHEL4. See
	 * gittrac #482.  So for now, THREAD_LOCAL_STORAGE is non-Win32
	 * platforms is a no-op. */
	#define THREAD_LOCAL_STORAGE /* Blank */
#endif

/* Max space needed to hold an IP string, as
 * returned by inet_ntoa().
 */
static const size_t IP_STRING_BUF_SIZE = 46;

/* Max space needed to hold a sinful string, as
 * returned by sin_to_string()
 */
// TODO: [IPV6] Should be increased
#define SINFUL_STRING_BUF_SIZE 64

#define MYPROXY_MAX_PASSWORD_BUFLEN 256

/* Max space needed to hold a null-terminated
 * user name such as the value of ATTR_JOB_OWNER
 */
#define MAX_CONDOR_USERNAME_LEN 100

#define CONDOR_HOSTNAME_MAX 256

// years of careful research, I am told...
#define DEFAULT_CEDAR_TIMEOUT 20

#define MAX_PARAM_LEN 1024

#define DEFAULT_SHORT_COMMAND_DEADLINE 600

#define STANDARD_COMMAND_PAYLOAD_TIMEOUT 300

#endif /* CONDOR_CONSTANTS_H */
