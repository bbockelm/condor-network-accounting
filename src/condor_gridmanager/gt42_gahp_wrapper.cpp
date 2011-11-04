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
#include <errno.h>
#include "condor_config.h"
#include "env.h"
#include "directory.h"
#include "setenv.h"

/***
 * 
 * This is a wrapper arount GT42 GAHP. It queries for the parameters
 * relevant to GT42 GAHP, sets up CLASSPATH and execs:
 *   java condor.gahp.Gahp
 *
 **/

int
main( int argc, char* argv[] ) {
	config(0);
  
	std::string user_proxy;

	if (argc >= 3) {
		if (strcmp (argv[1], "-p")) {
			user_proxy = argv[2];
		}
	}
  
	if (user_proxy.length() == 0) {
		sprintf (user_proxy, "/tmp/x509up_u%d", geteuid());
	}

		// Get the JAVA location
	char * java = param ( "JAVA" );
	if (java == NULL) {
		fprintf (stderr, "ERROR: JAVA not defined in your Condor config file!\n");
		exit (1);
	}

		// Get the java extra arguments value
		// Split on spaces only (not on commas)
	StringList java_extra_args(NULL," ");
	char *tmp = param( "JAVA_EXTRA_ARGUMENTS" );
	if ( tmp != NULL ) {
		java_extra_args.initializeFromString( tmp );
		free( tmp );
	}

		// Get the LIB location (where gt42-gahp.jar lives)
	char * liblocation = param ("LIB");
	if (liblocation == NULL) {
		fprintf (stderr, "ERROR: LIB not defined in your Condor config file!\n");
		exit (1);
	}

		// Get the GT42_LOCATION (where the required globus files live)
	char * gt42location = param ("GT42_LOCATION");
	if (gt42location == NULL) {
		fprintf (stderr, "ERROR: GT42_LOCATION not defined in your Condor config file!\n");
		exit (1);
	}

		// Verify GT42_LOCATION
	struct stat stat_buff;
	if (stat (gt42location, &stat_buff) == -1) {
		fprintf (stderr, "ERROR: Invalid GT42_LOCATION: %s\n", gt42location);
		exit (1);
	}

		// Change to the gt42 directory
		// This is cruicial believe it or not !!!!
	if (chdir (gt42location) < 0 ) {
		fprintf (stderr, "ERROR: Unable to cd into %s!\n", gt42location);
		exit (1);
	}

	StringList command_line;
	command_line.append (java);

	std::string buff;
	sprintf (buff, "-DGLOBUS_LOCATION=%s", gt42location);
	command_line.append (buff.c_str());

	sprintf (buff, "-Djava.endorsed.dirs=%s/endorsed", gt42location);
	command_line.append (buff.c_str());
  
	sprintf (buff, "-Dorg.globus.wsrf.container.webroot=%s", gt42location);
	command_line.append (buff.c_str());

	sprintf (buff, "-DX509_USER_PROXY=%s", user_proxy.c_str());
	command_line.append (buff.c_str());

	char *cacertdir = param ("GSI_DAEMON_TRUSTED_CA_DIR");
	if ( cacertdir ) {
		sprintf( buff, "-DX509_CERT_DIR=%s", cacertdir );
		command_line.append( buff.c_str() );
	}

	const char *port_range = GetEnv( "GLOBUS_TCP_PORT_RANGE" );
	if ( port_range != NULL ) {
		sprintf( buff, "-DGLOBUS_TCP_PORT_RANGE=%s", port_range );
		command_line.append( buff.c_str() );
	}
  
	command_line.append( "-Dlog4j.appender.A1=org.apache.log4j.ConsoleAppender" );
	command_line.append( "-Dlog4j.appender.A1.target=System.err" );

	java_extra_args.rewind();
	while ( (tmp = java_extra_args.next()) != NULL ) {
		command_line.append( tmp );
	}

/*
// Append bootstrap classpath
	const char * jarfiles [] = {
		"bootstrap.jar",
		"cog-url.jar",
		"axis-url.jar"
	};
*/

	std::string classpath;

	char classpath_seperator;
#ifdef WIN32
	classpath_seperator = ';';
#else
	classpath_seperator = ':';
#endif

	classpath += liblocation;
	classpath += "/gt42-gahp.jar";

		// Some java properties files used by Globus are kept in
		// $GLOBUS_LOCATION, so we need to include it in the classpath
	classpath += classpath_seperator;
	classpath += gt42location;

	const char *ctmp;
	sprintf( buff, "%s/lib", gt42location );
	Directory dir( buff.c_str() );
	dir.Rewind();
	while ( (ctmp = dir.Next()) ) {
		const char *match = strstr( ctmp, ".jar" );
		if ( match && strlen( match ) == 4 ) {
			classpath += classpath_seperator;
			classpath += dir.GetFullPath();
		}
	}
	sprintf( buff, "%s/lib/common", gt42location );
	Directory dir2( buff.c_str() );
	dir2.Rewind();
	while ( (ctmp = dir2.Next()) ) {
		const char *match = strstr( ctmp, ".jar" );
		if ( match && strlen( match ) == 4 ) {
			classpath += classpath_seperator;
			classpath += dir2.GetFullPath();
		}
	}
/*
	int i; 
	i = sizeof(jarfiles)/sizeof(char*)-1;
	for (; i>=0; i--) {
		char * dir = dircat (gt42location, "lib");
		char * fulljarpath = dircat (dir, jarfiles[i]);
    
		if (stat (fulljarpath, &stat_buff) == -1) {
			fprintf (stderr, "ERROR: Missing required jar file %s!\n", jarfiles[i]);
			exit (1);
		}

		classpath += fulljarpath;
		delete dir;
		delete fulljarpath;

		if (i > 0) {
#ifdef WIN32
			classpath += ";";
#else
			classpath += ":";
#endif
		}
	}
*/

	command_line.append ("-classpath");
	command_line.append (classpath.c_str());

	command_line.append ("org.globus.bootstrap.Bootstrap");
	command_line.append ("condor.gahp.Gahp");

	int nparams = command_line.number();
	char ** params = new char* [nparams+1];
	command_line.rewind();
	for (int i=0; i<command_line.number(); i++) {
		params[i] = strdup(command_line.next());
	}
	params[nparams]=(char*)0;


// Invoke java
	fflush (stdout);
	int rc = execv ( java, params );  

	fprintf( stderr, "gt42_gahp_wrapper: execv failed, errno=%d\n", errno );

	for (int i=0; i<nparams; i++) {
		free (params[i]);
	}
	delete[] params;
	free (java);
	free (gt42location);

	return rc;

}
