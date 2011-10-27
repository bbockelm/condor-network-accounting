/***************************************************************
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
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

// condor includes
#include "condor_common.h"

// local includes
#include "ODSJobLogConsumer.h"
#include "ODSHistoryUtils.h"

#include "assert.h"
#include "condor_daemon_core.h"
#include "condor_debug.h"
#include "condor_attributes.h"
#include "get_daemon_name.h"
#include "subsystem_info.h"
#include "condor_config.h"
#include "stat_info.h"
#include "JobLogMirror.h"

using namespace std;
using namespace plumage::etl;

ClassAd	*ad = NULL;
JobLogMirror *mirror = NULL;
ODSJobLogConsumer *consumer = NULL;

extern MyString m_path;

void init_classad();
void Dump();
void ProcessHistoryTimer(Service*);

//-------------------------------------------------------------

void main_init(int /* argc */, char * /* argv */ [])
{
	dprintf(D_ALWAYS, "main_init() called\n");

	// setup the job log consumer
	consumer = new ODSJobLogConsumer("localhost");
	mirror = new JobLogMirror(consumer);
	mirror->init();

	init_classad();

    // before doing any job history processing, set the location of the files
    // TODO: need to test mal-HISTORY values: HISTORY=/tmp/somewhere
    const char* tmp2 = param ( "HISTORY" );
    StatInfo si( tmp2 );
    tmp2 = si.DirPath ();
    if ( !tmp2 )
    {
        dprintf ( D_ALWAYS, "warning: No HISTORY defined - ODS will not process history jobs\n" );
    }
    else
    {
        m_path = tmp2;
        dprintf ( D_FULLDEBUG, "HISTORY path is %s\n",tmp2 );
        // register a timer for processing of historical job files
        daemonCore->Register_Timer(0, 120, (TimerHandler) ProcessHistoryTimer , "Timer for processing job history files");
        int index;
        if (-1 == (index = daemonCore->Register_Timer(
                0,
                param_integer("HISTORY_INTERVAL",120),
                (TimerHandler)ProcessHistoryTimer,
                "Timer for processing job history files"
                ))) 
        {
            EXCEPT("Failed to register history timer");
        }
    }
}

void ProcessHistoryTimer(Service*) {
    dprintf(D_FULLDEBUG, "ProcessHistoryTimer() called\n");
    processHistoryDirectory();
    processCurrentHistory();
}

void
init_classad()
{
	if ( ad ) {
		delete ad;
	}
	ad = new ClassAd();

	ad->SetMyTypeName("JobEtlServer");
	ad->SetTargetTypeName("Daemon");

	char* default_name = default_daemon_name();
		if( ! default_name ) {
			EXCEPT( "default_daemon_name() returned NULL" );
		}
	ad->Assign(ATTR_NAME, default_name);
	delete [] default_name;

	ad->Assign(ATTR_MY_ADDRESS, my_ip_string());

	// Initialize all the DaemonCore-provided attributes
	daemonCore->publish( ad );

}

//-------------------------------------------------------------

void
main_config()
{
	dprintf(D_ALWAYS, "main_config() called\n");
}

//-------------------------------------------------------------

void Stop()
{
	if (param_boolean("DUMP_STATE", false)) {
		Dump();
	}

	//delete consumer;

	DC_Exit(0);
}

//-------------------------------------------------------------

void main_shutdown_fast()
{
	dprintf(D_ALWAYS, "main_shutdown_fast() called\n");

	Stop();

	DC_Exit(0);
}

//-------------------------------------------------------------

void main_shutdown_graceful()
{
	dprintf(D_ALWAYS, "main_shutdown_graceful() called\n");

	Stop();

	DC_Exit(0);
}

int
main( int argc, char **argv )
{
	set_mySubSystem("JOB_ETL_SERVER", SUBSYSTEM_TYPE_DAEMON);	// used by Daemon Core

	dc_main_init = main_init;
	dc_main_config = main_config;
	dc_main_shutdown_fast = main_shutdown_fast;
	dc_main_shutdown_graceful = main_shutdown_graceful;
	return dc_main( argc, argv );
}

//-------------------------------------------------------------

void
main_pre_dc_init( int /* argc */, char* /* argv */ [] )
{
		// dprintf isn't safe yet...
}


void
main_pre_command_sock_init( )
{
}

void
Dump()
{
	dprintf(D_ALWAYS|D_NOHEADER, "DUMP called\n");
    if (ad) {
        ad->Puke();
    }
}
