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
#include "string_list.h"
#include "read_multiple_logs.h"
#include "check_events.h"
#include "condor_config.h"

MULTI_LOG_HASH_INSTANCE; // For the multi-log-file code...
CHECK_EVENTS_HASH_INSTANCE; // For the event checking code...

int main(int argc, char **argv)
{
	int		result = 0;
	param_functions *p_funcs = NULL;

	if ( argc <= 1 || (argc >= 2 && !strcmp("-usage", argv[1])) ) {
		printf("Usage: condor_check_userlogs <log file 1> "
				"[log file 2] ... [log file n]\n");
		exit(0);
	}

		// Set up dprintf.
	Termlog = true;
	p_funcs = get_param_functions();
	dprintf_config("condor_check_userlogs", p_funcs);
	set_debug_flags(NULL, D_ALWAYS);

	StringList	logFiles;
	for ( int argnum = 1; argnum < argc; ++argnum ) {
		logFiles.append(argv[argnum]);
	}
	logFiles.rewind();

	ReadMultipleUserLogs	ru;
	char *filename;
	while ( (filename = logFiles.next()) ) {
		MyString filestring( filename );
		CondorError errstack;
		if ( !ru.monitorLogFile( filestring, false, errstack ) ) {
			fprintf( stderr, "Error monitoring log file %s: %s\n", filename,
						errstack.getFullText() );
			result = 1;
		}
	}

	bool logsMissing = false;

	CheckEvents		ce;
	int totalSubmitted = 0;
	int netSubmitted = 0;
	bool done = false;
	while( !done ) {

    	ULogEvent* e = NULL;
		MyString errorMsg;

        ULogEventOutcome outcome = ru.readEvent( e );

        switch (outcome) {

        case ULOG_RD_ERROR:
        case ULOG_UNK_ERROR:
			logsMissing = true;
        case ULOG_NO_EVENT:

			printf( "Log outcome: %s\n", ULogEventOutcomeNames[outcome] );
			done = true;
			break;
 
        case ULOG_OK:

			printf( "Log event: %s (%d.%d.%d)",
						ULogEventNumberNames[e->eventNumber],
						e->cluster, e->proc, e->subproc );

			if ( ce.CheckAnEvent(e, errorMsg) != CheckEvents::EVENT_OKAY ) {
				fprintf(stderr, "%s\n", errorMsg.Value());
				result = 1;
			}

			if( e->eventNumber == ULOG_SUBMIT ) {
				SubmitEvent* ee = (SubmitEvent*) e;
				printf( " (\"%s\")", ee->submitEventLogNotes );
				++totalSubmitted;
				++netSubmitted;
				printf( "\n Total submitted: %d; net submitted: %d\n",
						totalSubmitted, netSubmitted );
			}
			
			if( e->eventNumber == ULOG_JOB_HELD ) {
				JobHeldEvent* ee = (JobHeldEvent*) e;
				printf( " (code=%d subcode=%d)", ee->getReasonCode(),
						ee->getReasonSubCode());
			}

			if( e->eventNumber == ULOG_JOB_TERMINATED ) {
				--netSubmitted;
				printf( "\n Total submitted: %d; net submitted: %d\n",
						totalSubmitted, netSubmitted );
			}

			if( e->eventNumber == ULOG_JOB_ABORTED ) {
				--netSubmitted;
				printf( "\n Total submitted: %d; net submitted: %d\n",
						totalSubmitted, netSubmitted );
			}

			if( e->eventNumber == ULOG_EXECUTABLE_ERROR ) {
				--netSubmitted;
				printf( "\n Total submitted: %d; net submitted: %d\n",
						totalSubmitted, netSubmitted );
			}

			printf( "\n" );
			break;

		default:

			fprintf(stderr, "Unexpected read event outcome!\n");
			result = 1;
			break;
        }
	}

	logFiles.rewind();
	while ( (filename = logFiles.next()) ) {
		MyString filestring( filename );
		CondorError errstack;
		if ( !ru.unmonitorLogFile( filestring, errstack ) ) {
			fprintf( stderr, "Error unmonitoring log file %s: %s\n", filename,
						errstack.getFullText() );
			result = 1;
		}
	}

	MyString errorMsg;
	CheckEvents::check_event_result_t checkAllResult =
				ce.CheckAllJobs(errorMsg);
	if ( checkAllResult != CheckEvents::EVENT_OKAY ) {
		fprintf(stderr, "%s\n", errorMsg.Value());
		fprintf(stderr, "CheckAllJobs() result: %s\n",
					CheckEvents::ResultToString(checkAllResult));
		result = 1;
	}

	if ( result == 0 ) {
		if ( !logsMissing ) {
			printf("Log(s) are okay\n");
		} else {
			printf("Log(s) may be okay\n");
			printf(  "Some logs cannot be read\n");
		}
	} else {
		printf("Log(s) have error(s)\n");
	}
	return result;
}
