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
#include <string.h>
#include <errno.h>
#include "condor_event.h"
#include "user_log.c++.h"
#include "condor_string.h"
#include "condor_classad.h"
#include "iso_dates.h"
#include "condor_attributes.h"
#include "classad_merge.h"

#include "misc_utils.h"

//added by Ameet
#include "condor_environ.h"
//--------------------------------------------------------
#include "condor_debug.h"
//--------------------------------------------------------


#define ESCAPE { errorNumber=(errno==EAGAIN) ? ULOG_NO_EVENT : ULOG_UNK_ERROR;\
					 return 0; }

#include "file_sql.h"
extern FILESQL *FILEObj;


//extern ClassAd *JobAd;

const char * ULogEventNumberNames[] = {
	"ULOG_SUBMIT",					// Job submitted
	"ULOG_EXECUTE",					// Job now running
	"ULOG_EXECUTABLE_ERROR",		// Error in executable
	"ULOG_CHECKPOINTED",			// Job was checkpointed
	"ULOG_JOB_EVICTED",				// Job evicted from machine
	"ULOG_JOB_TERMINATED",			// Job terminated
	"ULOG_IMAGE_SIZE",				// Image size of job updated
	"ULOG_SHADOW_EXCEPTION",		// Shadow threw an exception
	"ULOG_GENERIC",
	"ULOG_JOB_ABORTED",  			// Job aborted
	"ULOG_JOB_SUSPENDED",			// Job was suspended
	"ULOG_JOB_UNSUSPENDED",			// Job was unsuspended
	"ULOG_JOB_HELD",  				// Job was held
	"ULOG_JOB_RELEASED",  			// Job was released
	"ULOG_NODE_EXECUTE",  			// MPI (or parallel) Node executing
	"ULOG_NODE_TERMINATED",  		// MPI (or parallel) Node terminated
	"ULOG_POST_SCRIPT_TERMINATED",	// POST script terminated
	"ULOG_GLOBUS_SUBMIT",			// Job Submitted to Globus
	"ULOG_GLOBUS_SUBMIT_FAILED",	// Globus Submit Failed 
	"ULOG_GLOBUS_RESOURCE_UP",		// Globus Machine UP 
	"ULOG_GLOBUS_RESOURCE_DOWN",	// Globus Machine Down
	"ULOG_REMOTE_ERROR",            // Remote Error
	"ULOG_JOB_DISCONNECTED",        // RSC socket lost
	"ULOG_JOB_RECONNECTED",         // RSC socket re-established
	"ULOG_JOB_RECONNECT_FAILED",    // RSC reconnect failure
	"ULOG_GRID_RESOURCE_UP",		// Grid machine UP 
	"ULOG_GRID_RESOURCE_DOWN",		// Grid machine Down
	"ULOG_GRID_SUBMIT",				// Job submitted to grid resource
	"ULOG_JOB_AD_INFORMATION"		// Job Ad information update
};

const char * ULogEventOutcomeNames[] = {
  "ULOG_OK       ",
  "ULOG_NO_EVENT ",
  "ULOG_RD_ERROR ",
  "ULOG_MISSED_EVENT ",
  "ULOG_UNK_ERROR"
};


ULogEvent *
instantiateEvent (ClassAd *ad)
{
	ULogEvent *event;
	int eventNumber;
	if(!ad->LookupInteger("EventTypeNumber",eventNumber)) return NULL;

	event = instantiateEvent((ULogEventNumber)eventNumber);
	if(event) event->initFromClassAd(ad);
	return event;
}

ULogEvent *
instantiateEvent (ULogEventNumber event)
{
	switch (event)
	{
	  case ULOG_SUBMIT:
		return new SubmitEvent;

	  case ULOG_EXECUTE:
		return new ExecuteEvent;

	  case ULOG_EXECUTABLE_ERROR:
		return new ExecutableErrorEvent;

	  case ULOG_CHECKPOINTED:
		return new CheckpointedEvent;

	  case ULOG_JOB_EVICTED:
		return new JobEvictedEvent;

	  case ULOG_JOB_TERMINATED:
		return new JobTerminatedEvent;

	  case ULOG_IMAGE_SIZE:
		return new JobImageSizeEvent;

	  case ULOG_SHADOW_EXCEPTION:
		return new ShadowExceptionEvent;

	  case ULOG_GENERIC:
		return new GenericEvent;

	  case ULOG_JOB_ABORTED:
		return new JobAbortedEvent;

	  case ULOG_JOB_SUSPENDED:
		return new JobSuspendedEvent;

	  case ULOG_JOB_UNSUSPENDED:
		return new JobUnsuspendedEvent;

	  case ULOG_JOB_HELD:
		return new JobHeldEvent;

	  case ULOG_JOB_RELEASED:
		return new JobReleasedEvent;

	  case ULOG_NODE_EXECUTE:
		return new NodeExecuteEvent;

	  case ULOG_NODE_TERMINATED:
		return new NodeTerminatedEvent;

	  case ULOG_POST_SCRIPT_TERMINATED:
		return new PostScriptTerminatedEvent;

	  case ULOG_GLOBUS_SUBMIT:
		return new GlobusSubmitEvent;

	  case ULOG_GLOBUS_SUBMIT_FAILED:
		return new GlobusSubmitFailedEvent;

	  case ULOG_GLOBUS_RESOURCE_DOWN:
		return new GlobusResourceDownEvent;

	  case ULOG_GLOBUS_RESOURCE_UP:
		return new GlobusResourceUpEvent;

	case ULOG_REMOTE_ERROR:
		return new RemoteErrorEvent;

	case ULOG_JOB_DISCONNECTED:
		return new JobDisconnectedEvent;

	case ULOG_JOB_RECONNECTED:
		return new JobReconnectedEvent;

	case ULOG_JOB_RECONNECT_FAILED:
		return new JobReconnectFailedEvent;

	case ULOG_GRID_RESOURCE_DOWN:
		return new GridResourceDownEvent;

	case ULOG_GRID_RESOURCE_UP:
		return new GridResourceUpEvent;

	case ULOG_GRID_SUBMIT:
		return new GridSubmitEvent;

	case ULOG_JOB_AD_INFORMATION:
		return new JobAdInformationEvent;

	default:
		dprintf( D_ALWAYS, "Invalid ULogEventNumber: %d\n", event );
		// Return NULL/0 here instead of EXCEPTing to fix Gnats PR 706.
		// wenger 2006-06-08.
		return 0;
	}

    return 0;
}


ULogEvent::
ULogEvent()
{
	struct tm *tm;

	eventNumber = (ULogEventNumber) - 1;
	cluster = proc = subproc = -1;

	(void) time ((time_t *)&eventclock);
	tm = localtime ((time_t *)&eventclock);
	eventTime = *tm;
}


ULogEvent::
~ULogEvent ()
{
}


int ULogEvent::
getEvent (FILE *file)
{
	if( !file ) {
		dprintf( D_ALWAYS, "ERROR: file == NULL in ULogEvent::getEvent()\n" );
		return 0;
	}
	return (readHeader (file) && readEvent (file));
}


int ULogEvent::
putEvent (FILE *file)
{
	if( !file ) {
		dprintf( D_ALWAYS, "ERROR: file == NULL in ULogEvent::putEvent()\n" );
		return 0;
	}
	return (writeHeader (file) && writeEvent (file));
}


const char* ULogEvent::
eventName() const
{
	if( eventNumber == (ULogEventNumber)-1 ) {
		return NULL;
	}
	return ULogEventNumberNames[eventNumber];
}


// This function reads in the header of an event from the UserLog and fills
// the fields of the event object.  It does *not* read the event number.  The 
// caller is supposed to read the event number, instantiate the appropriate 
// event type using instantiateEvent(), and then call readEvent() of the 
// returned event.
int ULogEvent::
readHeader (FILE *file)
{
	int retval;
	
	// read from file
	retval = fscanf (file, " (%d.%d.%d) %d/%d %d:%d:%d ", 
					 &cluster, &proc, &subproc,
					 &(eventTime.tm_mon), &(eventTime.tm_mday), 
					 &(eventTime.tm_hour), &(eventTime.tm_min), 
					 &(eventTime.tm_sec));

	// check if all fields were successfully read
	if (retval != 8)
	{
		return 0;
	}

	// recall that tm_mon+1 was written to log; decrement to compensate
	eventTime.tm_mon--;

	return 1;
}


// Write the header for the event to the file
int ULogEvent::
writeHeader (FILE *file)
{
	int       retval;

	// write header
	retval = fprintf (file, "%03d (%03d.%03d.%03d) %02d/%02d %02d:%02d:%02d ",
					  eventNumber, 
					  cluster, proc, subproc,
					  eventTime.tm_mon+1, eventTime.tm_mday, 
					  eventTime.tm_hour, eventTime.tm_min, eventTime.tm_sec);

	// check if all fields were sucessfully written
	if (retval < 0) 
	{
		return 0;
	}

	return 1;
}

ClassAd* ULogEvent::
toClassAd()
{
	ClassAd* myad = new ClassAd;

	char buf0[128];

	if( eventNumber >= 0 ) {
		snprintf(buf0, 128, "EventTypeNumber = %d", eventNumber);
		buf0[127] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}
	
	switch( (ULogEventNumber) eventNumber )
	{
	  case ULOG_SUBMIT:
		myad->SetMyTypeName("SubmitEvent");
		break;
	  case ULOG_EXECUTE:
		myad->SetMyTypeName("ExecuteEvent");
		break;
	  case ULOG_EXECUTABLE_ERROR:
		myad->SetMyTypeName("ExecutableErrorEvent");
		break;
	  case ULOG_CHECKPOINTED:
		myad->SetMyTypeName("CheckpointedEvent");
		break;
	  case ULOG_JOB_EVICTED:
		myad->SetMyTypeName("JobEvictedEvent");
		break;
	  case ULOG_JOB_TERMINATED:
		myad->SetMyTypeName("JobTerminatedEvent");
		break;
	  case ULOG_IMAGE_SIZE:
		myad->SetMyTypeName("JobImageSizeEvent");
		break;
	  case ULOG_SHADOW_EXCEPTION:
		myad->SetMyTypeName("ShadowExceptionEvent");
		break;
	  case ULOG_GENERIC:
		myad->SetMyTypeName("GenericEvent");
		break;
	  case ULOG_JOB_ABORTED:
		myad->SetMyTypeName("JobAbortedEvent");
		break;
	  case ULOG_JOB_SUSPENDED:
		myad->SetMyTypeName("JobSuspendedEvent");
		break;
	  case ULOG_JOB_UNSUSPENDED:
		myad->SetMyTypeName("JobUnsuspendedEvent");
		break;
	  case ULOG_JOB_HELD:
		myad->SetMyTypeName("JobHeldEvent");
		break;
	  case ULOG_JOB_RELEASED:
		myad->SetMyTypeName("JobReleaseEvent");
		break;
	  case ULOG_NODE_EXECUTE:
		myad->SetMyTypeName("NodeExecuteEvent");
		break;
	  case ULOG_NODE_TERMINATED:
		myad->SetMyTypeName("NodeTerminatedEvent");
		break;
	  case ULOG_POST_SCRIPT_TERMINATED:
		myad->SetMyTypeName("PostScriptTerminatedEvent");
		break;
	  case ULOG_GLOBUS_SUBMIT:
		myad->SetMyTypeName("GlobusSubmitEvent");
		break;
	  case ULOG_GLOBUS_SUBMIT_FAILED:
		myad->SetMyTypeName("GlobusSubmitFailedEvent");
		break;
	  case ULOG_GLOBUS_RESOURCE_UP:
		myad->SetMyTypeName("GlobusResourceUpEvent");
		break;
	  case ULOG_GLOBUS_RESOURCE_DOWN:
		myad->SetMyTypeName("GlobusResourceDownEvent");
		break;
	case ULOG_REMOTE_ERROR:
		myad->SetMyTypeName("RemoteErrorEvent");
		break;
	case ULOG_JOB_DISCONNECTED:
		myad->SetMyTypeName("JobDisconnectedEvent");
		break;
	case ULOG_JOB_RECONNECTED:
		myad->SetMyTypeName("JobReconnectedEvent");
		break;
	case ULOG_JOB_RECONNECT_FAILED:
		myad->SetMyTypeName("JobReconnectFailedEvent");
		break;
	case ULOG_GRID_RESOURCE_UP:
		myad->SetMyTypeName("GridResourceUpEvent");
		break;
	case ULOG_GRID_RESOURCE_DOWN:
		myad->SetMyTypeName("GridResourceDownEvent");
		break;
	case ULOG_GRID_SUBMIT:
		myad->SetMyTypeName("GridSubmitEvent");
		break;
	case ULOG_JOB_AD_INFORMATION:
		myad->SetMyTypeName("JobAdInformationEvent");
		break;
	  default:
		return NULL;
	}

	const struct tm tmdup = eventTime;
	char* eventTimeStr = time_to_iso8601(tmdup, ISO8601_ExtendedFormat,
										 ISO8601_DateAndTime, FALSE);
	if( eventTimeStr ) {
		MyString buf1;
		buf1.sprintf("EventTime = \"%s\"", eventTimeStr);
		free(eventTimeStr);
		if( !myad->Insert(buf1.Value()) ) return NULL;
	} else {
		return NULL;
	}

	if( cluster >= 0 ) {
		snprintf(buf0, 128, "Cluster = %d", cluster);
		buf0[127] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}

	if( proc >= 0 ) {
		snprintf(buf0, 128, "Proc = %d", proc);
		buf0[127] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}

	if( subproc >= 0 ) {
		snprintf(buf0, 128, "Subproc = %d", subproc);
		buf0[127] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}
	
	return myad;
}

void ULogEvent::
initFromClassAd(ClassAd* ad)
{
	if( !ad ) return;
	int en;
	if ( ad->LookupInteger("EventTypeNumber", en) ) {
		eventNumber = (ULogEventNumber) en;
	}
	char* timestr = NULL;
	if( ad->LookupString("EventTime", &timestr) ) {
		bool f = FALSE;
		iso8601_to_time(timestr, &eventTime, &f);
		free(timestr);
	}
	ad->LookupInteger("Cluster", cluster);
	ad->LookupInteger("Proc", proc);
	ad->LookupInteger("Subproc", subproc);
}

void ULogEvent::
insertCommonIdentifiers(ClassAd *adToFill)
{
	MyString tmp;

	if( !adToFill ) return;
	if(scheddname) {
	  tmp.sprintf("scheddname = \"%s\"", scheddname);
	  adToFill->Insert(tmp.GetCStr());
	}

	if(m_gjid) {
	  tmp.sprintf("globaljobid = \"%s\"", m_gjid);
	  adToFill->Insert(tmp.GetCStr());
	}
 
	tmp.sprintf("cluster_id = %d", cluster);
	adToFill->Insert(tmp.GetCStr());

	tmp.sprintf("proc_id = %d", proc);
	adToFill->Insert(tmp.GetCStr());

	tmp.sprintf("spid = %d", subproc);
	adToFill->Insert(tmp.GetCStr());
}


// ----- the SubmitEvent class
SubmitEvent::
SubmitEvent()
{	
	submitHost [0] = '\0';
	submitEventLogNotes = NULL;
	submitEventUserNotes = NULL;
	eventNumber = ULOG_SUBMIT;
}

SubmitEvent::
~SubmitEvent()
{
    if( submitEventLogNotes ) {
        delete[] submitEventLogNotes;
    }
    if( submitEventUserNotes ) {
        delete[] submitEventUserNotes;
    }
}

int SubmitEvent::
writeEvent (FILE *file)
{	
	int retval = fprintf (file, "Job submitted from host: %s\n", submitHost);
	if (retval < 0)
	{
		return 0;
	}
	if( submitEventLogNotes ) {
		retval = fprintf( file, "    %.8191s\n", submitEventLogNotes );
		if( retval < 0 ) {
			return 0;
		}
	}
	if( submitEventUserNotes ) {
		retval = fprintf( file, "    %.8191s\n", submitEventUserNotes );
		if( retval < 0 ) {
			return 0;
		}
	}
	return (1);
}

int SubmitEvent::
readEvent (FILE *file)
{
	char s[8192];
	s[0] = '\0';
	delete[] submitEventLogNotes;
	submitEventLogNotes = NULL;
	if( fscanf( file, "Job submitted from host: %s\n", submitHost ) != 1 ) {
		return 0;
	}

	// check if event ended without specifying submit host.
	// in this case, the submit host would be the event delimiter
	if ( strncmp(submitHost,"...",3)==0 ) {
		submitHost[0] = '\0';
		// Backup to leave event delimiter unread go past \n too
		fseek( file, -4, SEEK_CUR );
		return 1;
	}

	// see if the next line contains an optional event notes string,
	// and, if not, rewind, because that means we slurped in the next
	// event delimiter looking for it...
 
	fpos_t filep;
	fgetpos( file, &filep );
     
	if( !fgets( s, 8192, file ) || strcmp( s, "...\n" ) == 0 ) {
		fsetpos( file, &filep );
		return 1;
	}
 
	// remove trailing newline
	s[ strlen( s ) - 1 ] = '\0';

	submitEventLogNotes = strnewp( s );

	// see if the next line contains an optional user event notes
	// string, and, if not, rewind, because that means we slurped in
	// the next event delimiter looking for it...
 
	fgetpos( file, &filep );
     
	if( !fgets( s, 8192, file ) || strcmp( s, "...\n" ) == 0 ) {
		fsetpos( file, &filep );
		return 1;
	}
 
	// remove trailing newline
	s[ strlen( s ) - 1 ] = '\0';

	submitEventUserNotes = strnewp( s );
	return 1;
}

ClassAd* SubmitEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];

	if( submitHost[0] ) {
		snprintf(buf0, 512, "SubmitHost = \"%s\"", submitHost);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}

	if( submitEventLogNotes && submitEventLogNotes[0] ) {
		MyString buf2;
		buf2.sprintf("LogNotes = \"%s\"", submitEventLogNotes);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}
	if( submitEventUserNotes && submitEventUserNotes[0] ) {
		MyString buf3;
		buf3.sprintf("UserNotes = \"%s\"", submitEventUserNotes);
		if( !myad->Insert(buf3.Value()) ) return NULL;
	}

	return myad;
}

void SubmitEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;
	if( ad->LookupString("SubmitHost", submitHost, 128) ) {
		submitHost[127] = 0;
	}

	// this fanagling is to ensure we don't malloc a pointer then delete it
	char* mallocstr = NULL;
	ad->LookupString("LogNotes", &mallocstr);
	if( mallocstr ) {
		submitEventLogNotes = new char[strlen(mallocstr) + 1];
		strcpy(submitEventLogNotes, mallocstr);
		free(mallocstr);
		mallocstr = NULL;
	}

	// this fanagling is to ensure we don't malloc a pointer then delete it
	ad->LookupString("UserNotes", &mallocstr);
	if( mallocstr ) {
		submitEventUserNotes = new char[strlen(mallocstr) + 1];
		strcpy(submitEventUserNotes, mallocstr);
		free(mallocstr);
		mallocstr = NULL;
	}
}

// ----- the GlobusSubmitEvent class
GlobusSubmitEvent::
GlobusSubmitEvent()
{	
	eventNumber = ULOG_GLOBUS_SUBMIT;
	rmContact = NULL;
	jmContact = NULL;
	restartableJM = false;
}

GlobusSubmitEvent::
~GlobusSubmitEvent()
{
	delete[] rmContact;
	delete[] jmContact;
}

int GlobusSubmitEvent::
writeEvent (FILE *file)
{
	const char * unknown = "UNKNOWN";
	const char * rm = unknown;
	const char * jm = unknown;

	int retval = fprintf (file, "Job submitted to Globus\n");
	if (retval < 0)
	{
		return 0;
	}
	
	if ( rmContact ) rm = rmContact;
	if ( jmContact ) jm = jmContact;

	retval = fprintf( file, "    RM-Contact: %.8191s\n", rm );
	if( retval < 0 ) {
		return 0;
	}

	retval = fprintf( file, "    JM-Contact: %.8191s\n", jm );
	if( retval < 0 ) {
		return 0;
	}

	int newjm = 0;
	if ( restartableJM ) { 
		newjm = 1;
	}
	retval = fprintf( file, "    Can-Restart-JM: %d\n", newjm );
	if( retval < 0 ) {
		return 0;
	}

	return (1);
}

int GlobusSubmitEvent::
readEvent (FILE *file)
{
	char s[8192];

	delete[] rmContact;
	delete[] jmContact;
	rmContact = NULL;
	jmContact = NULL;
	int retval = fscanf (file, "Job submitted to Globus\n");
    if (retval != 0)
    {
		return 0;
    }
	s[0] = '\0';
	retval = fscanf( file, "    RM-Contact: %8191s\n", s );
	if ( retval != 1 )
	{
		return 0;
	}
	rmContact = strnewp(s);
	retval = fscanf( file, "    JM-Contact: %8191s\n", s );
	if ( retval != 1 )
	{
		return 0;
	}
	jmContact = strnewp(s);
	
	int newjm = 0;
	retval = fscanf( file, "    Can-Restart-JM: %d\n", &newjm );
	if ( retval != 1 )
	{
		return 0;
	}
	if ( newjm ) {
		restartableJM = true;
	} else {
		restartableJM = false;
	}
    
	
	return 1;
}

ClassAd* GlobusSubmitEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];
	
	if( rmContact && rmContact[0] ) {
		MyString buf2;
		buf2.sprintf("RMContact = \"%s\"",rmContact);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}
	if( jmContact && jmContact[0] ) {
		MyString buf3;
		buf3.sprintf("JMContact = \"%s\"",jmContact);
		if( !myad->Insert(buf3.Value()) ) return NULL;
	}

	snprintf(buf0, 512, "RestartableJM = %s", restartableJM ? "TRUE" : "FALSE");
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	return myad;
}

void GlobusSubmitEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;
	
	// this fanagling is to ensure we don't malloc a pointer then delete it
	char* mallocstr = NULL;
	ad->LookupString("RMContact", &mallocstr);
	if( mallocstr ) {
		rmContact = new char[strlen(mallocstr) + 1];
		strcpy(rmContact, mallocstr);
		free(mallocstr);
	}

	// this fanagling is to ensure we don't malloc a pointer then delete it
	mallocstr = NULL;
	ad->LookupString("JMContact", &mallocstr);
	if( mallocstr ) {
		jmContact = new char[strlen(mallocstr) + 1];
		strcpy(jmContact, mallocstr);
		free(mallocstr);
	}

	int reallybool;
	if( ad->LookupInteger("RestartableJM", reallybool) ) {
		restartableJM = reallybool ? TRUE : FALSE;
	}
}

// ----- the GlobusSubmitFailedEvent class
GlobusSubmitFailedEvent::
GlobusSubmitFailedEvent()
{	
	eventNumber = ULOG_GLOBUS_SUBMIT_FAILED;
	reason = NULL;
}

GlobusSubmitFailedEvent::
~GlobusSubmitFailedEvent()
{
	delete[] reason;
}

int GlobusSubmitFailedEvent::
writeEvent (FILE *file)
{
	const char * unknown = "UNKNOWN";
	const char * reasonString = unknown;

	int retval = fprintf (file, "Globus job submission failed!\n");
	if (retval < 0)
	{
		return 0;
	}
	
	if ( reason ) reasonString = reason;

	retval = fprintf( file, "    Reason: %.8191s\n", reasonString );
	if( retval < 0 ) {
		return 0;
	}

	return (1);
}

int GlobusSubmitFailedEvent::
readEvent (FILE *file)
{
	char s[8192];

	delete[] reason;
	reason = NULL;
	int retval = fscanf (file, "Globus job submission failed!\n");
    if (retval != 0)
    {
		return 0;
    }
	s[0] = '\0';

	fpos_t filep;
	fgetpos( file, &filep );
     
	if( !fgets( s, 8192, file ) || strcmp( s, "...\n" ) == 0 ) {
		fsetpos( file, &filep );
		return 1;
	}
 
	// remove trailing newline
	s[ strlen( s ) - 1 ] = '\0';

	// Copy after the "Reason: "
	reason = strnewp( &s[8] );
	return 1;
}

ClassAd* GlobusSubmitFailedEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	
	if( reason && reason[0] ) {
		MyString buf2;
		buf2.sprintf("Reason = \"%s\"", reason);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}

	return myad;
}

void GlobusSubmitFailedEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	// this fanagling is to ensure we don't malloc a pointer then delete it
	char* mallocstr = NULL;
	ad->LookupString("Reason", &mallocstr);
	if( mallocstr ) {
		reason = new char[strlen(mallocstr) + 1];
		strcpy(reason, mallocstr);
		free(mallocstr);
	}
}

// ----- the GlobusResourceUp class
GlobusResourceUpEvent::
GlobusResourceUpEvent()
{	
	eventNumber = ULOG_GLOBUS_RESOURCE_UP;
	rmContact = NULL;
}

GlobusResourceUpEvent::
~GlobusResourceUpEvent()
{
	delete[] rmContact;
}

int GlobusResourceUpEvent::
writeEvent (FILE *file)
{
	const char * unknown = "UNKNOWN";
	const char * rm = unknown;

	int retval = fprintf (file, "Globus Resource Back Up\n");
	if (retval < 0)
	{
		return 0;
	}
	
	if ( rmContact ) rm = rmContact;

	retval = fprintf( file, "    RM-Contact: %.8191s\n", rm );
	if( retval < 0 ) {
		return 0;
	}

	return (1);
}

int GlobusResourceUpEvent::
readEvent (FILE *file)
{
	char s[8192];

	delete[] rmContact;
	rmContact = NULL;
	int retval = fscanf (file, "Globus Resource Back Up\n");
    if (retval != 0)
    {
		return 0;
    }
	s[0] = '\0';
	retval = fscanf( file, "    RM-Contact: %8191s\n", s );
	if ( retval != 1 )
	{
		return 0;
	}
	rmContact = strnewp(s);	
	return 1;
}

ClassAd* GlobusResourceUpEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	
	if( rmContact && rmContact[0] ) {
		MyString buf2;
		buf2.sprintf("RMContact = \"%s\"",rmContact);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}

	return myad;
}

void GlobusResourceUpEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	// this fanagling is to ensure we don't malloc a pointer then delete it
	char* mallocstr = NULL;
	ad->LookupString("RMContact", &mallocstr);
	if( mallocstr ) {
		rmContact = new char[strlen(mallocstr) + 1];
		strcpy(rmContact, mallocstr);
		free(mallocstr);
	}
}


// ----- the GlobusResourceUp class
GlobusResourceDownEvent::
GlobusResourceDownEvent()
{	
	eventNumber = ULOG_GLOBUS_RESOURCE_DOWN;
	rmContact = NULL;
}

GlobusResourceDownEvent::
~GlobusResourceDownEvent()
{
	delete[] rmContact;
}

int GlobusResourceDownEvent::
writeEvent (FILE *file)
{
	const char * unknown = "UNKNOWN";
	const char * rm = unknown;

	int retval = fprintf (file, "Detected Down Globus Resource\n");
	if (retval < 0)
	{
		return 0;
	}
	
	if ( rmContact ) rm = rmContact;

	retval = fprintf( file, "    RM-Contact: %.8191s\n", rm );
	if( retval < 0 ) {
		return 0;
	}

	return (1);
}

int GlobusResourceDownEvent::
readEvent (FILE *file)
{
	char s[8192];

	delete[] rmContact;
	rmContact = NULL;
	int retval = fscanf (file, "Detected Down Globus Resource\n");
    if (retval != 0)
    {
		return 0;
    }
	s[0] = '\0';
	retval = fscanf( file, "    RM-Contact: %8191s\n", s );
	if ( retval != 1 )
	{
		return 0;
	}
	rmContact = strnewp(s);	
	return 1;
}

ClassAd* GlobusResourceDownEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	
	if( rmContact && rmContact[0] ) {
		MyString buf2;
		buf2.sprintf("RMContact = \"%s\"",rmContact);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}

	return myad;
}

void GlobusResourceDownEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	// this fanagling is to ensure we don't malloc a pointer then delete it
	char* mallocstr = NULL;
	ad->LookupString("RMContact", &mallocstr);
	if( mallocstr ) {
		rmContact = new char[strlen(mallocstr) + 1];
		strcpy(rmContact, mallocstr);
		free(mallocstr);
	}
}


// ----- the GenericEvent class
GenericEvent::
GenericEvent()
{	
	info[0] = '\0';
	eventNumber = ULOG_GENERIC;
}

GenericEvent::
~GenericEvent()
{
}

int GenericEvent::
writeEvent(FILE *file)
{
    int retval = fprintf(file, "%s\n", info);
    if (retval < 0)
    {
	return 0;
    }
    
    return 1;
}

int GenericEvent::
readEvent(FILE *file)
{
    int retval = fscanf(file, "%[^\n]\n", info);
    if (retval < 0)
    {
	return 0;
    }
    return 1;
}
	
ClassAd* GenericEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];

	if( info[0] ) {
		snprintf(buf0, 512, "Info = \"%s\"", info);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}

	return myad;
}

void GenericEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	if( ad->LookupString("Info", info, 128) ) {
		info[127] = 0;
	}
}

void GenericEvent::
setInfoText(char const *str)
{
	strncpy(info,str,sizeof(info));
	info[ sizeof(info) - 1 ] = '\0'; //ensure null-termination
}

// ----- the RemoteErrorEvent class
RemoteErrorEvent::RemoteErrorEvent()
{	
	error_str = NULL;
	execute_host[0] = daemon_name[0] = '\0';
	eventNumber = ULOG_REMOTE_ERROR;
	critical_error = true;
	hold_reason_code = 0;
	hold_reason_subcode = 0;
}

RemoteErrorEvent::~RemoteErrorEvent()
{
	delete[] error_str;
}

void
RemoteErrorEvent::setHoldReasonCode(int hold_reason_code_arg)
{
	this->hold_reason_code = hold_reason_code_arg;
}
void
RemoteErrorEvent::setHoldReasonSubCode(int hold_reason_subcode_arg)
{
	this->hold_reason_subcode = hold_reason_subcode_arg;
}

int
RemoteErrorEvent::writeEvent(FILE *file)
{
	char const *error_type = "Error";
	char messagestr[512];
	
	ClassAd tmpCl1, tmpCl2;
	ClassAd *tmpClP1 = &tmpCl1, *tmpClP2 = &tmpCl2;
	MyString tmp = "";
	int retval;

	snprintf(messagestr, 512, "Remote %s from %s on %s",
			error_type,
			daemon_name,
			execute_host);
	
	scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );

	if(!critical_error) error_type = "Warning";

	if (critical_error) {
		tmp.sprintf("endts = %d", (int)eventclock);
		tmpClP1->Insert(tmp.GetCStr());		
		
		tmp.sprintf("endtype = %d", ULOG_REMOTE_ERROR);
		tmpClP1->Insert(tmp.GetCStr());
		
		tmp.sprintf("endmessage = \"%s\"", messagestr);
		tmpClP1->Insert(tmp.GetCStr());
	
		// this inserts scheddname, cluster, proc, etc
		insertCommonIdentifiers(tmpClP2);		

		tmp.sprintf("endtype = null");
		tmpClP2->Insert(tmp.GetCStr());

			// critical error means this run is ended.  
			// condor_event.o is part of cplus_lib.a, which may be linked by 
			// non-daemons who wouldn't have initialized FILEObj. We don't 
			// need to log events for non-daemons.
		if (FILEObj) {
			if (FILEObj->file_updateEvent("Runs", tmpClP1, tmpClP2) 
				== QUILL_FAILURE) {	
				dprintf(D_ALWAYS, "Logging Event 5--- Error\n");
				return 0; // return a error code, 0
			}		
		}

	} else {		
		        // this inserts scheddname, cluster, proc, etc
        insertCommonIdentifiers(tmpClP1);           

		tmp.sprintf( "eventtype = %d", ULOG_REMOTE_ERROR);
		tmpClP1->Insert(tmp.GetCStr());
		
		tmp.sprintf( "eventtime = %d", (int)eventclock);
		tmpClP1->Insert(tmp.GetCStr());	
		
		tmp.sprintf( "description = \"%s\"", messagestr);
		tmpClP1->Insert(tmp.GetCStr());	
				
		if (FILEObj) {
			if (FILEObj->file_newEvent("Events", tmpClP1) == QUILL_FAILURE) {
				dprintf(D_ALWAYS, "Logging Event 5--- Error\n");
				return 0; // return a error code, 0
			}			
		}
	}

    retval = fprintf(
	  file,
	  "%s from %s on %s:\n",
	  error_type,
	  daemon_name,
	  execute_host);



    if (retval < 0)
    {
	return 0;
    }

	//output each line of error_str, indented by one tab
	char *line = error_str;
	if(line)
	while(*line) {
		char *next_line = strchr(line,'\n');
		if(next_line) *next_line = '\0';

		retval = fprintf(file,"\t%s\n",line);
		if(retval < 0) return 0;

		if(!next_line) break;
		*next_line = '\n';
		line = next_line+1;
	}

	if (hold_reason_code) {
		fprintf(file,"\tCode %d Subcode %d\n",
		        hold_reason_code, hold_reason_subcode);
	}

    return 1;
}

int
RemoteErrorEvent::readEvent(FILE *file)
{
	char line[8192];
	char error_type[128];
    int retval = fscanf(
	  file,
	  "%127s from %127s on %127s\n",
	  error_type,
	  daemon_name,
	  execute_host);

    if (retval < 0)
    {
	return 0;
    }

	error_type[sizeof(error_type)-1] = '\0';
	daemon_name[sizeof(daemon_name)-1] = '\0';
	execute_host[sizeof(execute_host)-1] = '\0';

	if(!strcmp(error_type,"Error")) critical_error = true;
	else if(!strcmp(error_type,"Warning")) critical_error = false;

	//Now read one or more error_str lines from the body.
	MyString lines;

	while(!feof(file)) {
		// see if the next line contains an optional event notes string,
		// and, if not, rewind, because that means we slurped in the next
		// event delimiter looking for it...

		fpos_t filep;
		fgetpos( file, &filep );
     
		if( !fgets(line, sizeof(line), file) || strcmp(line, "...\n") == 0 ) {
			fsetpos( file, &filep );
			break;
		}

		char *l = strchr(line,'\n');
		if(l) *l = '\0';

		l = line;
		if(l[0] == '\t') l++;

		int code,subcode;
		if( sscanf(l,"Code %d Subcode %d",&code,&subcode) == 2 ) {
			hold_reason_code = code;
			hold_reason_subcode = subcode;
			continue;
		}

		if(lines.Length()) lines += "\n";
		lines += l;
	}

	setErrorText(lines.GetCStr());
    return 1;
}

ClassAd*
RemoteErrorEvent::toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;

	if(*daemon_name) {
		myad->Assign("Daemon",daemon_name);
	}
	if(*execute_host) {
		myad->Assign("ExecuteHost",execute_host);
	}
	if(error_str) {
		myad->Assign("ErrorMsg",error_str);
	}
	if(!critical_error) { //default is true
		myad->Assign("CriticalError",(int)critical_error);
	}
	if(hold_reason_code) {
		myad->Assign(ATTR_HOLD_REASON_CODE, hold_reason_code);
		myad->Assign(ATTR_HOLD_REASON_SUBCODE, hold_reason_subcode);
	}

	return myad;
}

void
RemoteErrorEvent::initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);
	char *buf;
	int crit_err = 0;

	if( !ad ) return;

	if( ad->LookupString("Daemon", daemon_name, sizeof(daemon_name)) ) {
		daemon_name[sizeof(daemon_name)-1] = '\0';
	}
	if( ad->LookupString("ExecuteHost", execute_host, sizeof(execute_host)) ) {
		execute_host[sizeof(execute_host)-1] = '\0';
	}
	if( ad->LookupString("ErrorMsg", &buf) ) {
		setErrorText(buf);
		free(buf);
	}
	if( ad->LookupInteger("CriticalError",crit_err) ) {
		critical_error = (crit_err != 0);
	}
	ad->LookupInteger(ATTR_HOLD_REASON_CODE, hold_reason_code);
	ad->LookupInteger(ATTR_HOLD_REASON_SUBCODE, hold_reason_subcode);
}

void
RemoteErrorEvent::setCriticalError(bool f)
{
	critical_error = f;
}

void
RemoteErrorEvent::setErrorText(char const *str)
{
	char *s = strnewp(str);
	delete [] error_str;
	error_str = s;
}

void
RemoteErrorEvent::setDaemonName(char const *str)
{
	if(!str) str = "";
	strncpy(daemon_name,str,sizeof(daemon_name));
	daemon_name[sizeof(daemon_name)-1] = '\0';
}

void
RemoteErrorEvent::setExecuteHost(char const *str)
{
	if(!str) str = "";
	strncpy(execute_host,str,sizeof(execute_host));
	execute_host[sizeof(execute_host)-1] = '\0';
}

// ----- the ExecuteEvent class
ExecuteEvent::
ExecuteEvent()
{	
	executeHost [0] = '\0';
	remoteName [0] = '\0';
	eventNumber = ULOG_EXECUTE;
}

ExecuteEvent::
~ExecuteEvent()
{
}


int ExecuteEvent::
writeEvent (FILE *file)
{	
  struct hostent *hp;
  unsigned long addr;
  MyString executehostname = "";
  ClassAd tmpCl1, tmpCl2, tmpCl3;
  ClassAd *tmpClP1 = &tmpCl1, *tmpClP2 = &tmpCl2, *tmpClP3 = &tmpCl3;
  MyString tmp = "";
  int retval;

  //JobAd is defined in condor_shadow.V6/log_events.C and is simply
  //defined as an external variable here

  scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );
  
  if(scheddname) 
    dprintf(D_FULLDEBUG, "scheddname = %s\n", scheddname);
  else 
    dprintf(D_FULLDEBUG, "scheddname is null\n");
  
  dprintf(D_FULLDEBUG, "executeHost = %s\n", executeHost);

  char *start = index(executeHost, '<');
  char *end = index(executeHost, ':');

  if(start && end) {
    char *tmpaddr;
    tmpaddr = (char *) malloc(32 * sizeof(char));
    tmpaddr = strncpy(tmpaddr, start+1, end-start-1);
    tmpaddr[end-start-1] = '\0';
    addr = inet_addr(tmpaddr);
	dprintf(D_FULLDEBUG, "start = %s\n", start);
	dprintf(D_FULLDEBUG, "end = %s\n", end);
	dprintf(D_FULLDEBUG, "tmpaddr = %s\n", tmpaddr);
    free(tmpaddr);
  }
  else {
    addr = inet_addr(executeHost);
  }

  hp = gethostbyaddr((char *) &addr, sizeof(addr), AF_INET);
  if(hp) {    
    dprintf(D_FULLDEBUG, "Executehost name = %s (hp->h_name) \n", hp->h_name);
    executehostname = hp->h_name;
  }
  else {
    dprintf(D_FULLDEBUG, "Executehost name = %s (executeHost) \n", executeHost);
    executehostname = executeHost;
  }

  tmp.sprintf("endts = %d", (int)eventclock);
  tmpClP1->Insert(tmp.GetCStr());

  tmp.sprintf("endtype = -1");
  tmpClP1->Insert(tmp.GetCStr());

  tmp.sprintf("endmessage = \"UNKNOWN ERROR\"");
  tmpClP1->Insert(tmp.GetCStr());
 
  // this inserts scheddname, cluster, proc, etc
  insertCommonIdentifiers(tmpClP2);           

  tmp.sprintf("endtype = null");
  tmpClP2->Insert(tmp.GetCStr());
  
  if (FILEObj) {
	  if (FILEObj->file_updateEvent("Runs", tmpClP1, tmpClP2) == QUILL_FAILURE) {
		  dprintf(D_ALWAYS, "Logging Event 1--- Error\n");
		  return 0; // return a error code, 0
	  }
  }

  tmp.sprintf("machine_id = \"%s\"", remoteName);
  tmpClP3->Insert(tmp.GetCStr());

  // this inserts scheddname, cluster, proc, etc
  insertCommonIdentifiers(tmpClP3);           

  tmp.sprintf("startts = %d", (int)eventclock);
  tmpClP3->Insert(tmp.GetCStr());

  if(FILEObj) {
	  if (FILEObj->file_newEvent("Runs", tmpClP3) == QUILL_FAILURE) {
		  dprintf(D_ALWAYS, "Logging Event 1--- Error\n");
		  return 0; // return a error code, 0
	  }
  }

  retval = fprintf (file, "Job executing on host: %s\n", executeHost);

  if (retval < 0) {
     return 0;
  }

  return 1;
}

int ExecuteEvent::
readEvent (FILE *file)
{
	MyString line;
	if ( ! line.readLine(file) ) 
	{
		return 0; // EOF or error
	}

		// 127 is sizeof(executeHost)-1
	int retval  = sscanf (line.Value(), "Job executing on host: %127[^\n]",
						  executeHost);
	if (retval == 1)
	{
		return 1;
	}

	if(strcmp(line.Value(), "Job executing on host: \n") == 0) {
		// Simply lacks a hostname.  Allow.
		executeHost[0] = 0;
		return 1;
	}

	return 0;
}

ClassAd* ExecuteEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];

	if( executeHost[0] ) {
		snprintf(buf0, 512, "ExecuteHost = \"%s\"", executeHost);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}

	return myad;
}

void ExecuteEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	if( !ad->LookupString("ExecuteHost", executeHost, 128) ) {
		executeHost[127] = 0;
	}
}


// ----- the ExecutableError class
ExecutableErrorEvent::
ExecutableErrorEvent()
{
	errType = (ExecErrorType) -1;
	eventNumber = ULOG_EXECUTABLE_ERROR;
}


ExecutableErrorEvent::
~ExecutableErrorEvent()
{
}

int ExecutableErrorEvent::
writeEvent (FILE *file)
{
	int retval;
	char messagestr[512];
	ClassAd tmpCl1, tmpCl2;
	ClassAd *tmpClP1 = &tmpCl1, *tmpClP2 = &tmpCl2;
	MyString tmp = "";

	scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );

	tmp.sprintf( "endts = %d", (int)eventclock);
	tmpClP1->Insert(tmp.GetCStr());		
		
	tmp.sprintf( "endtype = %d", ULOG_EXECUTABLE_ERROR);
	tmpClP1->Insert(tmp.GetCStr());
		
	tmp.sprintf( "endmessage = \"%s\"", messagestr);
	tmpClP1->Insert(tmp.GetCStr());
		
	// this inserts scheddname, cluster, proc, etc
	insertCommonIdentifiers(tmpClP2);           

	tmp.sprintf( "endtype = null");
	tmpClP2->Insert(tmp.GetCStr());
  
	if (FILEObj) {
		if (FILEObj->file_updateEvent("Runs", tmpClP1, tmpClP2) == QUILL_FAILURE) {
			dprintf(D_ALWAYS, "Logging Event 12--- Error\n");
			return 0; // return a error code, 0
		}
	}

	switch (errType)
	{
	  case CONDOR_EVENT_NOT_EXECUTABLE:
		retval = fprintf (file, "(%d) Job file not executable.\n", errType);
		sprintf(messagestr,  "Job file not executable");
		break;

	  case CONDOR_EVENT_BAD_LINK:
		retval=fprintf(file,"(%d) Job not properly linked for Condor.\n", errType);
		sprintf(messagestr,  "Job not properly linked for Condor");
		break;

	  default:
		retval = fprintf (file, "(%d) [Bad error number.]\n", errType);
		sprintf(messagestr,  "Unknown error");
	}
				
	if (retval < 0) return 0;

	return 1;
}


int ExecutableErrorEvent::
readEvent (FILE *file)
{
	int  retval;
	char buffer [128];

	// get the error number
	retval = fscanf (file, "(%d)", (int*)&errType);
	if (retval != 1) 
	{ 
		return 0;
	}

	// skip over the rest of the line
	if (fgets (buffer, 128, file) == 0)
	{
		return 0;
	}

	return 1;
}

ClassAd* ExecutableErrorEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];
	
	if( errType >= 0 ) {
		snprintf(buf0, 512, "ExecuteErrorType = %d", errType);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}

	return myad;
}

void ExecutableErrorEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	int reallyExecErrorType;
	if( ad->LookupInteger("ExecuteErrorType", reallyExecErrorType) ) {
		switch( reallyExecErrorType ) {
		  case CONDOR_EVENT_NOT_EXECUTABLE:
			errType = CONDOR_EVENT_NOT_EXECUTABLE;
			break;
		  case CONDOR_EVENT_BAD_LINK:
			errType = CONDOR_EVENT_BAD_LINK;
			break;
		}
	}
}

// ----- the CheckpointedEvent class
CheckpointedEvent::
CheckpointedEvent()
{
	(void)memset((void*)&run_local_rusage,0,(size_t) sizeof(run_local_rusage));
	run_remote_rusage = run_local_rusage;

	eventNumber = ULOG_CHECKPOINTED;

    sent_bytes = 0.0;
}

CheckpointedEvent::
~CheckpointedEvent()
{
}

int CheckpointedEvent::
writeEvent (FILE *file)
{
	char messagestr[512];
	ClassAd tmpCl1;
	ClassAd *tmpClP1 = &tmpCl1;
	MyString tmp = "";

	sprintf(messagestr,  "Job was checkpointed");

	scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );

	// this inserts scheddname, cluster, proc, etc
	insertCommonIdentifiers(tmpClP1);           

	tmp.sprintf( "eventtype = %d", ULOG_CHECKPOINTED);
	tmpClP1->Insert(tmp.GetCStr());
		
	tmp.sprintf( "eventtime = %d", (int)eventclock);
	tmpClP1->Insert(tmp.GetCStr());	
	
	tmp.sprintf( "description = \"%s\"", messagestr);
	tmpClP1->Insert(tmp.GetCStr());	
				
	if (FILEObj) {
		if (FILEObj->file_newEvent("Events", tmpClP1) == QUILL_FAILURE) {
			dprintf(D_ALWAYS, "Logging Event 6--- Error\n");
			return 0; // return a error code, 0
		}
	}

	if (fprintf (file, "Job was checkpointed.\n") < 0  		||
		(!writeRusage (file, run_remote_rusage)) 			||
		(fprintf (file, "  -  Run Remote Usage\n") < 0) 	||
		(!writeRusage (file, run_local_rusage)) 			||
		(fprintf (file, "  -  Run Local Usage\n") < 0))
		return 0;

    if( fprintf(file, "\t%.0f  -  Run Bytes Sent By Job For Checkpoint\n",
                sent_bytes) < 0 ) {
        return 0;
    }


	return 1;
}

int CheckpointedEvent::
readEvent (FILE *file)
{
	int retval = fscanf (file, "Job was checkpointed.\n");

	char buffer[128];
	if (retval == EOF ||
		!readRusage(file,run_remote_rusage) || fgets (buffer,128,file) == 0  ||
		!readRusage(file,run_local_rusage)  || fgets (buffer,128,file) == 0)
		return 0;

    if( !fscanf(file, "\t%f  -  Run Bytes Sent By Job For Checkpoint\n",
                &sent_bytes)) {
        return 1;		//backwards compatibility
    }

	return 1;
}
		
ClassAd* CheckpointedEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];

	char* rs = rusageToStr(run_local_rusage);
	snprintf(buf0, 512, "RunLocalUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	
	rs = rusageToStr(run_remote_rusage);
	snprintf(buf0, 512, "RunRemoteUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	snprintf(buf0, 512, "SentBytes = %f", sent_bytes);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	return myad;
}

void CheckpointedEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	char* usageStr = NULL;
	if( ad->LookupString("RunLocalUsage", &usageStr) ) {
		strToRusage(usageStr, run_local_rusage);
		free(usageStr);
	}
	usageStr = NULL;
	if( ad->LookupString("RunRemoteUsage", &usageStr) ) {
		strToRusage(usageStr, run_remote_rusage);
		free(usageStr);
	}

	ad->LookupFloat("SentBytes", sent_bytes);
}

// ----- the JobEvictedEvent class
JobEvictedEvent::JobEvictedEvent()
{
	eventNumber = ULOG_JOB_EVICTED;
	checkpointed = false;

	(void)memset((void*)&run_local_rusage,0,(size_t) sizeof(run_local_rusage));
	run_remote_rusage = run_local_rusage;

	sent_bytes = recvd_bytes = 0.0;

	terminate_and_requeued = false;
	normal = false;
	return_value = -1;
	signal_number = -1;
	reason = NULL;
	core_file = NULL;
}


JobEvictedEvent::~JobEvictedEvent()
{
	delete[] reason;
	delete[] core_file;
}


void
JobEvictedEvent::setReason( const char* reason_str )
{
    delete[] reason; 
    reason = NULL; 
    if( reason_str ) { 
        reason = strnewp( reason_str ); 
        if( !reason ) { 
            EXCEPT( "ERROR: out of memory!\n" ); 
        } 
    } 
}


const char* JobEvictedEvent::
getReason( void ) const
{
	return reason;
}


void
JobEvictedEvent::setCoreFile( const char* core_name )
{
	delete[] core_file;
	core_file = NULL;
	if( core_name ) {
		core_file = strnewp( core_name );
		if( !core_file ) {
			EXCEPT( "ERROR: out of memory!\n" );  
		}
	}
}


const char*
JobEvictedEvent::getCoreFile( void )
{
	return core_file;
}


int
JobEvictedEvent::readEvent( FILE *file )
{
	int  ckpt;
	char buffer [128];

	if( (fscanf(file, "Job was evicted.") == EOF) ||
		(fscanf(file, "\n\t(%d) ", &ckpt) != 1) )
	{
		return 0;
	}
	checkpointed = (bool) ckpt;
	if( fgets(buffer, 128, file) == 0 ) {
		return 0;
	}

		/* 
		   since the old parsing code treated the integer we read as a
		   bool (only to decide between checkpointed or not), we now
		   have to parse the string we just read to figure out if this
		   was a terminate_and_requeued eviction or not.
		*/
	if( ! strncmp(buffer, "Job terminated and was requeued", 31) ) {
		terminate_and_requeued = true;
	} else {
		terminate_and_requeued = false;
	}

	if( !readRusage(file,run_remote_rusage) || !fgets(buffer,128,file) ||
		!readRusage(file,run_local_rusage) || !fgets(buffer,128,file) )
	{
		return 0;
	}

	if( !fscanf(file, "\t%f  -  Run Bytes Sent By Job\n", &sent_bytes) ||
		!fscanf(file, "\t%f  -  Run Bytes Received By Job\n",
				&recvd_bytes) )
	{
		return 1;				// backwards compatibility
	}

	if( ! terminate_and_requeued ) {
			// nothing more to read
		return 1;
	}

		// now, parse the terminate and requeue specific stuff.

	int  normal_term;
	int  got_core;

	if( fscanf(file, "\n\t(%d) ", &normal_term) != 1 ) {
		return 0;
	}
	if( normal_term ) {
		normal = true;
		if( fscanf(file, "Normal termination (return value %d)\n",
				   &return_value) !=1 ) {
			return 0;
		}
	} else {
		normal = false;
		if( fscanf(file, "Abnormal termination (signal %d)",
				   &signal_number) !=1 ) {
			return 0;
		}
		if( fscanf(file, "\n\t(%d) ", &got_core) != 1 ) {
			return 0;
		}
		if( got_core ) {
			if( fscanf(file, "Corefile in: ") == EOF ) {
				return 0;
			}
			if( !fgets(buffer, 128, file) ) {
				return 0;
			}
			chomp( buffer );
			setCoreFile( buffer );
		} else {
			if( !fgets(buffer, 128, file) ) {
				return 0;
			}
		}
	}
		// finally, see if there's a reason.  this is optional.

	// if we get a reason, fine. If we don't, we need to 
	// rewind the file position.
	fpos_t filep;
	fgetpos( file, &filep );

    char reason_buf[BUFSIZ];
    if( !fgets( reason_buf, BUFSIZ, file ) ||
		strcmp( reason_buf, "...\n" ) == 0 ) {

		fsetpos( file, &filep );
		return 1;  // not considered failure
	}

	chomp( reason_buf );
		// This is strange, sometimes we get the \t from fgets(), and
		// sometimes we don't.  Instead of trying to figure out why,
		// we just check for it here and do the right thing...
	if( reason_buf[0] == '\t' && reason_buf[1] ) {
		setReason( &reason_buf[1] );
	} else {
		setReason( reason_buf );
	}
	return 1;
}


int
JobEvictedEvent::writeEvent( FILE *file )
{
  char messagestr[512], checkpointedstr[6], terminatestr[512];
  ClassAd tmpCl1, tmpCl2;
  ClassAd *tmpClP1 = &tmpCl1, *tmpClP2 = &tmpCl2;
  MyString tmp = "";
  
  //JobAd is defined in condor_shadow.V6/log_events.C and is simply
  //defined as an external variable here
  
  strcpy(checkpointedstr, "");
  strcpy(messagestr, "");
  strcpy(terminatestr, "");
  
  
  int retval;
  
  if( fprintf(file, "Job was evicted.\n\t") < 0 ) { 
    return 0;
  }
  
  if( terminate_and_requeued ) { 
    retval = fprintf( file, "(0) Job terminated and was requeued\n\t" );
    sprintf(messagestr,  "Job evicted, terminated and was requeued");
    strcpy(checkpointedstr, "false");
  } else if( checkpointed ) {
    retval = fprintf( file, "(1) Job was checkpointed.\n\t" );
    sprintf(messagestr,  "Job evicted and was checkpointed");	
    strcpy(checkpointedstr, "true");
  } else {
    retval = fprintf( file, "(0) Job was not checkpointed.\n\t" );
    sprintf(messagestr,  "Job evicted and was not checkpointed");
    strcpy(checkpointedstr, "false");
  }
  
  if( retval < 0 ) {
    return 0;
  }
  
  if( (!writeRusage (file, run_remote_rusage)) 			||
      (fprintf (file, "  -  Run Remote Usage\n\t") < 0) 	||
      (!writeRusage (file, run_local_rusage)) 			||
      (fprintf (file, "  -  Run Local Usage\n") < 0) )
    {
      return 0;
    }
  
  if( fprintf(file, "\t%.0f  -  Run Bytes Sent By Job\n", 
	      sent_bytes) < 0 ) {
    return 0;
  }
  if( fprintf(file, "\t%.0f  -  Run Bytes Received By Job\n", 
	      recvd_bytes) < 0 ) {
    return 0;
  }
  
  if(terminate_and_requeued ) {
    if( normal ) {
      if( fprintf(file, "\t(1) Normal termination (return value %d)\n", 
		  return_value) < 0 ) {
	return 0;
      }
      sprintf(terminatestr,  " (1) Normal termination (return value %d)", return_value);
    } 
    else {
      if( fprintf(file, "\t(0) Abnormal termination (signal %d)\n",
		  signal_number) < 0 ) {
	return 0;
      }
      sprintf(terminatestr,  " (0) Abnormal termination (signal %d)", signal_number);

      if( core_file ) {
	retval = fprintf( file, "\t(1) Corefile in: %s\n", core_file );
	strcat(terminatestr, " (1) Corefile in: ");
	strcat(terminatestr, core_file);
      } 
      else {
	retval = fprintf( file, "\t(0) No core file\n" );
	strcat(terminatestr, " (0) No core file ");
      }
      if( retval < 0 ) {
	return 0;
      }
    }
    
    if( reason ) {
      if( fprintf(file, "\t%s\n", reason) < 0 ) {
	return 0;
      }
      strcat(terminatestr,  " reason: ");
      strcat(terminatestr,  reason);
    }
  
  }
  
  scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );
  
  tmp.sprintf( "endts = %d", (int)eventclock);
  tmpClP1->Insert(tmp.GetCStr());		
		
  tmp.sprintf( "endtype = %d", ULOG_JOB_EVICTED);
  tmpClP1->Insert(tmp.GetCStr());
		
  tmp.sprintf( "endmessage = \"%s%s\"", messagestr, terminatestr);
  tmpClP1->Insert(tmp.GetCStr());
		
  tmp.sprintf( "wascheckpointed = \"%s\"", checkpointedstr);
  tmpClP1->Insert(tmp.GetCStr());

  tmp.sprintf( "runbytessent = %f", sent_bytes);
  tmpClP1->Insert(tmp.GetCStr());

  tmp.sprintf( "runbytesreceived = %f", recvd_bytes);
  tmpClP1->Insert(tmp.GetCStr());

  // this inserts scheddname, cluster, proc, etc
  insertCommonIdentifiers(tmpClP2);           
	
  tmp.sprintf( "endtype = null");
  tmpClP2->Insert(tmp.GetCStr());
  
  if (FILEObj) {
	  if (FILEObj->file_updateEvent("Runs", tmpClP1, tmpClP2) == QUILL_FAILURE) {
		  dprintf(D_ALWAYS, "Logging Event 2 --- Error\n");
		  return 0; // return a error code, 0
	  }
  }

  return 1;
}

ClassAd* JobEvictedEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];
	
	snprintf(buf0, 512, "Checkpointed = %s", checkpointed ? "TRUE" : "FALSE");
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	char* rs = rusageToStr(run_local_rusage);
	snprintf(buf0, 512, "RunLocalUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	
	rs = rusageToStr(run_remote_rusage);
	snprintf(buf0, 512, "RunRemoteUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	snprintf(buf0, 512, "SentBytes = %f", sent_bytes);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	snprintf(buf0, 512, "ReceivedBytes = %f", recvd_bytes);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	snprintf(buf0, 512, "TerminatedAndRequeued = %s",
			 terminate_and_requeued ? "TRUE" : "FALSE");
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	snprintf(buf0, 512, "TerminatedNormally = %s", 
			 normal ? "TRUE" : "FALSE");
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	if( return_value >= 0 ) {
		snprintf(buf0, 512, "ReturnValue = %d", return_value);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}
	if( signal_number >= 0 ) {
		snprintf(buf0, 512, "TerminatedBySignal = %d", signal_number);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}

	if( reason ) {
		MyString buf2;
		buf2.sprintf("Reason = \"%s\"", reason);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}
	if( core_file ) {
		MyString buf3;
		buf3.sprintf("CoreFile = \"%s\"", core_file);
		if( !myad->Insert(buf3.Value()) ) return NULL;
	}
	
	return myad;
}

void JobEvictedEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	int reallybool;
	if( ad->LookupInteger("Checkpointed", reallybool) ) {
		checkpointed = reallybool ? TRUE : FALSE;
	}

	char* usageStr = NULL;
	if( ad->LookupString("RunLocalUsage", &usageStr) ) {
		strToRusage(usageStr, run_local_rusage);
		free(usageStr);
	}
	usageStr = NULL;
	if( ad->LookupString("RunRemoteUsage", &usageStr) ) {
		strToRusage(usageStr, run_remote_rusage);
		free(usageStr);
	}
	
	ad->LookupFloat("SentBytes", sent_bytes);
	ad->LookupFloat("ReceivedBytes", recvd_bytes);

	if( ad->LookupInteger("TerminatedAndRequeued", reallybool) ) {
		terminate_and_requeued = reallybool ? TRUE : FALSE;
	}
	if( ad->LookupInteger("TerminatedNormally", reallybool) ) {
		normal = reallybool ? TRUE : FALSE;
	}

	ad->LookupInteger("ReturnValue", return_value);
	ad->LookupInteger("TerminatedBySignal", signal_number);

	char* multi = NULL;
	ad->LookupString("Reason", &multi);
	if( multi ) {
		setReason(multi);
		free(multi);
		multi = NULL;
	}
	ad->LookupString("CoreFile", &multi);
	if( multi ) {
		setCoreFile(multi);
		free(multi);
		multi = NULL;
	}
}


// ----- JobAbortedEvent class
JobAbortedEvent::
JobAbortedEvent ()
{
	eventNumber = ULOG_JOB_ABORTED;
	reason = NULL;
}

JobAbortedEvent::
~JobAbortedEvent()
{
	delete[] reason;
}


void JobAbortedEvent::
setReason( const char* reason_str )
{
	delete[] reason;
	reason = NULL;
	if( reason_str ) {
		reason = strnewp( reason_str );
		if( !reason ) {
			EXCEPT( "ERROR: out of memory!\n" );
		}
	}
}


const char* JobAbortedEvent::
getReason( void ) const
{
	return reason;
}


int JobAbortedEvent::
writeEvent (FILE *file)
{

	char messagestr[512];
	ClassAd tmpCl1;
	ClassAd *tmpClP1 = &tmpCl1;
	MyString tmp = "";

	scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );

	if (reason)
		snprintf(messagestr,  512, "Job was aborted by the user: %s", reason);
	else 
		sprintf(messagestr,  "Job was aborted by the user");

	// this inserts scheddname, cluster, proc, etc
	insertCommonIdentifiers(tmpClP1);           

	tmp.sprintf( "eventtype = %d", ULOG_JOB_ABORTED);
	tmpClP1->Insert(tmp.GetCStr());
		
	tmp.sprintf( "eventtime = %d", (int)eventclock);
	tmpClP1->Insert(tmp.GetCStr());	
	
	tmp.sprintf( "description = \"%s\"", messagestr);
	tmpClP1->Insert(tmp.GetCStr());	
				
	if (FILEObj) {
		if (FILEObj->file_newEvent("Events", tmpClP1) == QUILL_FAILURE) {
			dprintf(D_ALWAYS, "Logging Event 7--- Error\n");
			return 0; // return a error code, 0
		}
	}

	if( fprintf(file, "Job was aborted by the user.\n") < 0 ) {
		return 0;
	}
	if( reason ) {
		if( fprintf(file, "\t%s\n", reason) < 0 ) {
			return 0;
		}
	}
	return 1;
}


int JobAbortedEvent::
readEvent (FILE *file)
{
	if( fscanf(file, "Job was aborted by the user.\n") == EOF ) {
		return 0;
	}
	// try to read the reason, but if its not there,
	// rewind so we don't slurp up the next event delimiter
	fpos_t filep;
	fgetpos( file, &filep );
	char reason_buf[BUFSIZ];
	if( !fgets( reason_buf, BUFSIZ, file ) ||
		   	strcmp( reason_buf, "...\n" ) == 0 ) {
		setReason( NULL );
		fsetpos( file, &filep );
		return 1;	// backwards compatibility
	}
 
	chomp( reason_buf );  // strip the newline, if it's there.
		// This is strange, sometimes we get the \t from fgets(), and
		// sometimes we don't.  Instead of trying to figure out why,
		// we just check for it here and do the right thing...
	if( reason_buf[0] == '\t' && reason_buf[1] ) {
		setReason( &reason_buf[1] );
	} else {
		setReason( reason_buf );
	}
	return 1;
}

ClassAd* JobAbortedEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	
	if( reason ) {
		MyString buf2;
		buf2.sprintf("Reason = \"%s\"", reason);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}

	return myad;
}

void JobAbortedEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	char* multi = NULL;
	ad->LookupString("Reason", &multi);
	if( multi ) {
		setReason(multi);
		free(multi);
		multi = NULL;
	}
}

// ----- TerminatedEvent baseclass
TerminatedEvent::TerminatedEvent()
{
	normal = false;
	core_file = NULL;
	returnValue = signalNumber = -1;

	(void)memset((void*)&run_local_rusage,0,(size_t)sizeof(run_local_rusage));
	run_remote_rusage=total_local_rusage=total_remote_rusage=run_local_rusage;

	sent_bytes = recvd_bytes = total_sent_bytes = total_recvd_bytes = 0.0;
}

TerminatedEvent::~TerminatedEvent()
{
	delete[] core_file;
}


void
TerminatedEvent::setCoreFile( const char* core_name )
{
	delete[] core_file;
	core_file = NULL;
	if( core_name ) {
		core_file = strnewp( core_name );
		if( !core_file ) {
            EXCEPT( "ERROR: out of memory!\n" );
		}
	}
}


const char*
TerminatedEvent::getCoreFile( void )
{
	return core_file;
}

int
TerminatedEvent::writeEvent( FILE *file, const char* header )
{
  char messagestr[512];
  ClassAd tmpCl1, tmpCl2;
  ClassAd *tmpClP1 = &tmpCl1, *tmpClP2 = &tmpCl2;
  MyString tmp = "";

  //JobAd is defined in condor_shadow.V6/log_events.C and is simply
  //defined as an external variable here
  
  strcpy(messagestr, "");
  
	int retval=0;

	if( normal ) {
		if( fprintf(file, "\t(1) Normal termination (return value %d)\n\t", 
					returnValue) < 0 ) {
			return 0;
		}
		sprintf(messagestr,  "(1) Normal termination (return value %d)", returnValue);

	} else {
		if( fprintf(file, "\t(0) Abnormal termination (signal %d)\n",
					signalNumber) < 0 ) {
			return 0;
		}

		sprintf(messagestr,  "(0) Abnormal termination (signal %d)", signalNumber);

		if( core_file ) {
			retval = fprintf( file, "\t(1) Corefile in: %s\n\t",
							  core_file );
			strcat(messagestr, " (1) Corefile in: ");
			strcat(messagestr, core_file);
		} else {
			retval = fprintf( file, "\t(0) No core file\n\t" );
			strcat(messagestr, " (0) No core file ");
		}
	}

	if ((retval < 0)										||
		(!writeRusage (file, run_remote_rusage))			||
		(fprintf (file, "  -  Run Remote Usage\n\t") < 0) 	||
		(!writeRusage (file, run_local_rusage)) 			||
		(fprintf (file, "  -  Run Local Usage\n\t") < 0)   	||
		(!writeRusage (file, total_remote_rusage))			||
		(fprintf (file, "  -  Total Remote Usage\n\t") < 0)	||
		(!writeRusage (file,  total_local_rusage))			||
		(fprintf (file, "  -  Total Local Usage\n") < 0))
		return 0;


	if (fprintf(file, "\t%.0f  -  Run Bytes Sent By %s\n", 
				sent_bytes, header) < 0 ||
		fprintf(file, "\t%.0f  -  Run Bytes Received By %s\n",
				recvd_bytes, header) < 0 ||
		fprintf(file, "\t%.0f  -  Total Bytes Sent By %s\n",
				total_sent_bytes, header) < 0 ||
		fprintf(file, "\t%.0f  -  Total Bytes Received By %s\n",
				total_recvd_bytes, header) < 0)
		return 1;				// backwards compatibility

	scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );

	tmp.sprintf( "endmessage = \"%s\"", messagestr);
	tmpClP1->Insert(tmp.GetCStr());
	
	tmp.sprintf( "runbytessent = %f", sent_bytes);
	tmpClP1->Insert(tmp.GetCStr());	
	
	tmp.sprintf( "runbytesreceived = %f", recvd_bytes);
	tmpClP1->Insert(tmp.GetCStr());	

	// this inserts scheddname, cluster, proc, etc
	insertCommonIdentifiers(tmpClP2);           
	
	tmp.sprintf( "endts = %d", (int)eventclock);
	tmpClP2->Insert(tmp.GetCStr());

	if (FILEObj) {
		if (FILEObj->file_updateEvent("Runs", tmpClP1, tmpClP2) == QUILL_FAILURE) {
			dprintf(D_ALWAYS, "Logging Event 3--- Error\n");
			return 0; // return a error code, 0
		}
	}

	return 1;
}


int
TerminatedEvent::readEvent( FILE *file, const char* header )
{
	char buffer[128];
	int  normalTerm;
	int  gotCore;
	int  retval;

	if( (retval = fscanf (file, "\n\t(%d) ", &normalTerm)) != 1 ) {
		return 0;
	}

	if( normalTerm ) {
		normal = true;
		if(fscanf(file,"Normal termination (return value %d)",&returnValue)!=1)
			return 0;
	} else {
		normal = false;
		if((fscanf(file,"Abnormal termination (signal %d)",&signalNumber)!=1)||
		   (fscanf(file,"\n\t(%d) ", &gotCore) != 1))
			return 0;

		if( gotCore ) {
			if( fscanf(file, "Corefile in: ") == EOF ) {
				return 0;
			}
			if( !fgets(buffer, 128, file) ) {
				return 0;
			}
			chomp( buffer );
			setCoreFile( buffer );
		} else {
			if (fgets (buffer, 128, file) == 0) 
				return 0;
		}
	}

		// read in rusage values
	if (!readRusage(file,run_remote_rusage) || !fgets(buffer, 128, file) ||
		!readRusage(file,run_local_rusage)   || !fgets(buffer, 128, file) ||
		!readRusage(file,total_remote_rusage)|| !fgets(buffer, 128, file) ||
		!readRusage(file,total_local_rusage) || !fgets(buffer, 128, file))
		return 0;
	
		// THIS CODE IS TOTALLY BROKEN.  Please fix me.
		// In particular: fscanf() when you don't convert anything to
		// a local variable returns 0, but we think that's failure.
	if( fscanf (file, "\t%f  -  Run Bytes Sent By ", &sent_bytes) == 0 ||
		fscanf (file, header) == 0 ||
		fscanf (file, "\n") == 0 ||
		fscanf (file, "\t%f  -  Run Bytes Received By ",
				&recvd_bytes) == 0 ||
		fscanf (file, header) == 0 || 
		fscanf (file, "\n") == 0 ||
		fscanf (file, "\t%f  -  Total Bytes Sent By ",
				&total_sent_bytes) == 0 ||
		fscanf (file, header) == 0 ||
		fscanf (file, "\n") == 0 ||
		fscanf (file, "\t%f  -  Total Bytes Received By ",
				&total_recvd_bytes) == 0 ||
		fscanf (file, header) == 0 ||
		fscanf (file, "\n") == 0 ) {
		return 1;		// backwards compatibility
	}
	return 1;
}


// ----- JobTerminatedEvent class
JobTerminatedEvent::JobTerminatedEvent() : TerminatedEvent()
{
	eventNumber = ULOG_JOB_TERMINATED;
}


JobTerminatedEvent::~JobTerminatedEvent()
{
}


int
JobTerminatedEvent::writeEvent (FILE *file)
{
  ClassAd tmpCl1, tmpCl2;
  ClassAd *tmpClP1 = &tmpCl1, *tmpClP2 = &tmpCl2;
  MyString tmp = "";

  //JobAd is defined in condor_shadow.V6/log_events.C and is simply
  //defined as an external variable here
  
  scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );

  tmp.sprintf( "endts = %d", (int)eventclock);
  tmpClP1->Insert(tmp.GetCStr());
  
  tmp.sprintf( "endtype = %d", ULOG_JOB_TERMINATED);
  tmpClP1->Insert(tmp.GetCStr());  

  // this inserts scheddname, cluster, proc, etc
  insertCommonIdentifiers(tmpClP2);           
  
  tmp.sprintf( "endtype = null");
  tmpClP2->Insert(tmp.GetCStr());

  if (FILEObj) {
	  if (FILEObj->file_updateEvent("Runs", tmpClP1, tmpClP2) == QUILL_FAILURE) {
		  dprintf(D_ALWAYS, "Logging Event 4--- Error\n");
		  return 0; // return a error code, 0
	  }
  }

  if( fprintf(file, "Job terminated.\n") < 0 ) {
	  return 0;
  }
  return TerminatedEvent::writeEvent( file, "Job" );
}


int
JobTerminatedEvent::readEvent (FILE *file)
{
	if( fscanf(file, "Job terminated.") == EOF ) {
		return 0;
	}
	return TerminatedEvent::readEvent( file, "Job" );
}

ClassAd* JobTerminatedEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];
	
	snprintf(buf0, 512, "TerminatedNormally = %s", normal ? "TRUE" : "FALSE");
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	if( returnValue >= 0 ) {
		snprintf(buf0, 512, "ReturnValue = %d", returnValue);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}
	if( signalNumber >= 0 ) {
		snprintf(buf0, 512, "TerminatedBySignal = %d", signalNumber);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}

	const char* core = getCoreFile();
	if( core ) {
		MyString buf3;
		buf3.sprintf("CoreFile = \"%s\"", core);
		if( !myad->Insert(buf3.Value()) ) return NULL;
	}

	char* rs = rusageToStr(run_local_rusage);
	snprintf(buf0, 512, "RunLocalUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	rs = rusageToStr(run_remote_rusage);
	snprintf(buf0, 512, "RunRemoteUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	rs = rusageToStr(total_local_rusage);
	snprintf(buf0, 512, "TotalLocalUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	rs = rusageToStr(total_remote_rusage);
	snprintf(buf0, 512, "TotalRemoteUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	snprintf(buf0, 512, "SentBytes = %f", sent_bytes);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	snprintf(buf0, 512, "ReceivedBytes = %f", recvd_bytes);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	snprintf(buf0, 512, "TotalSentBytes = %f", total_sent_bytes);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	snprintf(buf0, 512, "TotalReceivedBytes = %f", total_recvd_bytes);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	return myad;
}

void JobTerminatedEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	int reallybool;
	if( ad->LookupInteger("TerminatedNormally", reallybool) ) {
		normal = reallybool ? TRUE : FALSE;
	}

	ad->LookupInteger("ReturnValue", returnValue);
	ad->LookupInteger("TerminatedBySignal", signalNumber);
	
	char* multi = NULL;
	ad->LookupString("CoreFile", &multi);
	if( multi ) {
		setCoreFile(multi);
		free(multi);
		multi = NULL;
	}

	if( ad->LookupString("RunLocalUsage", &multi) ) {
		strToRusage(multi, run_local_rusage);
		free(multi);
	}
	if( ad->LookupString("RunRemoteUsage", &multi) ) {
		strToRusage(multi, run_remote_rusage);
		free(multi);
	}
	if( ad->LookupString("TotalLocalUsage", &multi) ) {
		strToRusage(multi, total_local_rusage);
		free(multi);
	}
	if( ad->LookupString("TotalRemoteUsage", &multi) ) {
		strToRusage(multi, total_remote_rusage);
		free(multi);
	}

	ad->LookupFloat("SentBytes", sent_bytes);
	ad->LookupFloat("ReceivedBytes", recvd_bytes);
	ad->LookupFloat("TotalSentBytes", total_sent_bytes);
	ad->LookupFloat("TotalReceivedBytes", total_recvd_bytes);
}

JobImageSizeEvent::
JobImageSizeEvent()
{
	eventNumber = ULOG_IMAGE_SIZE;
	size = -1;
}


JobImageSizeEvent::
~JobImageSizeEvent()
{
}


int JobImageSizeEvent::
writeEvent (FILE *file)
{
	if (fprintf (file, "Image size of job updated: %d\n", size) < 0)
		return 0;

	return 1;
}


int JobImageSizeEvent::
readEvent (FILE *file)
{
	int retval;
	if ((retval=fscanf(file,"Image size of job updated: %d", &size)) != 1)
		return 0;

	return 1;
}

ClassAd* JobImageSizeEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];

	if( size >= 0 ) {
		snprintf(buf0, 512, "Size = %d", size);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}

	return myad;
}

void JobImageSizeEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	ad->LookupInteger("Size", size);
}

ShadowExceptionEvent::
ShadowExceptionEvent ()
{
	eventNumber = ULOG_SHADOW_EXCEPTION;
	message[0] = '\0';
	sent_bytes = recvd_bytes = 0.0;
	began_execution = FALSE;
}

ShadowExceptionEvent::
~ShadowExceptionEvent ()
{
}

int ShadowExceptionEvent::
readEvent (FILE *file)
{
	if (fscanf (file, "Shadow exception!\n\t") == EOF)
		return 0;
	if (fgets(message, BUFSIZ, file) == NULL) {
		message[0] = '\0';
		return 1;				// backwards compatibility
	}

	// remove '\n' from message
	message[strlen(message)-1] = '\0';

	if (fscanf (file, "\t%f  -  Run Bytes Sent By Job\n", &sent_bytes) == 0 ||
		fscanf (file, "\t%f  -  Run Bytes Received By Job\n",
				&recvd_bytes) == 0)
		return 1;				// backwards compatibility

	return 1;
}

int ShadowExceptionEvent::
writeEvent (FILE *file)
{
	char messagestr[512];
	ClassAd tmpCl1, tmpCl2;
	ClassAd *tmpClP1 = &tmpCl1, *tmpClP2 = &tmpCl2;
	MyString tmp = "";

	scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );
	
	snprintf(messagestr, 512, "Shadow exception: %s", message);

		// remove the new line in the end if any
	if  (messagestr[strlen(messagestr)-1] == '\n')
		messagestr[strlen(messagestr)-1] = '\0';

	if (began_execution) {
		tmp.sprintf( "endts = %d", (int)eventclock);
		tmpClP1->Insert(tmp.GetCStr());		
		
		tmp.sprintf( "endtype = %d", ULOG_SHADOW_EXCEPTION);
		tmpClP1->Insert(tmp.GetCStr());
		
		tmp.sprintf( "endmessage = \"%s\"", messagestr);
		tmpClP1->Insert(tmp.GetCStr());
		
		tmp.sprintf( "runbytessent = %f", sent_bytes);
		tmpClP1->Insert(tmp.GetCStr());

		tmp.sprintf( "runbytesreceived = %f", recvd_bytes);
		tmpClP1->Insert(tmp.GetCStr());

		// this inserts scheddname, cluster, proc, etc
		insertCommonIdentifiers(tmpClP2);           

		tmp.sprintf( "endtype = null");
		tmpClP2->Insert(tmp.GetCStr());
  
		if (FILEObj) {
			if (FILEObj->file_updateEvent("Runs", tmpClP1, tmpClP2) == QUILL_FAILURE) {
				dprintf(D_ALWAYS, "Logging Event 13--- Error\n");
				return 0; // return a error code, 0
			}
		}
	} else {
		// this inserts scheddname, cluster, proc, etc
        insertCommonIdentifiers(tmpClP1);           

		tmp.sprintf( "eventtype = %d", ULOG_SHADOW_EXCEPTION);
		tmpClP1->Insert(tmp.GetCStr());

		tmp.sprintf( "eventtime = %d", (int)eventclock);
		tmpClP1->Insert(tmp.GetCStr());	
	
		tmp.sprintf( "description = \"%s\"", messagestr);
		tmpClP1->Insert(tmp.GetCStr());	
				
		if (FILEObj) {
			if (FILEObj->file_newEvent("Events", tmpClP1) == QUILL_FAILURE) {
				dprintf(D_ALWAYS, "Logging Event 14 --- Error\n");
				return 0; // return a error code, 0
			}
		}			

	}

	if (fprintf (file, "Shadow exception!\n\t") < 0)
		return 0;
	if (fprintf (file, "%s\n", message) < 0)
		return 0;

	if (fprintf (file, "\t%.0f  -  Run Bytes Sent By Job\n", sent_bytes) < 0 ||
		fprintf (file, "\t%.0f  -  Run Bytes Received By Job\n",
				 recvd_bytes) < 0)
		return 1;				// backwards compatibility
	
	return 1;
}

ClassAd* ShadowExceptionEvent::
toClassAd()
{
	bool     success = true;
	ClassAd* myad = ULogEvent::toClassAd();
	if( myad ) {
		char buf0[512];
	
		MyString buf2;
		buf2.sprintf("Message = \"%s\"", message);
		if( !myad->Insert(buf2.Value())) {
			success = false;
		}

		snprintf(buf0, 512, "SentBytes = %f", sent_bytes);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) {
			success = false;
		}
		snprintf(buf0, 512, "ReceivedBytes = %f", recvd_bytes);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) {
			success = false;
		}
	}
	if (!success) {
		delete myad;
		myad = NULL;
	}
	return myad;
}

void ShadowExceptionEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);
	
	if( !ad ) return;

	if( ad->LookupString("Message", message, BUFSIZ) ) {
		message[BUFSIZ - 1] = 0;
	}
	
	ad->LookupFloat("SentBytes", sent_bytes);
	ad->LookupFloat("ReceivedBytes", recvd_bytes);
}

JobSuspendedEvent::
JobSuspendedEvent ()
{
	eventNumber = ULOG_JOB_SUSPENDED;
}

JobSuspendedEvent::
~JobSuspendedEvent ()
{
}

int JobSuspendedEvent::
readEvent (FILE *file)
{
	if (fscanf (file, "Job was suspended.\n\t") == EOF)
		return 0;
	if (fscanf (file, "Number of processes actually suspended: %d\n",
			&num_pids) == EOF)
		return 1;				// backwards compatibility

	return 1;
}


int JobSuspendedEvent::
writeEvent (FILE *file)
{
	char messagestr[512];
	ClassAd tmpCl1;
	ClassAd *tmpClP1 = &tmpCl1;
	MyString tmp = "";

	sprintf(messagestr, "Job was suspended (Number of processes actually suspended: %d)", num_pids);
	
	scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );

	// this inserts scheddname, cluster, proc, etc
	insertCommonIdentifiers(tmpClP1);           

	tmp.sprintf( "eventtype = %d", ULOG_JOB_SUSPENDED);
	tmpClP1->Insert(tmp.GetCStr());
		
	tmp.sprintf( "eventtime = %d", (int)eventclock);
	tmpClP1->Insert(tmp.GetCStr());	
	
	tmp.sprintf( "description = \"%s\"", messagestr);
	tmpClP1->Insert(tmp.GetCStr());	
				
	if (FILEObj) {
		if (FILEObj->file_newEvent("Events", tmpClP1) == QUILL_FAILURE) {
			dprintf(D_ALWAYS, "Logging Event 8--- Error\n");
			return 0; // return a error code, 0
		}
	}

	if (fprintf (file, "Job was suspended.\n\t") < 0)
		return 0;
	if (fprintf (file, "Number of processes actually suspended: %d\n", 
			num_pids) < 0)
		return 0;

	return 1;
}

ClassAd* JobSuspendedEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];
	
	snprintf(buf0, 512, "NumberOfPIDs = %d", num_pids);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	return myad;
}

void JobSuspendedEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	ad->LookupInteger("NumberOfPIDs", num_pids);
}

JobUnsuspendedEvent::
JobUnsuspendedEvent ()
{
	eventNumber = ULOG_JOB_UNSUSPENDED;
}

JobUnsuspendedEvent::
~JobUnsuspendedEvent ()
{
}

int JobUnsuspendedEvent::
readEvent (FILE *file)
{
	if (fscanf (file, "Job was unsuspended.\n") == EOF)
		return 0;

	return 1;
}

int JobUnsuspendedEvent::
writeEvent (FILE *file)
{
	char messagestr[512];
	ClassAd tmpCl1;
	ClassAd *tmpClP1 = &tmpCl1;
	MyString tmp = "";

	sprintf(messagestr, "Job was unsuspended");
	
	scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );

	// this inserts scheddname, cluster, proc, etc
	insertCommonIdentifiers(tmpClP1);           

	tmp.sprintf( "eventtype = %d", ULOG_JOB_UNSUSPENDED);
	tmpClP1->Insert(tmp.GetCStr());
		
	tmp.sprintf( "eventtime = %d", (int)eventclock);
	tmpClP1->Insert(tmp.GetCStr());	
	
	tmp.sprintf( "description = \"%s\"", messagestr);
	tmpClP1->Insert(tmp.GetCStr());	
				
	if (FILEObj) {
 	    if (FILEObj->file_newEvent("Events", tmpClP1) == QUILL_FAILURE) {
			dprintf(D_ALWAYS, "Logging Event 9--- Error\n");
			return 0; // return a error code, 0
		}
	}

	if (fprintf (file, "Job was unsuspended.\n") < 0)
		return 0;

	return 1;
}

ClassAd* JobUnsuspendedEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	
	return myad;
}

void JobUnsuspendedEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);
}

JobHeldEvent::JobHeldEvent ()
{
	eventNumber = ULOG_JOB_HELD;
	reason = NULL;
	code = 0;
	subcode = 0;
}


JobHeldEvent::~JobHeldEvent ()
{
	delete[] reason;
}


void
JobHeldEvent::setReason( const char* reason_str )
{
    delete[] reason; 
    reason = NULL; 
    if( reason_str ) { 
        reason = strnewp( reason_str ); 
        if( !reason ) { 
            EXCEPT( "ERROR: out of memory!\n" ); 
        } 
    } 
}

void
JobHeldEvent::setReasonCode(const int val)
{
	code = val;
}

void
JobHeldEvent::setReasonSubCode(const int val)
{
	subcode = val;
}


const char* JobHeldEvent::
getReason( void ) const
{
	return reason;
}

int JobHeldEvent::
getReasonCode( void ) const
{
	return code;
}

int JobHeldEvent::
getReasonSubCode( void ) const
{
	return subcode;
}

int
JobHeldEvent::readEvent( FILE *file )
{
	if( fscanf(file, "Job was held.\n") == EOF ) { 
		return 0;
	}
	// try to read the reason, but if its not there,
	// rewind so we don't slurp up the next event delimiter
	fpos_t filep;
	fgetpos( file, &filep );
	char reason_buf[BUFSIZ];
	if( !fgets( reason_buf, BUFSIZ, file ) ||
		   	strcmp( reason_buf, "...\n" ) == 0 ) {
		setReason( NULL );
		fsetpos( file, &filep );
		return 1;	// backwards compatibility
	}


	chomp( reason_buf );  // strip the newline
		// This is strange, sometimes we get the \t from fgets(), and
		// sometimes we don't.  Instead of trying to figure out why,
		// we just check for it here and do the right thing...
	if( reason_buf[0] == '\t' && reason_buf[1] ) {
		reason = strnewp( &reason_buf[1] );
	} else {
		reason = strnewp( reason_buf );
	}

	// read the code and subcodes, but if not there, rewind
	// for backwards compatibility.
	fgetpos( file, &filep );
	int incode = 0;
	int insubcode = 0;
	int fsf_ret = fscanf(file, "\tCode %d Subcode %d\n", &incode,&insubcode);
	if ( fsf_ret != 2 ) {
		code = 0;
		subcode = 0;
		fsetpos( file, &filep );
		return 1;	// backwards compatibility
	}
	code = incode;
	subcode = insubcode;

	return 1;
}


int
JobHeldEvent::writeEvent( FILE *file )
{
	char messagestr[512];
	ClassAd tmpCl1;
	ClassAd *tmpClP1 = &tmpCl1;
	MyString tmp = "";

	if (reason)
		snprintf(messagestr, 512, "Job was held: %s", reason);
	else
		sprintf(messagestr, "Job was held: reason unspecified");

	scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );

	// this inserts scheddname, cluster, proc, etc
	insertCommonIdentifiers(tmpClP1);           

	tmp.sprintf( "eventtype = %d", ULOG_JOB_HELD);
	tmpClP1->Insert(tmp.GetCStr());
		
	tmp.sprintf( "eventtime = %d", (int)eventclock);
	tmpClP1->Insert(tmp.GetCStr());	
	
	tmp.sprintf( "description = \"%s\"", messagestr);
	tmpClP1->Insert(tmp.GetCStr());	
				
	if (FILEObj) {
		if (FILEObj->file_newEvent("Events", tmpClP1) == QUILL_FAILURE) {
			dprintf(D_ALWAYS, "Logging Event 10--- Error\n");
			return 0; // return a error code, 0
		}
	}

	if( fprintf(file, "Job was held.\n") < 0 ) {
		return 0;
	}
	if( reason ) {
		if( fprintf(file, "\t%s\n", reason) < 0 ) {
			return 0;
		} 
	} else {
		if( fprintf(file, "\tReason unspecified\n") < 0 ) {
			return 0;
		}
	}

	// write the codes
	if( fprintf(file, "\tCode %d Subcode %d\n", code,subcode) < 0 ) {
		return 0;
	}

	return 1;
}

ClassAd* JobHeldEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	
	const char* hold_reason = getReason();
	MyString buf2;
	if ( hold_reason ) {
		buf2.sprintf("%s = \"%s\"", ATTR_HOLD_REASON,hold_reason);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}
	buf2.sprintf("%s = %d",ATTR_HOLD_REASON_CODE,code);
	if( !myad->Insert(buf2.Value()) ) return NULL;
	buf2.sprintf("%s = %d",ATTR_HOLD_REASON_SUBCODE,code);
	if( !myad->Insert(buf2.Value()) ) return NULL;

	return myad;
}

void JobHeldEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	char* multi = NULL;
	int incode = 0;
	int insubcode = 0;
	ad->LookupString(ATTR_HOLD_REASON, &multi);
	if( multi ) {
		setReason(multi);
		free(multi);
		multi = NULL;
	}
	ad->LookupInteger(ATTR_HOLD_REASON_CODE, incode);
	setReasonCode(incode);
	ad->LookupInteger(ATTR_HOLD_REASON_SUBCODE, insubcode);
	setReasonSubCode(insubcode);
}

JobReleasedEvent::JobReleasedEvent()
{
	eventNumber = ULOG_JOB_RELEASED;
	reason = NULL;
}


JobReleasedEvent::~JobReleasedEvent()
{
	delete[] reason;
}


void
JobReleasedEvent::setReason( const char* reason_str )
{
    delete[] reason; 
    reason = NULL; 
    if( reason_str ) { 
        reason = strnewp( reason_str ); 
        if( !reason ) { 
            EXCEPT( "ERROR: out of memory!\n" ); 
        } 
    } 
}


const char* JobReleasedEvent::
getReason( void ) const
{
	return reason;
}


int
JobReleasedEvent::readEvent( FILE *file )
{
	if( fscanf(file, "Job was released.\n") == EOF ) { 
		return 0;
	}
	// try to read the reason, but if its not there,
	// rewind so we don't slurp up the next event delimiter
	fpos_t filep;
	fgetpos( file, &filep );
	char reason_buf[BUFSIZ];
	if( !fgets( reason_buf, BUFSIZ, file ) ||
		   	strcmp( reason_buf, "...\n" ) == 0 ) {
		setReason( NULL );
		fsetpos( file, &filep );
		return 1;	// backwards compatibility
	}

	chomp( reason_buf );  // strip the newline
		// This is strange, sometimes we get the \t from fgets(), and
		// sometimes we don't.  Instead of trying to figure out why,
		// we just check for it here and do the right thing...
	if( reason_buf[0] == '\t' && reason_buf[1] ) {
		reason = strnewp( &reason_buf[1] );
	} else {
		reason = strnewp( reason_buf );
	}
	return 1;
}


int
JobReleasedEvent::writeEvent( FILE *file )
{
	char messagestr[512];
	ClassAd tmpCl1;
	ClassAd *tmpClP1 = &tmpCl1;
	MyString tmp = "";

	if (reason)
		snprintf(messagestr, 512, "Job was released: %s", reason);
	else
		sprintf(messagestr, "Job was released: reason unspecified");

	scheddname = getenv( EnvGetName( ENV_SCHEDD_NAME ) );

	// this inserts scheddname, cluster, proc, etc
	insertCommonIdentifiers(tmpClP1);           

	tmp.sprintf( "eventtype = %d", ULOG_JOB_RELEASED);
	tmpClP1->Insert(tmp.GetCStr());
		
	tmp.sprintf( "eventtime = %d", (int)eventclock);
	tmpClP1->Insert(tmp.GetCStr());	
	
	tmp.sprintf( "description = \"%s\"", messagestr);
	tmpClP1->Insert(tmp.GetCStr());	
				
	if (FILEObj) {
		if (FILEObj->file_newEvent("Events", tmpClP1) == QUILL_FAILURE) {
			dprintf(D_ALWAYS, "Logging Event 11--- Error\n");
			return 0; // return a error code, 0
		}
	}

	if( fprintf(file, "Job was released.\n") < 0 ) {
		return 0;
	}
	if( reason ) {
		if( fprintf(file, "\t%s\n", reason) < 0 ) {
			return 0;
		} else {
			return 1;
		}
	} 
		// do we want to do anything else if there's no reason?
		// should we fail?  EXCEPT()?  
	return 1;
}

ClassAd* JobReleasedEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	
	const char* release_reason = getReason();
	if( release_reason ) {
		MyString buf2;
		buf2.sprintf("Reason = \"%s\"", release_reason);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}

	return myad;
}

void JobReleasedEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	char* multi = NULL;
	ad->LookupString("Reason", &multi);
	if( multi ) {
		setReason(multi);
		free(multi);
		multi = NULL;
	}
}

static const int seconds = 1;
static const int minutes = 60 * seconds;
static const int hours = 60 * minutes;
static const int days = 24 * hours;

int ULogEvent::
writeRusage (FILE *file, rusage &usage)
{
	int usr_secs = usage.ru_utime.tv_sec;
	int sys_secs = usage.ru_stime.tv_sec;

	int usr_days, usr_hours, usr_minutes;
	int sys_days, sys_hours, sys_minutes;

	usr_days = usr_secs/days;  			usr_secs %= days;
	usr_hours = usr_secs/hours;			usr_secs %= hours;
	usr_minutes = usr_secs/minutes;		usr_secs %= minutes;
 	
	sys_days = sys_secs/days;  			sys_secs %= days;
	sys_hours = sys_secs/hours;			sys_secs %= hours;
	sys_minutes = sys_secs/minutes;		sys_secs %= minutes;
 	
	int retval;
	retval = fprintf (file, "\tUsr %d %02d:%02d:%02d, Sys %d %02d:%02d:%02d",
					  usr_days, usr_hours, usr_minutes, usr_secs,
					  sys_days, sys_hours, sys_minutes, sys_secs);

	return (retval > 0);
}


int ULogEvent::
readRusage (FILE *file, rusage &usage)
{
	int usr_secs, usr_minutes, usr_hours, usr_days;
	int sys_secs, sys_minutes, sys_hours, sys_days;
	int retval;

	retval = fscanf (file, "\tUsr %d %d:%d:%d, Sys %d %d:%d:%d",
					  &usr_days, &usr_hours, &usr_minutes, &usr_secs,
					  &sys_days, &sys_hours, &sys_minutes, &sys_secs);

	if (retval < 8)
	{
		return 0;
	}

	usage.ru_utime.tv_sec = usr_secs + usr_minutes*minutes + usr_hours*hours +
		usr_days*days;

	usage.ru_stime.tv_sec = sys_secs + sys_minutes*minutes + sys_hours*hours +
		sys_days*days;

	return (1);
}

char* ULogEvent::
rusageToStr (rusage usage)
{
	char* result = (char*) malloc(128);

	int usr_secs = usage.ru_utime.tv_sec;
	int sys_secs = usage.ru_stime.tv_sec;

	int usr_days, usr_hours, usr_minutes;
	int sys_days, sys_hours, sys_minutes;

	usr_days = usr_secs/days;  			usr_secs %= days;
	usr_hours = usr_secs/hours;			usr_secs %= hours;
	usr_minutes = usr_secs/minutes;		usr_secs %= minutes;
 	
	sys_days = sys_secs/days;  			sys_secs %= days;
	sys_hours = sys_secs/hours;			sys_secs %= hours;
	sys_minutes = sys_secs/minutes;		sys_secs %= minutes;
 	
	sprintf(result, "Usr %d %02d:%02d:%02d, Sys %d %02d:%02d:%02d",
			usr_days, usr_hours, usr_minutes, usr_secs,
			sys_days, sys_hours, sys_minutes, sys_secs);

	return result;
}

int ULogEvent::
strToRusage (char* rusageStr, rusage & usage)
{
	int usr_secs, usr_minutes, usr_hours, usr_days;
	int sys_secs, sys_minutes, sys_hours, sys_days;
	int retval;

	retval = sscanf (rusageStr, "\tUsr %d %d:%d:%d, Sys %d %d:%d:%d",
					 &usr_days, &usr_hours, &usr_minutes, &usr_secs,
					 &sys_days, &sys_hours, &sys_minutes, &sys_secs);

	if (retval < 8)
	{
		return 0;
	}

	usage.ru_utime.tv_sec = usr_secs + usr_minutes*minutes + usr_hours*hours +
		usr_days*days;

	usage.ru_stime.tv_sec = sys_secs + sys_minutes*minutes + sys_hours*hours +
		sys_days*days;

	return (1);
}

// ----- the NodeExecuteEvent class
NodeExecuteEvent::NodeExecuteEvent()
{	
	executeHost [0] = '\0';
	eventNumber = ULOG_NODE_EXECUTE;
}


NodeExecuteEvent::~NodeExecuteEvent()
{
}


int
NodeExecuteEvent::writeEvent (FILE *file)
{	
	return( fprintf(file, "Node %d executing on host: %s\n",
					node, executeHost) >= 0 );
}


int
NodeExecuteEvent::readEvent (FILE *file)
{
	return( fscanf(file, "Node %d executing on host: %s", 
				   &node, executeHost) != EOF );
}

ClassAd* NodeExecuteEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];
	
	snprintf(buf0, 512, "ExecuteHost = \"%s\"", executeHost);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	snprintf(buf0, 512, "Node = %d", node);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	return myad;
}

void NodeExecuteEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	if( ad->LookupString("ExecuteHost", executeHost, 128) ) {
		executeHost[127] = 0;
	}

	ad->LookupInteger("Node", node);
}

// ----- NodeTerminatedEvent class
NodeTerminatedEvent::NodeTerminatedEvent() : TerminatedEvent()
{
	eventNumber = ULOG_NODE_TERMINATED;
	node = -1;
}


NodeTerminatedEvent::
~NodeTerminatedEvent()
{
}


int
NodeTerminatedEvent::writeEvent( FILE *file )
{
	if( fprintf(file, "Node %d terminated.\n", node) < 0 ) {
		return 0;
	}
	return TerminatedEvent::writeEvent( file, "Node" );
}


int
NodeTerminatedEvent::readEvent( FILE *file )
{
	if( fscanf(file, "Node %d terminated.", &node) == EOF ) {
		return 0;
	}
	return TerminatedEvent::readEvent( file, "Node" );
}

ClassAd* NodeTerminatedEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];
	
	snprintf(buf0, 512, "TerminatedNormally = %s", normal ? "TRUE" : "FALSE");
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	snprintf(buf0, 512, "ReturnValue = %d", returnValue);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	snprintf(buf0, 512, "TerminatedBySignal = %d", signalNumber);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	const char* core = getCoreFile();
	if( core ) {
		MyString buf3;
		buf3.sprintf("CoreFile = \"%s\"", core);
		if( !myad->Insert(buf3.Value()) ) return NULL;
	}

	char* rs = rusageToStr(run_local_rusage);
	snprintf(buf0, 512, "RunLocalUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	rs = rusageToStr(run_remote_rusage);
	snprintf(buf0, 512, "RunRemoteUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	rs = rusageToStr(total_local_rusage);
	snprintf(buf0, 512, "TotalLocalUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	rs = rusageToStr(total_remote_rusage);
	snprintf(buf0, 512, "TotalRemoteUsage = \"%s\"", rs);
	free(rs);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	snprintf(buf0, 512, "SentBytes = %f", sent_bytes);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	snprintf(buf0, 512, "ReceivedBytes = %f", recvd_bytes);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	snprintf(buf0, 512, "TotalSentBytes = %f", total_sent_bytes);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	snprintf(buf0, 512, "TotalReceivedBytes = %f", total_recvd_bytes);
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;

	if( node >= 0 ) {
		snprintf(buf0, 512, "Node = %d", node);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}
	
	return myad;
}

void NodeTerminatedEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);
	
	if( !ad ) return;

	int reallybool;
	if( ad->LookupInteger("TerminatedNormally", reallybool) ) {
		normal = reallybool ? TRUE : FALSE;
	}

	ad->LookupInteger("ReturnValue", returnValue);
	ad->LookupInteger("TerminatedBySignal", signalNumber);
	
	char* multi = NULL;
	ad->LookupString("CoreFile", &multi);
	if( multi ) {
		setCoreFile(multi);
		free(multi);
		multi = NULL;
	}

	if( ad->LookupString("RunLocalUsage", &multi) ) {
		strToRusage(multi, run_local_rusage);
		free(multi);
	}
	if( ad->LookupString("RunRemoteUsage", &multi) ) {
		strToRusage(multi, run_remote_rusage);
		free(multi);
	}
	if( ad->LookupString("TotalLocalUsage", &multi) ) {
		strToRusage(multi, total_local_rusage);
		free(multi);
	}
	if( ad->LookupString("TotalRemoteUsage", &multi) ) {
		strToRusage(multi, total_remote_rusage);
		free(multi);
	}

	ad->LookupFloat("SentBytes", sent_bytes);
	ad->LookupFloat("ReceivedBytes", recvd_bytes);
	ad->LookupFloat("TotalSentBytes", total_sent_bytes);
	ad->LookupFloat("TotalReceivedBytes", total_recvd_bytes);

	ad->LookupInteger("Node", node);
}

// ----- PostScriptTerminatedEvent class

PostScriptTerminatedEvent::
PostScriptTerminatedEvent() :
	dagNodeNameLabel ("DAG Node: "),
	dagNodeNameAttr ("DAGNodeName")
{
	eventNumber = ULOG_POST_SCRIPT_TERMINATED;
	normal = false;
	returnValue = -1;
	signalNumber = -1;
	dagNodeName = NULL;
}


PostScriptTerminatedEvent::
~PostScriptTerminatedEvent()
{
	if( dagNodeName ) {
		delete[] dagNodeName;
	}
}


int PostScriptTerminatedEvent::
writeEvent( FILE* file )
{
    if( fprintf( file, "POST Script terminated.\n" ) < 0 ) {
        return 0;
    }

    if( normal ) {
        if( fprintf( file, "\t(1) Normal termination (return value %d)\n", 
					 returnValue ) < 0 ) {
            return 0;
        }
    } else {
        if( fprintf( file, "\t(0) Abnormal termination (signal %d)\n",
					 signalNumber ) < 0 ) {
            return 0;
        }
    }

    if( dagNodeName ) {
        if( fprintf( file, "    %s%.8191s\n",
					 dagNodeNameLabel, dagNodeName ) < 0 ) {
            return 0;
        }
    }

    return 1;
}


int PostScriptTerminatedEvent::
readEvent( FILE* file )
{
	int tmp;
	char buf[8192];
	buf[0] = '\0';

		// first clear any existing DAG node name
	if( dagNodeName ) {
		delete[] dagNodeName;
	}
    dagNodeName = NULL;
	
	if( fscanf( file, "POST Script terminated.\n\t(%d) ", &tmp ) != 1 ) {
		return 0;
	}
	if( tmp == 1 ) {
		normal = true;
	} else {
		normal = false;
	}
    if( normal ) {
        if( fscanf( file, "Normal termination (return value %d)\n",
					&returnValue ) != 1 ) {
            return 0;
		}
    } else {
        if( fscanf( file, "Abnormal termination (signal %d)\n",
					&signalNumber ) != 1 ) {
            return 0;
		}
    }

	// see if the next line contains an optional DAG node name string,
	// and, if not, rewind, because that means we slurped in the next
	// event delimiter looking for it...
 
	fpos_t filep;
	fgetpos( file, &filep );
     
	if( !fgets( buf, 8192, file ) || strcmp( buf, "...\n" ) == 0 ) {
		fsetpos( file, &filep );
		return 1;
	}

	// remove trailing newline
	buf[ strlen( buf ) - 1 ] = '\0';

		// skip "DAG Node: " label to find start of actual node name
	int label_len = strlen( dagNodeNameLabel );
	dagNodeName = strnewp( buf + label_len );

    return 1;
}

ClassAd* PostScriptTerminatedEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	char buf0[512];
	
	snprintf(buf0, 512, "TerminatedNormally = %s", normal ? "TRUE" : "FALSE");
	buf0[511] = 0;
	if( !myad->Insert(buf0) ) return NULL;
	if( returnValue >= 0 ) {
		snprintf(buf0, 512, "ReturnValue = %d", returnValue);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}
	if( signalNumber >= 0 ) {
		snprintf(buf0, 512, "TerminatedBySignal = %d", signalNumber);
		buf0[511] = 0;
		if( !myad->Insert(buf0) ) return NULL;
	}
	if( dagNodeName && dagNodeName[0] ) {
		MyString buf1;
		buf1.sprintf( "%s = \"%s\"", dagNodeNameAttr, dagNodeName );
		if( !myad->Insert( buf1.Value() ) ) {
			return NULL;
		}
	}

	return myad;
}

void PostScriptTerminatedEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);
	
	if( !ad ) return;

	int reallybool;
	if( ad->LookupInteger("TerminatedNormally", reallybool) ) {
		normal = reallybool ? TRUE : FALSE;
	}

	ad->LookupInteger("ReturnValue", returnValue);
	ad->LookupInteger("TerminatedBySignal", signalNumber);

	if( dagNodeName ) {
		delete[] dagNodeName;
		dagNodeName = NULL;
	}
	char* mallocstr = NULL;
	ad->LookupString( dagNodeNameAttr, &mallocstr );
	if( mallocstr ) {
		dagNodeName = strnewp( mallocstr );
		free( mallocstr );
		mallocstr = NULL;
	}
}


// ----- JobDisconnectedEvent class

JobDisconnectedEvent::JobDisconnectedEvent()
{
	eventNumber = ULOG_JOB_DISCONNECTED;
	startd_addr = NULL;
	startd_name = NULL;
	disconnect_reason = NULL;
	no_reconnect_reason = NULL;
	can_reconnect = true;
}


JobDisconnectedEvent::~JobDisconnectedEvent()
{
	if( startd_addr ) {
		delete [] startd_addr;
	}
	if( startd_name ) {
		delete [] startd_name;
	}
	if( disconnect_reason ) {
		delete [] disconnect_reason;
	}
	if( no_reconnect_reason ) {
		delete [] no_reconnect_reason;
	}
}


void
JobDisconnectedEvent::setStartdAddr( const char* startd )
{
	if( startd_addr ) {
		delete[] startd_addr;
		startd_addr = NULL;
	}
	if( startd ) {
		startd_addr = strnewp( startd );
		if( !startd_addr ) {
			EXCEPT( "ERROR: out of memory!\n" );
		}
	}
}


void
JobDisconnectedEvent::setStartdName( const char* name )
{
	if( startd_name ) {
		delete[] startd_name;
		startd_name = NULL;
	}
	if( name ) {
		startd_name = strnewp( name );
		if( !startd_name ) {
			EXCEPT( "ERROR: out of memory!\n" );
		}
	}
}


void
JobDisconnectedEvent::setDisconnectReason( const char* reason_str )
{
	if( disconnect_reason ) {
		delete [] disconnect_reason;
		disconnect_reason = NULL;
	}
	if( reason_str ) {
		disconnect_reason = strnewp( reason_str );
		if( !disconnect_reason ) {
			EXCEPT( "ERROR: out of memory!\n" );
		}
	}
}


void
JobDisconnectedEvent::setNoReconnectReason( const char* reason_str )
{
	if( no_reconnect_reason ) {
		delete [] no_reconnect_reason;
		no_reconnect_reason = NULL;
	}
	if( reason_str ) {
		no_reconnect_reason = strnewp( reason_str );
		if( !no_reconnect_reason ) {
			EXCEPT( "ERROR: out of memory!\n" );
		}
		can_reconnect = false;
	}
}


int
JobDisconnectedEvent::writeEvent( FILE *file )
{
	if( ! disconnect_reason ) {
		EXCEPT( "JobDisconnectedEvent::writeEvent() called without "
				"disconnect_reason" );
	}
	if( ! startd_addr ) {
		EXCEPT( "JobDisconnectedEvent::writeEvent() called without "
				"startd_addr" );
	}
	if( ! startd_name ) {
		EXCEPT( "JobDisconnectedEvent::writeEvent() called without "
				"startd_name" );
	}
	if( ! can_reconnect && ! no_reconnect_reason ) {
		EXCEPT( "impossible: JobDisconnectedEvent::writeEvent() called "
				"without no_reconnect_reason when can_reconnect is FALSE" );
	}

	if( fprintf(file, "Job disconnected, %s reconnect\n", 
				can_reconnect ? "attempting to" : "can not") < 0 ) { 
		return 0;
	}
	if( fprintf(file, "    %.8191s\n", disconnect_reason) < 0 ) {
		return 0;
	}
	if( fprintf(file, "    %s reconnect to %s %s\n", 
				can_reconnect ? "Trying to" : "Can not",
				startd_name, startd_addr) < 0 ) {
		return 0;
	}
	if( no_reconnect_reason ) {
		if( fprintf(file, "    %.8191s\n", no_reconnect_reason) < 0 ) {
			return 0;
		}
		if( fprintf(file, "    Rescheduling job\n") < 0 ) {
			return 0;
		}
	}
	return( 1 );
}


int
JobDisconnectedEvent::readEvent( FILE *file )
{
	MyString line;
	if(line.readLine(file) && line.replaceString("Job disconnected, ", "")) {
		line.chomp();
		if( line == "attempting to reconnect" ) {
			can_reconnect = true;
		} else if( line == "can not reconnect" ) {
			can_reconnect = false;
		} else {
			return 0;
		}
	} else {
		return 0;
	}

	if( line.readLine(file) && line[0] == ' ' && line[1] == ' ' 
		&& line[2] == ' ' && line[3] == ' ' && line[4] )
	{
		line.chomp();
		setDisconnectReason( &line[4] );
	} else {
		return 0;
	}

	if( ! line.readLine(file) ) {
		return 0;
	}
	line.chomp();
	if( line.replaceString("    Trying to reconnect to ", "") ) {
		int i = line.FindChar( ' ' );
		if( i > 0 ) {
			line.setChar( i, '\0' );
			setStartdName( line.Value() );
			setStartdAddr( &line[i+1] );
		} else {
			return 0;
		}
	} else if( line.replaceString("    Can not reconnect to ", "") ) {
		if( can_reconnect ) {
			return 0;
		}
		int i = line.FindChar( ' ' );
		if( i > 0 ) {
			line.setChar( i, '\0' );
			setStartdName( line.Value() );
			setStartdAddr( &line[i+1] );
		} else {
			return 0;
		}
		if( line.readLine(file) && line[0] == ' ' && line[1] == ' ' 
			&& line[2] == ' ' && line[3] == ' ' && line[4] )
		{
			line.chomp();
			setNoReconnectReason( &line[4] );
		} else {
			return 0;
		}
	} else {
		return 0;
	}

	return 1;
}


ClassAd*
JobDisconnectedEvent::toClassAd( void )
{
	if( ! disconnect_reason ) {
		EXCEPT( "JobDisconnectedEvent::toClassAd() called without"
				"disconnect_reason" );
	}
	if( ! startd_addr ) {
		EXCEPT( "JobDisconnectedEvent::toClassAd() called without "
				"startd_addr" );
	}
	if( ! startd_name ) {
		EXCEPT( "JobDisconnectedEvent::toClassAd() called without "
				"startd_name" );
	}
	if( ! can_reconnect && ! no_reconnect_reason ) {
		EXCEPT( "JobDisconnectedEvent::toClassAd() called without "
				"no_reconnect_reason when can_reconnect is FALSE" );
	}


	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) {
		return NULL;
	}
	
	MyString line;
	line.sprintf( "StartdAddr = \"%s\"", startd_addr );
	if( !myad->Insert(line.Value()) ) {
		return NULL;
	}
	line.sprintf( "StartdName = \"%s\"", startd_name );
	if( !myad->Insert(line.Value()) ) {
		return NULL;
	}
	line.sprintf( "DisconnectReason = \"%s\"", disconnect_reason );
	if( !myad->Insert(line.Value()) ) {
		return NULL;
	}

	line = "EventDescription = \"Job disconnected, ";
	if( can_reconnect ) {
		line += "attempting to reconnect\"";
	} else {
		line += "can not reconnect, rescheduling job\"";
	}
	if( !myad->Insert(line.Value()) ) {
		return NULL;
	}

	if( no_reconnect_reason ) { 
		line.sprintf( "NoReconnectReason = \"%s\"", no_reconnect_reason );
		if( !myad->Insert(line.Value()) ) {
			return NULL;
		}
	}

	return myad;
}


void
JobDisconnectedEvent::initFromClassAd( ClassAd* ad )
{
	ULogEvent::initFromClassAd(ad);
	
	if( !ad ) {
		return;
	}

	// this fanagling is to ensure we don't malloc a pointer then delete it
	char* mallocstr = NULL;
	ad->LookupString( "DisconnectReason", &mallocstr );
	if( mallocstr ) {
		setDisconnectReason( mallocstr );
		free( mallocstr );
		mallocstr = NULL;
	}

	ad->LookupString( "NoReconnectReason", &mallocstr );
	if( mallocstr ) {
		setNoReconnectReason( mallocstr );
		free( mallocstr );
		mallocstr = NULL;
	}

	ad->LookupString( "StartdAddr", &mallocstr );
	if( mallocstr ) {
		setStartdAddr( mallocstr );
		free( mallocstr );
		mallocstr = NULL;
	}

	ad->LookupString( "StartdName", &mallocstr );
	if( mallocstr ) {
		setStartdName( mallocstr );
		free( mallocstr );
		mallocstr = NULL;
	}
}


// ----- JobReconnectedEvent class

JobReconnectedEvent::JobReconnectedEvent()
{
	eventNumber = ULOG_JOB_RECONNECTED;
	startd_addr = NULL;
	startd_name = NULL;
	starter_addr = NULL;
}


JobReconnectedEvent::~JobReconnectedEvent()
{
	if( startd_addr ) {
		delete [] startd_addr;
	}
	if( startd_name ) {
		delete [] startd_name;
	}
	if( starter_addr ) {
		delete [] starter_addr;
	}
}


void
JobReconnectedEvent::setStartdAddr( const char* startd )
{
	if( startd_addr ) {
		delete[] startd_addr;
		startd_addr = NULL;
	}
	if( startd ) {
		startd_addr = strnewp( startd );
		if( !startd_addr ) {
			EXCEPT( "ERROR: out of memory!\n" );
		}
	}
}


void
JobReconnectedEvent::setStartdName( const char* name )
{
	if( startd_name ) {
		delete[] startd_name;
		startd_name = NULL;
	}
	if( name ) {
		startd_name = strnewp( name );
		if( !startd_name ) {
			EXCEPT( "ERROR: out of memory!\n" );
		}
	}
}


void
JobReconnectedEvent::setStarterAddr( const char* starter )
{
	if( starter_addr ) {
		delete[] starter_addr;
		starter_addr = NULL;
	}
	if( starter ) {
		starter_addr = strnewp( starter );
		if( !starter_addr ) {
			EXCEPT( "ERROR: out of memory!\n" );
		}
	}
}


int
JobReconnectedEvent::writeEvent( FILE *file )
{
	if( ! startd_addr ) {
		EXCEPT( "JobReconnectedEvent::writeEvent() called without "
				"startd_addr" );
	}
	if( ! startd_name ) {
		EXCEPT( "JobReconnectedEvent::writeEvent() called without "
				"startd_name" );
	}
	if( ! starter_addr ) {
		EXCEPT( "JobReconnectedEvent::writeEvent() called without "
				"starter_addr" );
	}

	if( fprintf(file, "Job reconnected to %s\n", startd_name) < 0 ) { 
		return 0;
	}
	if( fprintf(file, "    startd address: %s\n", startd_addr) < 0 ) { 
		return 0;
	}
	if( fprintf(file, "    starter address: %s\n", starter_addr) < 0 ) { 
		return 0;
	}
	return( 1 );
}


int
JobReconnectedEvent::readEvent( FILE *file )
{
	MyString line;

	if( line.readLine(file) && 
		line.replaceString("Job reconnected to ", "") )
	{
		line.chomp();
		setStartdName( line.Value() );
	} else {
		return 0;
	}

	if( line.readLine(file) && 
		line.replaceString( "    startd address: ", "" ) )
	{
		line.chomp();
		setStartdAddr( line.Value() );
	} else {
		return 0;
	}

	if( line.readLine(file) && 
		line.replaceString( "    starter address: ", "" ) )
	{
		line.chomp();
		setStarterAddr( line.Value() );
	} else {
		return 0;
	}

	return 1;
}


ClassAd*
JobReconnectedEvent::toClassAd( void )
{
	if( ! startd_addr ) {
		EXCEPT( "JobReconnectedEvent::toClassAd() called without "
				"startd_addr" );
	}
	if( ! startd_name ) {
		EXCEPT( "JobReconnectedEvent::toClassAd() called without "
				"startd_name" );
	}
	if( ! starter_addr ) {
		EXCEPT( "JobReconnectedEvent::toClassAd() called without "
				"starter_addr" );
	}

	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) {
		return NULL;
	}

	MyString line;
	line.sprintf( "StartdAddr = \"%s\"", startd_addr );
	if( !myad->Insert(line.Value()) ) {
		return NULL;
	}
	line.sprintf( "StartdName = \"%s\"", startd_name );
	if( !myad->Insert(line.Value()) ) {
		return NULL;
	}
	line.sprintf( "StarterAddr = \"%s\"", starter_addr );
	if( !myad->Insert(line.Value()) ) {
		return NULL;
	}
	if( !myad->Insert("EventDescription = \"Job reconnected\"") ) {
		return NULL;
	}
	return myad;
}


void
JobReconnectedEvent::initFromClassAd( ClassAd* ad )
{
	ULogEvent::initFromClassAd(ad);
	
	if( !ad ) {
		return;
	}

	// this fanagling is to ensure we don't malloc a pointer then delete it
	char* mallocstr = NULL;
	ad->LookupString( "StartdAddr", &mallocstr );
	if( mallocstr ) {
		if( startd_addr ) {
			delete [] startd_addr;
		}
		startd_addr = strnewp( mallocstr );
		free( mallocstr );
		mallocstr = NULL;
	}

	ad->LookupString( "StartdName", &mallocstr );
	if( mallocstr ) {
		if( startd_name ) {
			delete [] startd_name;
		}
		startd_name = strnewp( mallocstr );
		free( mallocstr );
		mallocstr = NULL;
	}

	ad->LookupString( "StarterAddr", &mallocstr );
	if( mallocstr ) {
		if( starter_addr ) {
			delete [] starter_addr;
		}
		starter_addr = strnewp( mallocstr );
		free( mallocstr );
		mallocstr = NULL;
	}
}


// ----- JobReconnectFailedEvent class

JobReconnectFailedEvent::JobReconnectFailedEvent()
{
	eventNumber = ULOG_JOB_RECONNECT_FAILED;
	reason = NULL;
	startd_name = NULL;
}


JobReconnectFailedEvent::~JobReconnectFailedEvent()
{
	if( reason ) {
		delete [] reason;
	}
	if( startd_name ) {
		delete [] startd_name;
	}
}


void
JobReconnectFailedEvent::setReason( const char* reason_str )
{
	if( reason ) {
		delete [] reason;
		reason = NULL;
	}
	if( reason_str ) {
		reason = strnewp( reason_str );
		if( !reason ) {
			EXCEPT( "ERROR: out of memory!\n" );
		}
	}
}


void
JobReconnectFailedEvent::setStartdName( const char* name )
{
	if( startd_name ) {
		delete[] startd_name;
		startd_name = NULL;
	}
	if( name ) {
		startd_name = strnewp( name );
		if( !startd_name ) {
			EXCEPT( "ERROR: out of memory!\n" );
		}
	}
}


int
JobReconnectFailedEvent::writeEvent( FILE *file )
{
	if( ! reason ) {
		EXCEPT( "JobReconnectFailedEvent::writeEvent() called without "
				"reason" );
	}
	if( ! startd_name ) {
		EXCEPT( "JobReconnectFailedEvent::writeEvent() called without "
				"startd_name" );
	}

	if( fprintf(file, "Job reconnection failed\n") < 0 ) {
		return 0;
	}
	if( fprintf(file, "    %.8191s\n", reason) < 0 ) {
		return 0;
	}
	if( fprintf(file, "    Can not reconnect to %s, rescheduling job\n", 
				startd_name) < 0 ) {
		return 0;
	}
	return( 1 );
}


int
JobReconnectFailedEvent::readEvent( FILE *file )
{
	MyString line;

		// the first line contains no useful information for us, but
		// it better be there or we've got a parse error.
	if( ! line.readLine(file) ) {
		return 0;
	}

		// 2nd line is the reason
	if( line.readLine(file) && line[0] == ' ' && line[1] == ' ' 
		&& line[2] == ' ' && line[3] == ' ' && line[4] )
	{
		line.chomp();
		setReason( &line[4] );
	} else {
		return 0;
	}

		// 3rd line is who we tried to reconnect to
	if( line.readLine(file) && 
		line.replaceString( "    Can not reconnect to ", "" ) )
	{
			// now everything until the first ',' will be the name
		int i = line.FindChar( ',' );
		if( i > 0 ) {
			line.setChar( i, '\0' );
			setStartdName( line.Value() );
		} else {
			return 0;
		}
	} else {
		return 0;
	}

	return 1;
}


ClassAd*
JobReconnectFailedEvent::toClassAd( void )
{
	if( ! reason ) {
		EXCEPT( "JobReconnectFailedEvent::toClassAd() called without "
				"reason" );
	}
	if( ! startd_name ) {
		EXCEPT( "JobReconnectFailedEvent::toClassAd() called without "
				"startd_name" );
	}

	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) {
		return NULL;
	}
	
	MyString line;
	line.sprintf( "StartdName = \"%s\"", startd_name );
	if( !myad->Insert(line.Value()) ) {
		return NULL;
	}
	line.sprintf( "Reason = \"%s\"", reason );
	if( !myad->Insert(line.Value()) ) {
		return NULL;
	}
	line = "EventDescription=\"Job reconnect impossible: rescheduling job\"";
	if( !myad->Insert(line.Value()) ) {
		return NULL;
	}
	return myad;
}


void
JobReconnectFailedEvent::initFromClassAd( ClassAd* ad )
{
	ULogEvent::initFromClassAd(ad);
	if( !ad ) {
		return;
	}

	// this fanagling is to ensure we don't malloc a pointer then delete it
	char* mallocstr = NULL;
	ad->LookupString( "Reason", &mallocstr );
	if( mallocstr ) {
		if( reason ) {
			delete [] reason;
		}
		reason = strnewp( mallocstr );
		free( mallocstr );
		mallocstr = NULL;
	}

	ad->LookupString( "StartdName", &mallocstr );
	if( mallocstr ) {
		if( startd_name ) {
			delete [] startd_name;
		}
		startd_name = strnewp( mallocstr );
		free( mallocstr );
		mallocstr = NULL;
	}
}


// ----- the GridResourceUp class
GridResourceUpEvent::
GridResourceUpEvent()
{	
	eventNumber = ULOG_GRID_RESOURCE_UP;
	resourceName = NULL;
}

GridResourceUpEvent::
~GridResourceUpEvent()
{
	delete[] resourceName;
}

int GridResourceUpEvent::
writeEvent (FILE *file)
{
	const char * unknown = "UNKNOWN";
	const char * resource = unknown;

	int retval = fprintf (file, "Grid Resource Back Up\n");
	if (retval < 0)
	{
		return 0;
	}
	
	if ( resourceName ) resource = resourceName;

	retval = fprintf( file, "    GridResource: %.8191s\n", resource );
	if( retval < 0 ) {
		return 0;
	}

	return (1);
}

int GridResourceUpEvent::
readEvent (FILE *file)
{
	char s[8192];

	delete[] resourceName;
	resourceName = NULL;
	int retval = fscanf (file, "Grid Resource Back Up\n");
    if (retval != 0)
    {
		return 0;
    }
	s[0] = '\0';
	retval = fscanf( file, "    GridResource: %8191[^\n]\n", s );
	if ( retval != 1 )
	{
		return 0;
	}
	resourceName = strnewp(s);	
	return 1;
}

ClassAd* GridResourceUpEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	
	if( resourceName && resourceName[0] ) {
		MyString buf2;
		buf2.sprintf("GridResource = \"%s\"",resourceName);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}

	return myad;
}

void GridResourceUpEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	// this fanagling is to ensure we don't malloc a pointer then delete it
	char* mallocstr = NULL;
	ad->LookupString("GridResource", &mallocstr);
	if( mallocstr ) {
		resourceName = new char[strlen(mallocstr) + 1];
		strcpy(resourceName, mallocstr);
		free(mallocstr);
	}
}


// ----- the GridResourceDown class
GridResourceDownEvent::
GridResourceDownEvent()
{	
	eventNumber = ULOG_GRID_RESOURCE_DOWN;
	resourceName = NULL;
}

GridResourceDownEvent::
~GridResourceDownEvent()
{
	delete[] resourceName;
}

int GridResourceDownEvent::
writeEvent (FILE *file)
{
	const char * unknown = "UNKNOWN";
	const char * resource = unknown;

	int retval = fprintf (file, "Detected Down Grid Resource\n");
	if (retval < 0)
	{
		return 0;
	}
	
	if ( resourceName ) resource = resourceName;

	retval = fprintf( file, "    GridResource: %.8191s\n", resource );
	if( retval < 0 ) {
		return 0;
	}

	return (1);
}

int GridResourceDownEvent::
readEvent (FILE *file)
{
	char s[8192];

	delete[] resourceName;
	resourceName = NULL;
	int retval = fscanf (file, "Detected Down Grid Resource\n");
    if (retval != 0)
    {
		return 0;
    }
	s[0] = '\0';
	retval = fscanf( file, "    GridResource: %8191[^\n]\n", s );
	if ( retval != 1 )
	{
		return 0;
	}
	resourceName = strnewp(s);	
	return 1;
}

ClassAd* GridResourceDownEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	
	if( resourceName && resourceName[0] ) {
		MyString buf2;
		buf2.sprintf("GridResource = \"%s\"",resourceName);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}

	return myad;
}

void GridResourceDownEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	// this fanagling is to ensure we don't malloc a pointer then delete it
	char* mallocstr = NULL;
	ad->LookupString("GridResource", &mallocstr);
	if( mallocstr ) {
		resourceName = new char[strlen(mallocstr) + 1];
		strcpy(resourceName, mallocstr);
		free(mallocstr);
	}
}


// ----- the GridSubmitEvent class
GridSubmitEvent::
GridSubmitEvent()
{	
	eventNumber = ULOG_GRID_SUBMIT;
	resourceName = NULL;
	jobId = NULL;
}

GridSubmitEvent::
~GridSubmitEvent()
{
	delete[] resourceName;
	delete[] jobId;
}

int GridSubmitEvent::
writeEvent (FILE *file)
{
	const char * unknown = "UNKNOWN";
	const char * resource = unknown;
	const char * job = unknown;

	int retval = fprintf (file, "Job submitted to grid resource\n");
	if (retval < 0)
	{
		return 0;
	}
	
	if ( resourceName ) resource = resourceName;
	if ( jobId ) job = jobId;

	retval = fprintf( file, "    GridResource: %.8191s\n", resource );
	if( retval < 0 ) {
		return 0;
	}

	retval = fprintf( file, "    GridJobId: %.8191s\n", job );
	if( retval < 0 ) {
		return 0;
	}

	return (1);
}

int GridSubmitEvent::
readEvent (FILE *file)
{
	char s[8192];

	delete[] resourceName;
	delete[] jobId;
	resourceName = NULL;
	jobId = NULL;
	int retval = fscanf (file, "Job submitted to grid resource\n");
    if (retval != 0)
    {
		return 0;
    }
	s[0] = '\0';
	retval = fscanf( file, "    GridResource: %8191[^\n]\n", s );
	if ( retval != 1 )
	{
		return 0;
	}
	resourceName = strnewp(s);
	retval = fscanf( file, "    GridJobId: %8191[^\n]\n", s );
	if ( retval != 1 )
	{
		return 0;
	}
	jobId = strnewp(s);

	return 1;
}

ClassAd* GridSubmitEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;
	
	if( resourceName && resourceName[0] ) {
		MyString buf2;
		buf2.sprintf("GridResource = \"%s\"",resourceName);
		if( !myad->Insert(buf2.Value()) ) return NULL;
	}
	if( jobId && jobId[0] ) {
		MyString buf3;
		buf3.sprintf("GridJobId = \"%s\"",jobId);
		if( !myad->Insert(buf3.Value()) ) return NULL;
	}

	return myad;
}

void GridSubmitEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;
	
	// this fanagling is to ensure we don't malloc a pointer then delete it
	char* mallocstr = NULL;
	ad->LookupString("GridResource", &mallocstr);
	if( mallocstr ) {
		resourceName = new char[strlen(mallocstr) + 1];
		strcpy(resourceName, mallocstr);
		free(mallocstr);
	}

	// this fanagling is to ensure we don't malloc a pointer then delete it
	mallocstr = NULL;
	ad->LookupString("GridJobId", &mallocstr);
	if( mallocstr ) {
		jobId = new char[strlen(mallocstr) + 1];
		strcpy(jobId, mallocstr);
		free(mallocstr);
	}
}

// ----- the JobAdInformationEvent class
JobAdInformationEvent::
JobAdInformationEvent()
{	
	jobad = NULL;
	eventNumber = ULOG_JOB_AD_INFORMATION;
}

JobAdInformationEvent::
~JobAdInformationEvent()
{
	if ( jobad ) delete jobad;
}

int JobAdInformationEvent::
writeEvent(FILE *file)
{
	return writeEvent(file,jobad);
}

int JobAdInformationEvent::
writeEvent(FILE *file, ClassAd *jobad_arg)
{
    int retval = 0;	 // 0 == FALSE == failure

	fprintf(file,"Job ad information event triggered.\n");

	if ( jobad_arg ) {
		retval = jobad_arg->fPrint(file);
	}
    
    return retval;
}

int JobAdInformationEvent::
readEvent(FILE *file)
{
    int retval = 0;	// 0 == FALSE == failure
	int EndFlag, ErrorFlag, EmptyFlag;

	EndFlag =  ErrorFlag =  EmptyFlag = 0;

	if( fscanf(file, "Job ad information event triggered.") == EOF ) {
		return 0;
	}

	if ( jobad ) delete jobad;

	if( !( jobad=new ClassAd(file,"...", EndFlag, ErrorFlag, EmptyFlag) ) )
	{
		// Out of memory?!?!
		return 0;
	} 

	// Backup to leave event delimiter unread go past \n too
	fseek( file, -4, SEEK_CUR );

	retval = ! (ErrorFlag || EmptyFlag);

	return retval;
}
	
ClassAd* JobAdInformationEvent::
toClassAd()
{
	ClassAd* myad = ULogEvent::toClassAd();
	if( !myad ) return NULL;

	MergeClassAds(myad,jobad,false);

		// Reset MyType in case MergeClassAds() clobbered it.
	myad->SetMyTypeName("JobAdInformationEvent");

	return myad;
}

void JobAdInformationEvent::
initFromClassAd(ClassAd* ad)
{
	ULogEvent::initFromClassAd(ad);

	if( !ad ) return;

	if ( !jobad ) delete jobad;

	jobad = new ClassAd( *ad );	// invoke copy constructor to make deep copy

	return;
}

int JobAdInformationEvent::
LookupString (const char *attributeName, char **value) const
{
	if ( !jobad ) return 0;		// 0 = failure

	return jobad->LookupString(attributeName,value);
}

int JobAdInformationEvent::
LookupInteger (const char *attributeName, int & value) const
{
	if ( !jobad ) return 0;		// 0 = failure

	return jobad->LookupInteger(attributeName,value);
}

int JobAdInformationEvent::
LookupFloat (const char *attributeName, float & value) const
{
	if ( !jobad ) return 0;		// 0 = failure

	return jobad->LookupFloat(attributeName,value);
}

int JobAdInformationEvent::
LookupBool  (const char *attributeName, bool & value) const
{
	if ( !jobad ) return 0;		// 0 = failure

	return jobad->LookupBool(attributeName,value);
}