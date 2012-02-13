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
#include "condor_daemon_core.h"
#include "condor_debug.h"
#include "HashTable.h"


/// Support object for Create_Thread_With_Data
struct Create_Thread_With_Data_Data {
	int data_n1;
	int data_n2;
	void * data_vp;
	DataThreadWorkerFunc worker;
	DataThreadReaperFunc reaper;
};

/// Support function for Create_Thread_With_Data
static Create_Thread_With_Data_Data * 
malloc_Create_Thread_With_Data_Data(int data_n1, int data_n2, void * data_vp,
	DataThreadWorkerFunc worker, DataThreadReaperFunc reaper)
{
	Create_Thread_With_Data_Data * tmp = (Create_Thread_With_Data_Data *)
		malloc(sizeof(Create_Thread_With_Data_Data));
	ASSERT( tmp );
	tmp->data_n1 = data_n1;
	tmp->data_n2 = data_n2;
	tmp->data_vp = data_vp;
	tmp->worker = worker;
	tmp->reaper = reaper;
	return tmp;
}

/// Support function for Create_Thread_With_Data
static int Create_Thread_With_Data_Start(void * data, Stream *)
{
	Create_Thread_With_Data_Data * tmp = (Create_Thread_With_Data_Data *)data;
	ASSERT(tmp);
	ASSERT(tmp->worker);
	return tmp->worker(tmp->data_n1, tmp->data_n2, tmp->data_vp);
}

static HashTable<int, Create_Thread_With_Data_Data *> tid_to_data(10, hashFuncInt, rejectDuplicateKeys);

/// Support function for Create_Thread_With_Data
static int Create_Thread_With_Data_Reaper(Service *, int tid, int exit_status)
{
	Create_Thread_With_Data_Data * tmp = 0;
	if( tid_to_data.lookup(tid, tmp) != 0 )
	{
		// This tid didn't get inserted.
		ASSERT(0);  
	}
	ASSERT(tmp);
	int ret = 0;
	if( tmp->reaper) {
		ret = tmp->reaper(tmp->data_n1, tmp->data_n2, tmp->data_vp, exit_status);
	}
	if( tid_to_data.remove(tid) != 0 )
	{
		// Index/key wasn't found?  Can't happen.
		ASSERT(0);
	}
	free(tmp);
	return ret;
}

int Create_Thread_With_Data(DataThreadWorkerFunc Worker, DataThreadReaperFunc Reaper, 
	int data_n1 /*= 0*/, int data_n2 /*= 0*/, void * data_vp /*= 0*/)
{
	static bool initialized = false;
	static int reaper = 0;
	if( ! initialized )
	{
		reaper =
		daemonCore->Register_Reaper("Create_Thread_With_Data_Reaper",
		Create_Thread_With_Data_Reaper,
			"Create_Thread_With_Data_Reaper");
		dprintf(D_FULLDEBUG, "Registered reaper for job threads, id %d\n", reaper);
		initialized = true;
	}

	ASSERT(Worker);

	// Passing data to the worker thread is easy, 
	// just pass a malloc()ed struct in.
	// (Must be malloc()ed; the thread code free()s it.)
	Create_Thread_With_Data_Data * tmp = malloc_Create_Thread_With_Data_Data(
		data_n1, data_n2, data_vp, Worker, 0);

	int tid = daemonCore->Create_Thread(Create_Thread_With_Data_Start, 
		tmp, NULL, reaper);

	ASSERT(tid != 0); // otherwise Create_Thread failed.

	// Passing per-thread data to the reader is not quite so easy.  
	// Keep a tid->data map.
	tmp = malloc_Create_Thread_With_Data_Data(data_n1, data_n2, data_vp, 
		0, Reaper);
	if( tid_to_data.insert(tid, tmp) != 0 )
	{
		// This tid already exists!
		ASSERT(0);
	}
	return tid;
}
