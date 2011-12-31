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

#include "Globals.h"

JobCollectionType g_jobs;
SubmissionCollectionType g_submissions;
OwnerlessClusterType g_ownerless_clusters;
OwnerlessSubmissionType g_ownerless_submissions;

void global_reset() {

	for (JobCollectionType::iterator i = g_jobs.begin();
	     g_jobs.end() != i; i++) {
		// Skip clusters for now
		if ('0' != (*i).second->GetKey()[0]) {
			delete (*i).second;
			g_jobs.erase(i);
		}
	}

	for (JobCollectionType::iterator i = g_jobs.begin();
		  g_jobs.end() != i; i++) {
		     delete (*i).second;
		     g_jobs.erase(i);
	}

	for (OwnerlessClusterType::iterator i = g_ownerless_clusters.begin();
		       g_ownerless_clusters.end() != i; i++) {
			  g_ownerless_clusters.erase(i);
	}

	for (OwnerlessSubmissionType::iterator i = g_ownerless_submissions.begin();
		       g_ownerless_submissions.end() != i; i++) {
			  g_ownerless_submissions.erase(i);
	}

	for (SubmissionCollectionType::iterator i = g_submissions.begin();
		       g_submissions.end() != i; i++) {
			  delete (*i).second;
			  g_submissions.erase(i);
	}
}
