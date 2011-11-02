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

#include <string>
#include <map>

#include "condor_classad.h"
#include "list.h"
#include "scheduler.h"

enum AllocStatus { A_NEW, A_RUNNING, A_DYING };

enum NegotiationResult { NR_MATCHED, NR_REJECTED, NR_END_NEGOTIATE, 
						 NR_LIMIT_REACHED, NR_ERROR };

class CAList : public List<ClassAd> {};

class MRecArray : public ExtArray<match_rec*> {};

class AllocationNode {
 public:
	AllocationNode( int cluster_id, int n_procs );
	~AllocationNode();

		// Methods
	void addResource( ClassAd* r, int proc );
	void setClaimId( const char* new_claim_id );
	void display( void );

		// Data
	int status;
	char* claim_id;	// The ClaimId for the first match in the cluster 
	int cluster;		// cluster id of the job(s) for this allocation
	int num_procs;			// How many procs are in the cluster
	ExtArray< ClassAd* >* jobs;		// Both arrays are indexed by proc
	ExtArray< MRecArray* >* matches;
	int num_resources;		// How many total resources have been allocated

	bool is_reconnect;
};		

// These aren't used anymore, but should we care about
// MAX_JOB_RETIREMENT_TIME in the dedicated world, we
// might need to bring this back.

// A ResTimeNode has a list of resources, all of which
// we think will come free at time "time".  These
// ResTimeNodes themselves are linked, sorted by 
// ascending time.

#if 0
class ResTimeNode {
 public:
	ResTimeNode( time_t t );
	~ResTimeNode();
	
		/** Can we satisfy the given job with this ResTimeNode?  No
			matter what we return, num_matches is reset to the number
			of matches we found at this time, and the candidates list
			includes a pointer to each resource ad we matched with.
			@param jobAd The job to satisfy
			@param max_hosts How many resources does this job need?
			@param candidates List of pointers to ads that matched
			@return Was the job completely satisfied?
		*/
	bool satisfyJob( ClassAd* jobAd, int max_hosts,
					 CAList* candidates );

	void display( int level );

	time_t time;
	CAList* res_list;
	int num_matches;
};

#endif

// A ResList is a list of machine resources, all of which are in some
// given state (e.g. unclaimed, busy, etc.)

class ResList : public CAList {
 public:
	ResList(); 
	~ResList();
	
		/** Can we satisfy the given job with this ResList?  No
			matter what we return, num_matches is reset to the number
			of matches we found at this time, and the candidates list
			includes a pointer to each resource ad we matched with.
			@param jobAd The job to satisfy
			@param candidates List of pointers to ads that matched
			@param candidates_jobs parallel list of jobs that matched
			@return Was the job completely satisfied?
		*/

	bool satisfyJobs( CAList* jobs,
					  CAList* candidates, CAList *candidates_jobs, bool rank = false );

	void display( int level );

	void sortByRank( ClassAd *rankAd);

	int num_matches;
	
	static int machineSortByRank(const void *lhs, const void *rhs);

	void selectGroup( CAList *group, const char   *groupName);
};

class CandidateList : public CAList {
 public:
	CandidateList();
	virtual ~CandidateList();

    void appendResources(ResList *res);
	void markScheduled();
};

// We build an array of these, in order to
// sort them, first on rank, then on clusterid
struct PreemptCandidateNode {
	float rank;
	int   cluster_id;
	ClassAd *machine_ad;
};

// save for reservations
#if 0

class AvailTimeList : public List<ResTimeNode> {
 public:
	~AvailTimeList();
	void display( int debug_level );

		/// Returns if there are any resources available in our list.
	bool hasAvailResources( void );

		/** Add the resource described in the given match record into
			our list.  We find out when the resource will be
			available, and add the resource to our list in the
			appropriate ResTimeNode.  If no node exists for the given
			time, we create a new node.
			@param mrec The match record for the resource to add.  */
	void addResource( match_rec* mrec );

		/** Removes the resource classad from the given ResTimeNode in
			our list.  If that was the last resource in the
			ResTimeNode, we remove the node from our list, delete the
			object, and set the given rtn pointer to NULL.
			@param resource The resource to remove
			@param rtn The ResTimeNode to remove it from */
	void removeResource( ClassAd* resource, ResTimeNode* &rtn );
};

#endif

class DedicatedScheduler : public Service {
 public:
	DedicatedScheduler();
	~DedicatedScheduler();

		// Called at start-up to initialize this class.  This does the
		// work of finding which dedicated resources we control, and
		// starting the process of claiming them.
	int initialize( void );
	int shutdown_fast( void );
	int shutdown_graceful( void );
	int	reconfig( void );

		// Function to negotiate with the central manager for our MPI
		// jobs.  This is called by Scheduler::negotiate() if the
		// owner we get off the wire matches the "owner" string we're
		// using. 
	int negotiate( int command, Sock* s, char const* remote_pool );

		// Called everytime we want to process the job queue and
		// schedule/spawn MPI jobs.
	int handleDedicatedJobs( void );

	void handleDedicatedJobTimer( int seconds );

		// Let the outside world know what we're doing... how exactly
		// this should work is still unclear
	void displaySchedule( void );

	void listDedicatedJobs( int debug_level );
	void listDedicatedResources( int debug_level, ClassAdList* resources );

		// Used for claiming/releasing startds we control
	bool releaseClaim( match_rec* m_rec, bool use_tcp = true );
	bool deactivateClaim( match_rec* m_rec );
	void sendAlives( void );

		// Reaper for the MPI shadow
	int reaper( int pid, int status );

	int giveMatches( int cmd, Stream* stream );

		// These are public, since the Scheduler class needs to call
		// them from vacate_service and possibly other places, too.
	bool DelMrec( char const* id );
	bool DelMrec( match_rec* rec );

	char* name( void ) { return ds_name; };
	char* owner( void ) { return ds_owner; };

		/** Publish a ClassAd to the collector that says we have
			resource requests we want to negotiate for.
		*/
	void publishRequestAd( void );

	void generateRequest( ClassAd* job );

	void removeRequest( PROC_ID job_id );

	ClassAd *makeGenericAdFromJobAd(ClassAd *job);

		/** Clear out all existing resource requests.  Used at the
			begining of computeSchedule(), since, if there are still
			resource requests from the last schedule that we haven't
			negotiated for, we want to get rid of those and figure out 
			everything we need to request given the current state of
			things.
		*/
	void clearResourceRequests( void );

		// Set the correct value of ATTR_SCHEDULER in the queue for
		// the given job ad.
	bool setScheduler( ClassAd* job_ad );

		/// Clear out our data structure of idle dedicated jobs. 
	void clearDedicatedClusters( void );

		/// Add the given cluster to our set of idle dedicated jobs.
	void addDedicatedCluster( int cluster );

		/// Returns true if there are idle dedicated clusters.
	bool hasDedicatedClusters( void );

		/** Called by the Scheduler class when an MPI shadow is
			finally running (after waiting in the RunnableJobQueue).
		*/ 
	bool shadowSpawned( shadow_rec* srec );

		// the qmgmt code calls this method at startup with
		// each job that can be reconnect to running startds
	bool enqueueReconnectJob(PROC_ID id);

    match_rec *FindMRecByJobID(PROC_ID job_id);

	match_rec *FindMrecByClaimID(char const *claim_id);

		// it is caller's responsibility to delete returned ClassAd
	ClassAd *GetMatchRequestAd( match_rec *mrec );

	match_rec *AddMrec(char const* claim_id,
					   char const* startd_addr,
					   char const* slot_name,
					   PROC_ID job_id,
					   const ClassAd* match_ad,
					   char const *remote_pool );

	void			checkReconnectQueue( void );

	int		rid;			// DC reaper id

 private:

		// This gets a list of all dedicated resources we control.
		// This is called at the begining of each handleDedicatedJobs
		// cycle.
	bool getDedicatedResourceInfo( void );

		// This one should be seperated out, and most easy to change.
	bool computeSchedule( void );

		// This creates resource allocations from a matched job
	void createAllocations( CAList *idle_candidates, CAList *idle_candidates_jobs, 
							int cluster, int nprocs, bool is_reconnect);

		// This does the work of acting on a schedule, once that's
		// been decided.  
	bool spawnJobs( void );

		// We need to stick all the claimids and remote-hosts
		// into the job ad, so we can find them at reconnect-time
	void addReconnectAttributes(AllocationNode *node);

    char *matchToHost(match_rec *mrec, int cluster, int proc);

		// Do through our list of pending resource requests, and
		// publish a ClassAd to the CM to ask for them.
	bool requestResources( void );

		// Go through the list of pending preemption, and
		// call deactivateClaim on each of them
	bool preemptResources( void );

		// Print out all our pending resource requests.
	void displayResourceRequests( void );

	void printSatisfaction( int cluster, CAList* idle, CAList* limbo,
							CAList* unclaimed, CAList* busy );

	void sortResources( void );
	void clearResources( void );
	void addToSchedulingGroup( ClassAd *r );

	bool sortJobs( void );

        // Used to give matches to the mpi shadow when it asks for
		// them. 
    int giveMPIMatches( Service*, int cmd, Stream* stream );

		// Deactivate the claim on all resources used by this shadow
	void shutdownMpiJob( shadow_rec* srec , bool kill = false);

		/** Update internal data structures to remove the allocation  
			associated with this shadow.
			@param srec Shadow record of the allocation to remove
		*/
	void removeAllocation( shadow_rec* srec );

	void callHandleDedicatedJobs( void );

		/** Do a number of sanity-checks, like releasing resources
			we're holding onto and not using.
		*/
	void checkSanity( void );

		/** Check the given match record to make sure the claim hasn't
			been unused for too long.
			@param mrec The match record to check
			@return how many seconds this match has not been used
		*/
	int getUnusedTime( match_rec* mrec );

		/** Find the match record that corresponds to the given
			resource classad.  If the second argument is non-NULL, the
			value of ATTR_NAME from the given resource ad will be
			printed there.
			@param ad ClassAd for the resource you want to find
			@param buf An optional buffer to store ATTR_NAME
			@return pointer to the mrec if found, NULL if not
		*/
	match_rec* getMrec( ClassAd* ad, char* buf = NULL );

		/** Figure out if it's possible to ever schedule this job,
			given all of the dedicated resources we know about. 
			@param job ClassAd of the job to schedule
			@param max_hosts How many hosts the job is looking for
			@return true if possible, false if not
		*/
	bool isPossibleToSatisfy( CAList* jobs, int max_hosts );

	bool hasDedicatedShadow( void );

	void holdAllDedicatedJobs( void );

	bool satisfyJobWithGroups(CAList *jobs, int cluster, int nprocs);

		// // // // // // 
		// Data members 
		// // // // // // 

		// Stuff for interacting w/ DaemonCore
	int		hdjt_tid;		// DC timer id for handleDedicatedJobTimer()
	int		sanity_tid;		// DC timer id for sanityCheck()

		// data structures for managing dedicated jobs and resources. 
	ExtArray<int>*		idle_clusters;	// Idle cluster ids

	ClassAdList*		resources;		// All dedicated resources 


		// All resources, sorted by the time they'll next be available 
		//AvailTimeList*			avail_time_list;	

		// 	These four lists are the heart of the data structures for
		// the dedicated scheduler: We prefer to schedule jobs from
		// the idle_resources list, but if that's not possible, we
		// then go to the limbo, then unclaimed list, to kick off
		// vanilla jobs.  If we still can't satisfy, then go to the
		// busy list, and preempt those.

	    // Each of these lists is sorted first by preemption rank,
		//  then by Cluster -- the idea is that if we have to evict
		//  one job of a cluster we hope to evict the peers as well.
																	   
		// All resources that are idle and claimed by the ded sched
	ResList*		idle_resources;

		// All resources that might be dedicated to us that aren't
		// currently claimed by us -- they are probably running
		// vanilla jobs
	ResList*		unclaimed_resources;

		// All resources that are in limbo
		// These should be idle soon, but haven't made
		// it there yet.
	ResList*		limbo_resources;

		// All resources that are busy (and claimed)
	ResList*		busy_resources;

        // hashed on cluster, all our allocations
    HashTable <int, AllocationNode*>* allocations;

		// List of resources to preempt
	CAList *pending_preemptions;

		// hashed on resource name, each claim we have
	HashTable <HashKey, match_rec*>* all_matches;

		// hashed on ClaimId, each claim we have.  only store
		// pointers in here into the real match records we store in
		// all_matches.  This is needed for some functions that only
		// know the ClaimId (like DelMrec(), since vacate_service()
		// is only given a ClaimId to identify the lost claim).
	HashTable <HashKey, match_rec*>* all_matches_by_id;

		// Queue for resource requests we need to negotiate for. 
	std::list<PROC_ID> resource_requests;

        // stores job classads, indexed by each job's pending claim-id
    std::map<std::string, ClassAd*> pending_requests;

        // stores match recs from partitionable slots, indexed by claim id
    std::map<std::string, match_rec*> pending_matches;

        // stores pending claim ids against partitionable slots, indexed
        // by corresponding public claim id
    std::map<std::string, std::string> pending_claims;


	int		num_matches;	// Total number of matches in all_matches 

    static const int MPIShadowSockTimeout;

	ClassAd		dummy_job;		// Dummy ad used for claiming startds 

	char* ds_name;		// Name of this dedicated scheduler.  Also
		                // used for ATTR_SCHEDULER.
	char* ds_owner;		// "Owner" to identify this dedicated scheduler 

	int unused_timeout;	// How many seconds are we willing to hold
		// onto a resource without using it before we release it? 

	Shadow* shadow_obj;

	friend class CandidateList;

	SimpleList<PROC_ID> jobsToReconnect;
	//int				checkReconnectQueue_tid;
	
	StringList scheduling_groups;
};


// ////////////////////////////////////////////////////////////
//   Utility functions
// ////////////////////////////////////////////////////////////

// Find when a given resource will next be available
time_t findAvailTime( match_rec* mrec );

// Comparison function for sorting job cluster ids by JOB_PRIO and QDate
int clusterSortByPrioAndDate( const void* ptr1, const void* ptr2 );

// Comparison function for sorting machines by rank, cluster_id
int
RankSorter( const void *ptr1, const void* ptr2 );

// Print out
void displayResource( ClassAd* ad, const char* str, int debug_level );
void displayRequest( ClassAd* ad, char* str, int debug_level );

// Clear out all the fields in the match record that have anything to
// do with the mrec being allocated to a certain MPI job.
void deallocMatchRec( match_rec* mrec );

