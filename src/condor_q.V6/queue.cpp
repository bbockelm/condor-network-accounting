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
#include "condor_config.h"
#include "condor_accountant.h"
#include "condor_classad.h"
#include "condor_debug.h"
#include "condor_query.h"
#include "condor_q.h"
#include "condor_io.h"
#include "condor_string.h"
#include "condor_attributes.h"
#include "match_prefix.h"
#include "get_daemon_name.h"
#include "MyString.h"
#include "ad_printmask.h"
#include "internet.h"
#include "sig_install.h"
#include "format_time.h"
#include "daemon.h"
#include "dc_collector.h"
#include "basename.h"
#include "metric_units.h"
#include "globus_utils.h"
#include "error_utils.h"
#include "print_wrapped_text.h"
#include "condor_distribution.h"
#include "string_list.h"
#include "condor_version.h"
#include "subsystem_info.h"
#include "condor_xml_classads.h"
#include "condor_open.h"
#include "condor_sockaddr.h"
#include "ipv6_hostname.h"
#include <map>
#include <vector>
#include "../classad_analysis/analysis.h"

#ifdef HAVE_EXT_POSTGRESQL
#include "sqlquery.h"
#endif /* HAVE_EXT_POSTGRESQL */

/* Since this enum can have conditional compilation applied to it, I'm
	specifying the values for it to keep their actual integral values
	constant in case someone decides to write this information to disk to
	pass it to another daemon or something. This enum is used to determine
	who to talk to when using the -direct option. */
enum {
	/* don't know who I should be talking to */
	DIRECT_UNKNOWN = 0,
	/* start at the rdbms and fail over like normal */
	DIRECT_ALL = 1,
#ifdef HAVE_EXT_POSTGRESQL
	/* talk directly to the rdbms system */
	DIRECT_RDBMS = 2,
	/* talk directly to the quill daemon */
	DIRECT_QUILLD = 3,
#endif
	/* talk directly to the schedd */
	DIRECT_SCHEDD = 4
};

#ifdef WIN32
static int getConsoleWindowSize(int * pHeight = NULL) {
	CONSOLE_SCREEN_BUFFER_INFO ws;
	if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &ws)) {
		if (pHeight)
			*pHeight = (int)(ws.srWindow.Bottom - ws.srWindow.Top)+1;
		return (int)ws.dwSize.X;
	}
	return 80;
}
#else
#include <sys/ioctl.h> 
static int getConsoleWindowSize(int * pHeight = NULL) {
    struct winsize ws; 
	if (0 == ioctl(0, TIOCGWINSZ, &ws)) {
		//printf ("lines %d\n", ws.ws_row); 
		//printf ("columns %d\n", ws.ws_col); 
		if (pHeight)
			*pHeight = (int)ws.ws_row;
		return (int) ws.ws_col;
	}
	return 80;
}
#endif

extern 	"C" int SetSyscalls(int val){return val;}
extern  void short_print(int,int,const char*,int,int,int,int,int,const char *);
static  void processCommandLineArguments(int, char *[]);

static  bool process_buffer_line( ClassAd * );

static 	void short_header (void);
static 	void usage (const char *);
static 	void io_display (ClassAd *);
static 	char * buffer_io_display (ClassAd *);
static 	void displayJobShort (ClassAd *);
static 	char * bufferJobShort (ClassAd *);

/* if useDB is false, then v1 =scheddAddress, v2=scheddName, v3=scheddMachine, v4=scheddVersion;
   if useDB is true,  then v1 =quill_name,  v2=db_ipAddr,   v3=db_name, v4=db_password
*/
static	bool show_queue (const char* v1, const char* v2, const char* v3, const char* v4, bool useDB);
static	bool show_queue_buffered (const char* v1, const char* v2, const char* v3, const char* v4, bool useDB);
static void init_output_mask();


/* a type used to point to one of the above two functions */
typedef bool (*show_queue_fp)(const char* v1, const char* v2, const char* v3, const char* v4, bool useDB);

static bool read_classad_file(const char *filename, ClassAdList &classads);

/* convert the -direct aqrgument prameter into an enum */
unsigned int process_direct_argument(char *arg);

#ifdef HAVE_EXT_POSTGRESQL
/* execute a database query directly */ 
static void exec_db_query(const char *quill_name, const char *db_ipAddr, const char *db_name,const char *query_password);

/* build database connection string */
static char * getDBConnStr(char const *&, char const *&, char const *&, char const *&);

/* get the quill address for the quill_name specified */
static QueryResult getQuillAddrFromCollector(char *quill_name, char *&quill_addr);

/* avgqueuetime is used to indicate a request to query average wait time for uncompleted jobs in queue */
static  bool avgqueuetime = false;
#endif

/* Warn about schedd-wide limits that may confuse analysis code */
void warnScheddLimits(Daemon *schedd,ClassAd *job,MyString &result_buf);

/* directDBquery means we will just run a database query and return results directly to user */
static  bool directDBquery = false;

/* who is it that I should directly ask for the queue, defaults to the normal
	failover semantics */
static unsigned int direct = DIRECT_ALL;

static 	int verbose = 0, summarize = 1, global = 0, show_io = 0, dag = 0, show_held = 0;
static  int use_xml = 0;
static  bool widescreen = false;
static  bool unbuffered = false;
static  bool expert = false;

static 	int malformed, running, idle, held, suspended, completed, removed;

static  char *jobads_file = NULL;
static  char *machineads_file = NULL;

static	CondorQ 	Q;
static	QueryResult result;

#ifdef HAVE_EXT_POSTGRESQL
static  QueryResult result2;
#endif

static	CondorQuery	scheddQuery(SCHEDD_AD);
static	CondorQuery submittorQuery(SUBMITTOR_AD);

static	ClassAdList	scheddList;

static  Daemon *g_cur_schedd_for_process_buffer_line = NULL;

static  ClassAdAnalyzer analyzer;

static const char* format_owner( char*, AttrList*);
static const char* format_owner_wide( char*, AttrList*, Formatter &);

// clusterProcString is the container where the output strings are
//    stored.  We need the cluster and proc so that we can sort in an
//    orderly manner (and don't need to rely on the cluster.proc to be
//    available....)

class clusterProcString {
public:
	clusterProcString();
	int dagman_cluster_id;
	int dagman_proc_id;
	int cluster;
	int proc;
	char * string;
	clusterProcString *parent;
	std::vector<clusterProcString*> children;
};

class clusterProcMapper {
public:
	int dagman_cluster_id;
	int dagman_proc_id;
	int cluster;
	int proc;
	clusterProcMapper(const clusterProcString& cps) : dagman_cluster_id(cps.dagman_cluster_id),
		dagman_proc_id(cps.dagman_proc_id), cluster(cps.cluster), proc(cps.proc) {}
	clusterProcMapper(int dci) : dagman_cluster_id(dci), dagman_proc_id(0), cluster(dci),
		proc(0) {}
};

class clusterIDProcIDMapper {
public:
	int cluster;
	int proc;
	clusterIDProcIDMapper(const clusterProcString& cps) :  cluster(cps.cluster), proc(cps.proc) {}
	clusterIDProcIDMapper(int dci) : cluster(dci), proc(0) {}
};

class CompareProcMaps {
public:
	bool operator()(const clusterProcMapper& a, const clusterProcMapper& b) const {
		if (a.cluster < 0 || a.proc < 0) return true;
		if (b.cluster < 0 || b.proc < 0) return false;
		if (a.dagman_cluster_id < b.dagman_cluster_id) { return true; }
		if (a.dagman_cluster_id > b.dagman_cluster_id) { return false; }
		if (a.dagman_proc_id < b.dagman_proc_id) { return true; }
		if (a.dagman_proc_id > b.dagman_proc_id) { return false; }
		if (a.cluster < b.cluster ) { return true; }
		if (a.cluster > b.cluster ) { return false; }
		if (a.proc    < b.proc    ) { return true; }
		if (a.proc    > b.proc    ) { return false; }
		return false;
	}
};

class CompareProcIDMaps {
public:
	bool operator()(const clusterIDProcIDMapper& a, const clusterIDProcIDMapper& b) const {
		if (a.cluster < 0 || a.proc < 0) return true;
		if (b.cluster < 0 || b.proc < 0) return false;
		if (a.cluster < b.cluster ) { return true; }
		if (a.cluster > b.cluster ) { return false; }
		if (a.proc    < b.proc    ) { return true; }
		if (a.proc    > b.proc    ) { return false; }
		return false;
	}
};

/* To save typing */
typedef std::map<clusterProcMapper,clusterProcString*,CompareProcMaps> dag_map_type;
typedef std::map<clusterIDProcIDMapper,clusterProcString*,CompareProcIDMaps> dag_cluster_map_type;
dag_map_type dag_map;
dag_cluster_map_type dag_cluster_map;

clusterProcString::clusterProcString() : dagman_cluster_id(-1), dagman_proc_id(-1),
	cluster(-1), proc(-1), string(0), parent(0) {}

static	bool		usingPrintMask = false;
static 	bool		customFormat = false;
static  bool		cputime = false;
static	bool		current_run = false;
static 	bool		globus = false;
static	bool		dash_grid = false;
static  const char		*JOB_TIME = "RUN_TIME";
static	bool		querySchedds 	= false;
static	bool		querySubmittors = false;
static	char		constraint[4096];
static  const char *user_constraint; // just the constraint given by the user
static	DCCollector* pool = NULL; 
static	char		*scheddAddr;	// used by format_remote_host()
static	AttrListPrintMask 	mask;
static  List<const char> mask_head; // The list of headings for the mask entries
//static const char * mask_headings = NULL;
static CollectorList * Collectors = NULL;

// for run failure analysis
static  int			findSubmittor( char * );
static	void 		setupAnalysis();
static 	void		fetchSubmittorPrios();
static	void		doRunAnalysis( ClassAd*, Daemon* );
static	const char *doRunAnalysisToBuffer( ClassAd*, Daemon* );
struct 	PrioEntry { MyString name; float prio; };
static  bool        better_analyze = false;
static	bool		run = false;
static	bool		goodput = false;
static	char		*fixSubmittorName( char*, int );
static	ClassAdList startdAds;
static	ExprTree	*stdRankCondition;
static	ExprTree	*preemptRankCondition;
static	ExprTree	*preemptPrioCondition;
static	ExprTree	*preemptionReq;
static  ExtArray<PrioEntry> prioTable;
#ifndef WIN32
#endif
	
const int SHORT_BUFFER_SIZE = 8192;
const int LONG_BUFFER_SIZE = 16384;	
char return_buff[LONG_BUFFER_SIZE * 100];

char *quillName = NULL;
char *quillAddr = NULL;
char *quillMachine = NULL;
char *dbIpAddr = NULL;
char *dbName = NULL;
char *queryPassword = NULL;

StringList attrs(NULL, "\n");; // The list of attrs we want, "" for all

bool g_stream_results = false;

static void freeConnectionStrings() {
	if(quillName) {
		free(quillName);
		quillName = NULL;
	}
	if(quillAddr) {
		free(quillAddr);
		quillAddr = NULL;
	}
	if(quillMachine) {
		free(quillMachine);
		quillMachine = NULL;
	}
	if(dbIpAddr) {
		free(dbIpAddr);
		dbIpAddr = NULL;
	}
	if(dbName) {
		free(dbName);
		dbName = NULL;
	}
	if(queryPassword) {
		free(queryPassword);
		queryPassword = NULL;
	}
}

#ifdef HAVE_EXT_POSTGRESQL
/* this function for checking whether database can be used for querying in local machine */
static bool checkDBconfig() {
	char *tmp;

	if (param_boolean("QUILL_ENABLED", false) == false) {
		return false;
	};

	tmp = param("QUILL_NAME");
	if (!tmp) {
		return false;
	}
	free(tmp);

	tmp = param("QUILL_DB_IP_ADDR");
	if (!tmp) {
		return false;
	}
	free(tmp);

	tmp = param("QUILL_DB_NAME");
	if (!tmp) {
		return false;
	}
	free(tmp);

	tmp = param("QUILL_DB_QUERY_PASSWORD");
	if (!tmp) {
		return false;
	}
	free(tmp);

	return true;
}
#endif /* HAVE_EXT_POSTGRESQL */

extern 	"C"	int		Termlog;

int main (int argc, char **argv)
{
	ClassAd		*ad;
	bool		first;
	char		*scheddName=NULL;
	char		scheddMachine[64];
	MyString    scheddVersion;
	char		*tmp;
	bool        useDB; /* Is there a database to query for a schedd */
	int         retval = 0;
	show_queue_fp sqfp;

	Collectors = NULL;

	// load up configuration file
	myDistro->Init( argc, argv );
	config();

#ifdef HAVE_EXT_POSTGRESQL
		/* by default check the configuration for local database */
	useDB = checkDBconfig();
#else 
	useDB = FALSE;
	if (useDB) {} /* Done to suppress set-but-not-used warnings */
#endif /* HAVE_EXT_POSTGRESQL */

#if !defined(WIN32)
	install_sig_handler(SIGPIPE, SIG_IGN );
#endif

	// process arguments
	processCommandLineArguments (argc, argv);

	// Since we are assuming that we want to talk to a DB in the normal
	// case, this will ensure that we don't try to when loading the job queue
	// classads from file.
	if (jobads_file != NULL) {
		useDB = FALSE;
	}

	if (Collectors == NULL) {
		Collectors = CollectorList::create();
	}

	// check if analysis is required
	if( better_analyze ) {
		setupAnalysis();
	}

	// if we haven't figured out what to do yet, just display the
	// local queue 
	if (!global && !querySchedds && !querySubmittors) {

		Daemon schedd( DT_SCHEDD, 0, 0 );

		if ( schedd.locate() ) {

			scheddAddr = strdup(schedd.addr());
			if( (tmp = schedd.name()) ) {
				scheddName = strdup(tmp);
				Q.addSchedd(scheddName);
			} else {
				scheddName = strdup("Unknown");
			}
			if( (tmp = schedd.fullHostname()) ) {
				sprintf( scheddMachine, "%s", tmp );
			} else {
				sprintf( scheddMachine, "Unknown" );
			}
			if( (tmp = schedd.version()) ) {
				scheddVersion = tmp;
			}
			else {
				scheddVersion = "";
			}
			
			if ( directDBquery ) {				
				/* perform direct DB query if indicated and exit */
#ifdef HAVE_EXT_POSTGRESQL

					/* check if database is available */
				if (!useDB) {
					printf ("\n\n-- Schedd: %s : %s\n", scheddName, scheddAddr);
					fprintf(stderr, "Database query not supported on schedd: %s\n", scheddName);
				}

				exec_db_query(NULL, NULL, NULL, NULL);
				freeConnectionStrings();
				exit(EXIT_SUCCESS);
#endif /* HAVE_EXT_POSTGRESQL */
			} 

			/* .. not a direct db query, so just happily continue ... */

           	// When we use the new analysis code, it can be really
           	// slow. Slow enough that show_queue_buffered()'s connection
           	// to the schedd time's out and the user gets nothing
           	// useful printed out. Therefore, we use show_queue,
           	// which fetches all of the ads, then analyzes them. 
			if ( (unbuffered || verbose || better_analyze || jobads_file) && !g_stream_results ) {
				sqfp = show_queue;
			} else {
				sqfp = show_queue_buffered;
			}
			init_output_mask();
			
			/* When an installation has database parameters configured, 
				it means there is quill daemon. If database
				is not accessible, we fail over to
				quill daemon, and if quill daemon
				is not available, we fail over the
				schedd daemon */
			switch(direct)
			{
				case DIRECT_ALL:
					/* always try the failover sequence */

					/* FALL THROUGH */

#ifdef HAVE_EXT_POSTGRESQL
				case DIRECT_RDBMS:
					if (useDB) {

						/* ask the database for the queue */

						if ( (retval = sqfp( NULL, NULL, NULL, NULL, TRUE) ) ) {
							/* if the queue was retrieved, then I am done */
							freeConnectionStrings();
							exit(retval?EXIT_SUCCESS:EXIT_FAILURE);
						}
						
						fprintf( stderr, 
							"-- Database not reachable or down.\n");

						if (direct == DIRECT_RDBMS) {
							fprintf(stderr,
								"\t- Not failing over due to -direct\n");
							exit(retval?EXIT_SUCCESS:EXIT_FAILURE);
						} 

						fprintf(stderr,
							"\t- Failing over to the quill daemon --\n");

						/* Hmm... couldn't find the database, so try the 
							quilld */
					} else {
						if (direct == DIRECT_RDBMS) {
							fprintf(stderr, 
								"-- Direct query to rdbms on behalf of\n"
								"\tschedd %s(%s) failed.\n"
								"\t- Schedd doesn't appear to be using "
								"quill.\n",
								scheddName, scheddAddr);
							fprintf(stderr,
								"\t- Not failing over due to -direct\n");
							exit(EXIT_FAILURE);
						}
					}

					/* FALL THROUGH */

				case DIRECT_QUILLD:
					if (useDB) {

						Daemon quill( DT_QUILL, 0, 0 );
						char tmp_char[8];
						strcpy(tmp_char, "Unknown");

						/* query the quill daemon */
						if ( quill.locate() &&
					 		( (retval = 
					 			sqfp( quill.addr(), 
						  		(quill.name())?
									(quill.name()):tmp_char,
						  		(quill.fullHostname())?
									(quill.fullHostname()):tmp_char,
						  		NULL, FALSE) ) ) )
						{
							/* if the queue was retrieved, then I am done */
							freeConnectionStrings();
							exit(retval?EXIT_SUCCESS:EXIT_FAILURE);
						}

						fprintf( stderr,
							"-- Quill daemon at %s(%s)\n"
							"\tassociated with schedd %s(%s)\n"
							"\tis not reachable or can't talk to rdbms.\n",
							quill.name(), quill.addr(),
							scheddName, scheddAddr );

						if (direct == DIRECT_QUILLD) {
							fprintf(stderr,
								"\t- Not failing over due to -direct\n");
							exit(retval?EXIT_SUCCESS:EXIT_FAILURE);
						}

						fprintf(stderr,
							"\t- Failing over to the schedd %s(%s).\n", 
							scheddName, scheddAddr);

					} else {
						if (direct == DIRECT_QUILLD) {
							fprintf(stderr,
								"-- Direct query to quilld associated with\n"
								"\tschedd %s(%s) failed.\n"
								"\t- Schedd doesn't appear to be using "
								"quill.\n",
								scheddName, scheddAddr);

							fprintf(stderr,
								"\t- Not failing over due to use of -direct\n");

							exit(EXIT_FAILURE);
						}
					}

#endif /* HAVE_EXT_POSTGRESQL */
				case DIRECT_SCHEDD:
					retval = sqfp(scheddAddr, scheddName, scheddMachine, 
								  scheddVersion.Value(), FALSE);
			
					/* Hopefully I got the queue from the schedd... */
					freeConnectionStrings();
					exit(retval?EXIT_SUCCESS:EXIT_FAILURE);
					break;

				case DIRECT_UNKNOWN:
				default:
					fprintf( stderr,
						"-- Cannot determine any location for queue "
						"using option -direct!\n"
						"\t- This is an internal error and should be "
						"reported to condor-admin@cs.wisc.edu." );
					exit(EXIT_FAILURE);
					break;
			}
		} 
		
		/* I couldn't find a local schedd, so dump a message about what
			happened. */

		fprintf( stderr, "Error: %s\n", schedd.error() );
		if (!expert) {
			fprintf(stderr, "\n");
			print_wrapped_text("Extra Info: You probably saw this "
							   "error because the condor_schedd is "
							   "not running on the machine you are "
							   "trying to query.  If the condor_schedd "
							   "is not running, the Condor system "
							   "will not be able to find an address "
							   "and port to connect to and satisfy "
							   "this request.  Please make sure "
							   "the Condor daemons are running and "
							   "try again.\n", stderr );
			print_wrapped_text("Extra Info: "
							   "If the condor_schedd is running on the "
							   "machine you are trying to query and "
							   "you still see the error, the most "
							   "likely cause is that you have setup a " 
							   "personal Condor, you have not "
							   "defined SCHEDD_NAME in your "
							   "condor_config file, and something "
							   "is wrong with your "
							   "SCHEDD_ADDRESS_FILE setting. "
							   "You must define either or both of "
							   "those settings in your config "
							   "file, or you must use the -name "
							   "option to condor_q. Please see "
							   "the Condor manual for details on "
							   "SCHEDD_NAME and "
							   "SCHEDD_ADDRESS_FILE.",  stderr );
		}

		freeConnectionStrings();
		exit( EXIT_FAILURE );
	}
	
	// if a global queue is required, query the schedds instead of submittors
	if (global) {
		querySchedds = true;
		sprintf( constraint, "%s > 0 || %s > 0 || %s > 0 || %s > 0 || %s > 0", 
			ATTR_TOTAL_RUNNING_JOBS, ATTR_TOTAL_IDLE_JOBS,
			ATTR_TOTAL_HELD_JOBS, ATTR_TOTAL_REMOVED_JOBS,
			ATTR_TOTAL_JOB_ADS );
		result = scheddQuery.addANDConstraint( constraint );
		if( result != Q_OK ) {
			fprintf( stderr, "Error: Couldn't add constraint %s\n", constraint);
			freeConnectionStrings();
			exit( 1 );
		}
	}

	// get the list of ads from the collector
	if( querySchedds ) { 
		result = Collectors->query ( scheddQuery, scheddList );		
	} else {
		result = Collectors->query ( submittorQuery, scheddList );
	}

	switch( result ) {
	case Q_OK:
		break;
	case Q_COMMUNICATION_ERROR: 
			// if we're not an expert, we want verbose output
		printNoCollectorContact( stderr, pool ? pool->name() : NULL,
								 !expert ); 
		freeConnectionStrings();
		exit( 1 );
	case Q_NO_COLLECTOR_HOST:
		ASSERT( pool );
		fprintf( stderr, "Error: Can't contact condor_collector: "
				 "invalid hostname: %s\n", pool->name() );
		freeConnectionStrings();
		exit( 1 );
	default:
		fprintf( stderr, "Error fetching ads: %s\n", 
				 getStrQueryResult(result) );
		freeConnectionStrings();
		exit( 1 );
	}

		/*if(querySchedds && scheddList.MyLength() == 0) {
		  result = Collectors->query(quillQuery, quillList);
		}*/

	first = true;
	// get queue from each ScheddIpAddr in ad
	scheddList.Open();	
	while ((ad = scheddList.Next()))
	{
		/* default to true for remotely queryable */
#ifdef HAVE_EXT_POSTGRESQL
		int flag=1;
#endif

		freeConnectionStrings();
		useDB = FALSE;
		if ( ! (ad->LookupString(ATTR_SCHEDD_IP_ADDR, &scheddAddr)  &&
				 ad->LookupString(ATTR_NAME, &scheddName)		&& 
				 ad->LookupString(ATTR_MACHINE, scheddMachine) &&
				 ad->LookupString(ATTR_VERSION, scheddVersion) ) ) 
		{
			/* something is wrong with this schedd/quill ad, try the next one */
			continue;
		}

#ifdef HAVE_EXT_POSTGRESQL
		char		daemonAdName[128];
			// get the address of the database
		if (ad->LookupString(ATTR_QUILL_DB_IP_ADDR, &dbIpAddr) &&
			ad->LookupString(ATTR_QUILL_NAME, &quillName) &&
			ad->LookupString(ATTR_QUILL_DB_NAME, &dbName) && 
			ad->LookupString(ATTR_QUILL_DB_QUERY_PASSWORD, &queryPassword) &&
			(!ad->LookupBool(ATTR_QUILL_IS_REMOTELY_QUERYABLE,flag) || flag)) {

			/* If the quill information is available, try to use it first */
			useDB = TRUE;
	    	if (ad->LookupString(ATTR_SCHEDD_NAME, daemonAdName)) {
				Q.addSchedd(daemonAdName);
			} else {
				Q.addSchedd(scheddName);
			}

				/* get the quill info for fail-over processing */
			ASSERT(ad->LookupString(ATTR_MACHINE, &quillMachine));
		}
#endif 

		first = false;

			/* check if direct DB query is indicated */
		if ( directDBquery ) {				
#ifdef HAVE_EXT_POSTGRESQL
			if (!useDB) {
				printf ("\n\n-- Schedd: %s : %s\n", scheddName, scheddAddr);
				fprintf(stderr, "Database query not supported on schedd: %s\n",
						scheddName);
				continue;
			}
			
			exec_db_query(quillName, dbIpAddr, dbName, queryPassword);

			/* done processing the ad, so get the next one */
			continue;

#endif /* HAVE_EXT_POSTGRESQL */
		}

        // When we use the new analysis code, it can be really
        // slow. Slow enough that show_queue_buffered()'s connection
        // to the schedd time's out and the user gets nothing
        // useful printed out. Therefore, we use show_queue,
        // which fetches all of the ads, then analyzes them. 
		if ( (unbuffered || verbose || better_analyze) && !g_stream_results ) {
			sqfp = show_queue;
		} else {
			sqfp = show_queue_buffered;
		}
		init_output_mask();

		/* When an installation has database parameters configured, it means 
		   there is quill daemon. If database is not accessible, we fail
		   over to quill daemon, and if quill daemon is not available, 
		   we fail over the schedd daemon */			
		switch(direct)
		{
			case DIRECT_ALL:
				/* FALL THROUGH */
#ifdef HAVE_EXT_POSTGRESQL
			case DIRECT_RDBMS:
				if (useDB) {
					if ( (retval = sqfp(quillName, dbIpAddr, dbName, 
										queryPassword, TRUE) ) )
					{
						/* processed correctly, so do the next ad */
						continue;
					}

					fprintf( stderr, "-- Database server %s\n"
							"\tbeing used by the quill daemon %s\n"
							"\tassociated with schedd %s(%s)\n"
							"\tis not reachable or down.\n",
							dbIpAddr, quillName, scheddName, scheddAddr);

					if (direct == DIRECT_RDBMS) {
						fprintf(stderr, 
							"\t- Not failing over due to -direct\n");
						continue;
					} 

					fprintf(stderr, 
						"\t- Failing over to the quill daemon at %s--\n", 
						quillName);

				} else {
					if (direct == DIRECT_RDBMS) {
						fprintf(stderr, 
							"-- Direct query to rdbms on behalf of\n"
							"\tschedd %s(%s) failed.\n"
							"\t- Schedd doesn't appear to be using quill.\n",
							scheddName, scheddAddr);
						fprintf(stderr,
							"\t- Not failing over due to -direct\n");
						continue;
					}
				}

				/* FALL THROUGH */

			case DIRECT_QUILLD:
				if (useDB) {
					result2 = getQuillAddrFromCollector(quillName, quillAddr);

					/* if quillAddr is NULL, then while the collector's 
						schedd's ad had a quill name in it, the collector
						didn't have a quill ad by that name. */

					if((result2 == Q_OK) && quillAddr &&
			   			(retval = sqfp(quillAddr, quillName, quillMachine, 
									   NULL, FALSE) ) )
					{
						/* processed correctly, so do the next ad */
						continue;
					}

					/* NOTE: it is not impossible that quillAddr could be
						NULL if the quill name is specified in a schedd ad
						but the collector has no record of such quill ad by
						that name. So we deal with that mess here in the 
						debugging output. */

					fprintf( stderr,
						"-- Quill daemon %s(%s)\n"
						"\tassociated with schedd %s(%s)\n"
						"\tis not reachable or can't talk to rdbms.\n",
						quillName, quillAddr!=NULL?quillAddr:"<\?\?\?>", 
						scheddName, scheddAddr);

					if (quillAddr == NULL) {
						fprintf(stderr,
							"\t- Possible misconfiguration of quill\n"
							"\tassociated with this schedd since associated\n"
							"\tquilld ad is missing and was expected to be\n"
							"\tfound in the collector.\n");
					}

					if (direct == DIRECT_QUILLD) {
						fprintf(stderr,
							"\t- Not failing over due to use of -direct\n");
						continue;
					}

					fprintf(stderr,
						"\t- Failing over to the schedd at %s(%s) --\n",
						scheddName, scheddAddr);

				} else {
					if (direct == DIRECT_QUILLD) {
						fprintf(stderr,
							"-- Direct query to quilld associated with\n"
							"\tschedd %s(%s) failed.\n"
							"\t- Schedd doesn't appear to be using quill.\n",
							scheddName, scheddAddr);
						printf("\t- Not failing over due to use of -direct\n");
						continue;
					}
				}

				/* FALL THROUGH */

#endif /* HAVE_EXT_POSTGRESQL */

			case DIRECT_SCHEDD:
				/* database not configured or could not be reached,
					query the schedd daemon directly */
				retval = sqfp(scheddAddr, scheddName, scheddMachine, scheddVersion.Value(), FALSE);

				break;

			case DIRECT_UNKNOWN:
			default:
				fprintf( stderr,
					"-- Cannot determine any location for queue "
					"using option -direct!\n"
					"\t- This is an internal error and should be "
					"reported to condor-admin@cs.wisc.edu." );
				exit(EXIT_FAILURE);
				break;
		}
	}

	// close list
	scheddList.Close();

	if( first ) {
		if( global ) {
			printf( "All queues are empty\n" );
		} else {
			fprintf(stderr,"Error: Collector has no record of "
							"schedd/submitter\n");

			freeConnectionStrings();
			exit(1);
		}
	}

	freeConnectionStrings();
	exit(retval?EXIT_SUCCESS:EXIT_FAILURE);
}

// append all variable references made by expression to references list
static void
GetAllReferencesFromClassAdExpr(char const *expression,StringList &references)
{
	ClassAd ad;
	ad.GetExprReferences(expression,references,references);
}

static void 
processCommandLineArguments (int argc, char *argv[])
{
	int i, cluster, proc;
	char *arg, *at, *daemonname;
	const char * pcolon;
	param_functions *p_funcs = NULL;

	bool custom_attributes = false;
	attrs.initializeFromString("ClusterId\nProcId\nQDate\nRemoteUserCPU\nJobStatus\nServerTime\nShadowBday\nRemoteWallClockTime\nJobPrio\nImageSize\nOwner\nCmd\nArgs");

	for (i = 1; i < argc; i++)
	{
		if( *argv[i] != '-' ) {
			// no dash means this arg is a cluster/proc, proc, or owner
			if( sscanf( argv[i], "%d.%d", &cluster, &proc ) == 2 ) {
				sprintf( constraint, "((%s == %d) && (%s == %d))",
					ATTR_CLUSTER_ID, cluster, ATTR_PROC_ID, proc );
                                Q.addOR( constraint );
   
				Q.addDBConstraint(CQ_CLUSTER_ID, cluster);
				Q.addDBConstraint(CQ_PROC_ID, proc);
				summarize = 0;
			} 
			else if( sscanf ( argv[i], "%d", &cluster ) == 1 ) {
				sprintf( constraint, "(%s == %d)", ATTR_CLUSTER_ID, cluster );
				Q.addOR( constraint );
   				Q.addDBConstraint(CQ_CLUSTER_ID, cluster);
				summarize = 0;
			} 
			else if( Q.add( CQ_OWNER, argv[i] ) != Q_OK ) {
				// this error doesn't seem very helpful... can't we say more?
				fprintf( stderr, "Error: Argument %d (%s)\n", i, argv[i] );
				exit( 1 );
			}
			continue;
		}

		// the argument began with a '-', so use only the part after
		// the '-' for prefix matches
		arg = argv[i]+1;

		if (match_prefix (arg, "wide")) {
			widescreen = true;
			continue;
		}
		//if (match_prefix (arg, "unbuf")) {
		//	unbuffered = true;
		//	continue;
		//}
		if (match_prefix (arg, "long")) {
			verbose = 1;
			summarize = 0;
		} 
		else
		if (match_prefix (arg, "xml")) {
			use_xml = 1;
			verbose = 1;
			summarize = 0;
			customFormat = true;
		}
		else
		if (match_prefix (arg, "pool")) {
			if( pool ) {
				delete pool;
			}
            if( ++i >= argc ) {
				fprintf( stderr,
						 "Error: Argument -pool requires a hostname as an argument.\n" );
				if (!expert) {
					printf("\n");
					print_wrapped_text("Extra Info: The hostname should be the central "
									   "manager of the Condor pool you wish to work with.",
									   stderr);
				}
				exit(1);
			}
			pool = new DCCollector( argv[i] );
			if( ! pool->addr() ) {
				fprintf( stderr, "Error: %s\n", pool->error() );
				if (!expert) {
					printf("\n");
					print_wrapped_text("Extra Info: You specified a hostname for a pool "
									   "(the -pool argument). That should be the Internet "
									   "host name for the central manager of the pool, "
									   "but it does not seem to "
									   "be a valid hostname. (The DNS lookup failed.)",
									   stderr);
				}
				exit(1);
			}
			Collectors = new CollectorList();
				// Add a copy of our DCCollector object, because
				// CollectorList() takes ownership and may even delete
				// this object before we are done.
			Collectors->append ( new DCCollector( *pool ) );
		} 
		else
		if (match_prefix (arg, "D")) {
			if( ++i >= argc ) {
				fprintf( stderr, 
						 "Error: Argument -D requires a list of flags as an argument.\n" );
				if (!expert) {
					printf("\n");
					print_wrapped_text("Extra Info: You need to specify debug flags "
									   "as a quoted string. Common flags are D_ALL, and "
									   "D_ALWAYS.",
									   stderr);
				}
				exit( 1 );
			}
			Termlog = 1;
			set_debug_flags( argv[i], 0 );
		} 
		else
		if (match_prefix (arg, "name")) {

			if (querySubmittors) {
				// cannot query both schedd's and submittors
				fprintf (stderr, "Cannot query both schedd's and submitters\n");
				if (!expert) {
					printf("\n");
					print_wrapped_text("Extra Info: You cannot specify both -name and "
									   "-submitter. -name implies you want to only query "
									   "the local schedd, while -submitter implies you want "
									   "to find everything in the entire pool for a given"
									   "submitter.",
									   stderr);
				}
				exit(1);
			}

			// make sure we have at least one more argument
			if (argc <= i+1) {
				fprintf( stderr, 
						 "Error: Argument -name requires the name of a schedd as a parameter.\n" );
				exit(1);
			}

			if( !(daemonname = get_daemon_name(argv[i+1])) ) {
				fprintf( stderr, "Error: unknown host %s\n",
						 get_host_part(argv[i+1]) );
				if (!expert) {
					printf("\n");
					print_wrapped_text("Extra Info: The name given with the -name "
									   "should be the name of a condor_schedd process. "
									   "Normally it is either a hostname, or "
									   "\"name@hostname\". "
									   "In either case, the hostname should be the Internet "
									   "host name, but it appears that it wasn't.",
									   stderr);
				}
				exit(1);
			}
			sprintf (constraint, "%s == \"%s\"", ATTR_NAME, daemonname);
			scheddQuery.addORConstraint (constraint);
			Q.addSchedd(daemonname);

			sprintf (constraint, "%s == \"%s\"", ATTR_QUILL_NAME, daemonname);
			scheddQuery.addORConstraint (constraint);

			delete [] daemonname;
			i++;
			querySchedds = true;
		} 
		else
		if (match_prefix (arg, "direct")) {
			/* check for one more argument */
			if (argc <= i+1) {
				fprintf( stderr, 
					"Error: Argument -direct requires "
						"[rdbms | quilld | schedd]\n" );
				exit(EXIT_FAILURE);
			}
			direct = process_direct_argument(argv[i+1]);
			i++;
		}
		else
		if (match_prefix (arg, "submitter")) {

			if (querySchedds) {
				// cannot query both schedd's and submittors
				fprintf (stderr, "Cannot query both schedd's and submitters\n");
				if (!expert) {
					printf("\n");
					print_wrapped_text("Extra Info: You cannot specify both -name and "
									   "-submitter. -name implies you want to only query "
									   "the local schedd, while -submitter implies you want "
									   "to find everything in the entire pool for a given"
									   "submitter.",
									   stderr);
				}
				exit(1);
			}
			
			// make sure we have at least one more argument
			if (argc <= i+1) {
				fprintf( stderr, "Error: Argument -submitter requires the name of a "
						 "user.\n");
				exit(1);
			}
				
			i++;
			if ((at = strchr(argv[i],'@'))) {
				// is the name already qualified with a UID_DOMAIN?
				sprintf (constraint, "%s == \"%s\"", ATTR_NAME, argv[i]);
				*at = '\0';
			} else {
				// no ... add UID_DOMAIN
				char *uid_domain = param( "UID_DOMAIN" );
				if (uid_domain == NULL)
				{
					EXCEPT ("No 'UID_DOMAIN' found in config file");
				}
				sprintf (constraint, "%s == \"%s@%s\"", ATTR_NAME, argv[i], 
							uid_domain);
				free (uid_domain);
			}

			// insert the constraints
			submittorQuery.addORConstraint (constraint);

			{
				char *ownerName = argv[i];
				// ensure that the "nice-user" prefix isn't inserted as part
				// of the job ad constraint
				if( strstr( argv[i] , NiceUserName ) == argv[i] ) {
					ownerName = argv[i]+strlen(NiceUserName)+1;
				}
				// ensure that the group prefix isn't inserted as part
				// of the job ad constraint.
				char *groups = param("GROUP_NAMES");
				if ( groups && ownerName ) {
					StringList groupList(groups);
					char *dotptr = strchr(ownerName,'.');
					if ( dotptr ) {
						*dotptr = '\0';
						if ( groupList.contains_anycase(ownerName) ) {
							// this name starts with a group prefix.
							// strip it off.
							ownerName = dotptr + 1;	// add one for the '.'
						}
						*dotptr = '.';
					}
				}
				if ( groups ) free(groups);
				if (Q.add (CQ_OWNER, ownerName) != Q_OK) {
					fprintf (stderr, "Error:  Argument %d (%s)\n", i, argv[i]);
					exit (1);
				}
			}

			querySubmittors = true;
		}
		else
		if (match_prefix (arg, "constraint")) {
			// make sure we have at least one more argument
			if (argc <= i+1) {
				fprintf( stderr, "Error: Argument -constraint requires "
							"another parameter\n");
				exit(1);
			}

			if (Q.addAND (argv[++i]) != Q_OK) {
				fprintf (stderr, "Error: Argument %d (%s)\n", i, argv[i]);
				exit (1);
			}
			user_constraint = argv[i];
			summarize = 0;
		} 
		else
		if (match_prefix (arg, "address")) {

			if (querySubmittors) {
				// cannot query both schedd's and submittors
				fprintf (stderr, "Cannot query both schedd's and submitters\n");
				exit(1);
			}

			// make sure we have at least one more argument
			if (argc <= i+1) {
				fprintf( stderr,
						 "Error: Argument -address requires another "
						 "parameter\n" );
				exit(1);
			}
			if( ! is_valid_sinful(argv[i+1]) ) {
				fprintf( stderr, 
					 "Address must be of the form: \"<ip.address:port>\"\n" );
				exit(1);
			}
			sprintf(constraint, "%s == \"%s\"", ATTR_SCHEDD_IP_ADDR, argv[i+1]);
			scheddQuery.addORConstraint(constraint);
			i++;
			querySchedds = true;
		} 
		else
		if( match_prefix( arg, "attributes" ) ) {
			if( argc <= i+1 ) {
				fprintf( stderr, "Error: Argument -attributes requires "
						 "a list of attributes to show\n" );
				exit( 1 );
			}
			if( !custom_attributes ) {
				custom_attributes = true;
				attrs.clearAll();
			}
			StringList more_attrs(argv[i+1],",");
			char const *s;
			more_attrs.rewind();
			while( (s=more_attrs.next()) ) {
				attrs.append(s);
			}
			i++;
		}
		else
		if( match_prefix( arg, "format" ) ) {
				// make sure we have at least two more arguments
			if( argc <= i+2 ) {
				fprintf( stderr, "Error: Argument -format requires "
						 "format and attribute parameters\n" );
				exit( 1 );
			}
			if( !custom_attributes ) {
				custom_attributes = true;
				attrs.clearAll();
				attrs.initializeFromString("ClusterId\nProcId"); // this is needed to prevent some DAG code from faulting.
			}
			GetAllReferencesFromClassAdExpr(argv[i+2],attrs);
				
			customFormat = true;
			mask.registerFormat( argv[i+1], argv[i+2] );
			usingPrintMask = true;
			i+=2;
		}
		else
		if( is_arg_colon_prefix(arg, "autoformat", &pcolon, 5) || 
			is_arg_colon_prefix(arg, "af", &pcolon, 2) ) {
				// make sure we have at least one more argument
			if ( (i+1 >= argc)  || *(argv[i+1]) == '-') {
				fprintf( stderr, "Error: Argument -autoformat requires "
						 "at last one attribute parameter\n" );
				exit( 1 );
			}
			if( !custom_attributes ) {
				custom_attributes = true;
				attrs.clearAll();
				attrs.initializeFromString("ClusterId\nProcId"); // this is needed to prevent some DAG code from faulting.
			}
			bool flabel = false;
			bool fCapV  = false;
			bool fheadings = false;
			bool fJobId = false;
			const char * pcolpre = " ";
			const char * pcolsux = NULL;
			if (pcolon) {
				++pcolon;
				while (*pcolon) {
					switch (*pcolon)
					{
						case ',': pcolsux = ","; break;
						case 'n': pcolsux = "\n"; break;
						case 't': pcolpre = "\t"; break;
						case 'l': flabel = true; break;
						case 'V': fCapV = true; break;
						case 'h': fheadings = true; break;
						case 'j': fJobId = true; break;
					}
					++pcolon;
				}
			}
			if (fJobId) {
				if (fheadings || mask_head.Length() > 0) {
					mask_head.Append(" ID");
					mask_head.Append(" ");
					mask.registerFormat (flabel ? "ID = %4d." : "%4d.", 5, FormatOptionAutoWidth | FormatOptionNoSuffix, ATTR_CLUSTER_ID);
					mask.registerFormat ("%-3d", 3, FormatOptionAutoWidth | FormatOptionNoPrefix, ATTR_PROC_ID);
				} else {
					mask.registerFormat (flabel ? "ID = %d." : "%d.", 0, FormatOptionNoSuffix, ATTR_CLUSTER_ID);
					mask.registerFormat ("%d", 0, FormatOptionNoPrefix, ATTR_PROC_ID);
				}
			}
			// process all arguments that don't begin with "-" as part
			// of autoformat.
			while (i+1 < argc && *(argv[i+1]) != '-') {
				++i;
				GetAllReferencesFromClassAdExpr(argv[i], attrs);
				MyString lbl = "";
				int wid = 0;
				int opts = FormatOptionNoTruncate;
				if (fheadings || mask_head.Length() > 0) { 
					const char * hd = fheadings ? argv[i] : "(expr)";
					wid = 0 - (int)strlen(hd); 
					opts = FormatOptionAutoWidth | FormatOptionNoTruncate; 
					mask_head.Append(hd);
				}
				else if (flabel) { lbl.sprintf("%s = ", argv[i]); wid = 0; opts = 0; }
				lbl += fCapV ? "%V" : "%v";
				mask.registerFormat(lbl.Value(), wid, opts, argv[i]);
			}
			mask.SetAutoSep(NULL, pcolpre, pcolsux, "\n");
			customFormat = true;
			usingPrintMask = true;
		}
		else
		if (match_prefix (arg, "global")) {
			global = 1;
		} 
		else
		if (match_prefix (arg, "help")) {
			usage(argv[0]);
			exit(0);
		}
        else
        if (match_prefix( arg, "better-analyze")
			|| match_prefix( arg , "better-analyse")
			|| match_prefix( arg , "analyze")
			|| match_prefix( arg , "analyse")
			) {
            better_analyze = true;
			attrs.clearAll();
        }
		else
		if (match_prefix( arg, "run")) {
			std::string expr;
			sprintf( expr, "%s == %d || %s == %d || %s == %d", ATTR_JOB_STATUS, RUNNING,
					 ATTR_JOB_STATUS, TRANSFERRING_OUTPUT, ATTR_JOB_STATUS, SUSPENDED );
			Q.addAND( expr.c_str() );
			run = true;
			attrs.append( ATTR_REMOTE_HOST );
			attrs.append( ATTR_JOB_UNIVERSE );
			attrs.append( ATTR_EC2_REMOTE_VM_NAME ); // for displaying HOST(s) in EC2
		}
		else
		if (match_prefix( arg, "hold") || match_prefix( arg, "held")) {
			Q.add (CQ_STATUS, HELD);		
			show_held = true;
			widescreen = true;
			attrs.append( ATTR_ENTERED_CURRENT_STATUS );
			attrs.append( ATTR_HOLD_REASON );
		}
		else
		if (match_prefix( arg, "goodput")) {
			// goodput and show_io require the same column
			// real-estate, so they're mutually exclusive
			goodput = true;
			show_io = false;
			attrs.append( ATTR_JOB_COMMITTED_TIME );
			attrs.append( ATTR_SHADOW_BIRTHDATE );
			attrs.append( ATTR_LAST_CKPT_TIME );
			attrs.append( ATTR_JOB_REMOTE_WALL_CLOCK );
		}
		else
		if (match_prefix( arg, "cputime")) {
			cputime = true;
			JOB_TIME = "CPU_TIME";
		 	attrs.append( ATTR_JOB_REMOTE_USER_CPU );
		}
		else
		if (match_prefix( arg, "currentrun")) {
			current_run = true;
		}
		else
		if (match_prefix( arg, "grid" ) ) {
			// grid is a superset of globus, so we can't do grid if globus has been specifed
			if ( ! globus) {
				dash_grid = true;
				attrs.append( ATTR_GRID_JOB_ID );
				attrs.append( ATTR_GRID_RESOURCE );
				attrs.append( ATTR_GRID_JOB_STATUS );
				attrs.append( ATTR_GLOBUS_STATUS );
				Q.addAND( "JobUniverse == 9" );
			}
		}
		else
		if( match_prefix( arg, "globus" ) ) {
			Q.addAND( "GlobusStatus =!= UNDEFINED" );
			globus = true;
			if (dash_grid) {
				dash_grid = false;
			} else {
				attrs.append( ATTR_GLOBUS_STATUS );
				attrs.append( ATTR_GRID_RESOURCE );
				attrs.append( ATTR_GRID_JOB_STATUS );
				attrs.append( ATTR_GRID_JOB_ID );
			}
		}
		else
		if( match_prefix( arg, "debug" ) ) {
			// dprintf to console
			Termlog = 1;
			p_funcs = get_param_functions();
			dprintf_config ("TOOL", p_funcs);
		}
		else
		if (match_prefix(arg,"io")) {
			// goodput and show_io require the same column
			// real-estate, so they're mutually exclusive
			show_io = true;
			goodput = false;
			attrs.append(ATTR_FILE_READ_BYTES);
			attrs.append(ATTR_FILE_WRITE_BYTES);
			attrs.append(ATTR_FILE_SEEK_COUNT);
			attrs.append(ATTR_JOB_REMOTE_WALL_CLOCK);
			attrs.append(ATTR_BUFFER_SIZE);
			attrs.append(ATTR_BUFFER_BLOCK_SIZE);
		}
		else if( match_prefix( arg, "dag" ) ) {
			dag = true;
			attrs.clearAll();
			if( g_stream_results  ) {
				fprintf( stderr, "-stream-results and -dag are incompatible\n" );
				usage( argv[0] );
				exit( 1 );
			}
		}
		else if (match_prefix(arg, "expert")) {
			expert = true;
			attrs.clearAll();
		}
        else if (match_prefix(arg, "jobads")) {
			if (argc <= i+1) {
				fprintf( stderr, "Error: Argument -jobads require filename\n");
				exit(1);
			} else {
                i++;
                jobads_file = strdup(argv[i]);
            }
        }
        else if (match_prefix(arg, "machineads")) {
			if (argc <= i+1) {
				fprintf( stderr, "Error: Argument -machineads require filename\n");
				exit(1);
			} else {
                i++;
                machineads_file = strdup(argv[i]);
            }
        }
#ifdef HAVE_EXT_POSTGRESQL
		else if (match_prefix(arg, "avgqueuetime")) {
				/* if user want average wait time, we will perform direct DB query */
			avgqueuetime = true;
			directDBquery =  true;
		}
#endif /* HAVE_EXT_POSTGRESQL */
        else if (match_prefix(arg, "version")) {
			printf( "%s\n%s\n", CondorVersion(), CondorPlatform() );
			exit(0);
        }
		else
		if (match_prefix (arg, "stream")) {
			g_stream_results = true;
			if( dag ) {
				fprintf( stderr, "-stream-results and -dag are incompatible\n" );
				usage( argv[0] );
				exit( 1 );
			}
		}
		else {
			fprintf( stderr, "Error: unrecognized argument -%s\n", arg );
			usage(argv[0]);
			exit( 1 );
		}
	}

		//Added so -long or -xml can be listed before other options
	if(verbose && !custom_attributes) {
		attrs.clearAll();
	}
}

static float
job_time(float cpu_time,ClassAd *ad)
{
	if ( cputime ) {
		return cpu_time;
	}

		// here user wants total wall clock time, not cpu time
	int job_status = 0;
	int cur_time = 0;
	int shadow_bday = 0;
	float previous_runs = 0;

	ad->LookupInteger( ATTR_JOB_STATUS, job_status);
	ad->LookupInteger( ATTR_SERVER_TIME, cur_time);
	ad->LookupInteger( ATTR_SHADOW_BIRTHDATE, shadow_bday );
	if ( current_run == false ) {
		ad->LookupFloat( ATTR_JOB_REMOTE_WALL_CLOCK, previous_runs );
	}

		// if we have an old schedd, there is no ATTR_SERVER_TIME,
		// so return a "-1".  This will cause "?????" to show up
		// in condor_q.
	if ( cur_time == 0 ) {
		return -1;
	}

	/* Compute total wall time as follows:  previous_runs is not the 
	 * number of seconds accumulated on earlier runs.  cur_time is the
	 * time from the point of view of the schedd, and shadow_bday is the
	 * epoch time from the schedd's view when the shadow was started for
	 * this job.  So, we figure out the time accumulated on this run by
	 * computing the time elapsed between cur_time & shadow_bday.  
	 * NOTE: shadow_bday is set to zero when the job is RUNNING but the
	 * shadow has not yet started due to JOB_START_DELAY parameter.  And
	 * shadow_bday is undefined (stale value) if the job status is not
	 * RUNNING.  So we only compute the time on this run if shadow_bday
	 * is not zero and the job status is RUNNING.  -Todd <tannenba@cs.wisc.edu>
	 */
	float total_wall_time = previous_runs;
	if ( ( job_status == RUNNING || job_status == TRANSFERRING_OUTPUT || job_status == SUSPENDED) && shadow_bday ) {
		total_wall_time += cur_time - shadow_bday;
	}

	return total_wall_time;
}

unsigned int process_direct_argument(char *arg)
{
#ifdef HAVE_EXT_POSTGRESQL
	if (strcasecmp(arg, "rdbms") == MATCH) {
		return DIRECT_RDBMS;
	}

	if (strcasecmp(arg, "quilld") == MATCH) {
		return DIRECT_QUILLD;
	}

#endif

	if (strcasecmp(arg, "schedd") == MATCH) {
		return DIRECT_SCHEDD;
	}

#ifdef HAVE_EXT_POSTGRESQL
	fprintf( stderr, 
		"Error: Argument -direct requires [rdbms | quilld | schedd]\n" ); 
/*		"Error: Argument -direct requires [rdbms | schedd]\n" ); */
#else
	fprintf( stderr, 
		"Error: Quill feature set is not available.\n"
		"Error: Argument -direct may only take 'schedd' as an option.\n" );
#endif

	exit(EXIT_FAILURE);

	/* Here to make the compiler happy since there is an exit above */
	return DIRECT_UNKNOWN;
}

static void
io_display(ClassAd *ad)
{
	printf("%s", buffer_io_display( ad ) );
}

static char *
buffer_io_display( ClassAd *ad )
{
	int cluster=0, proc=0;
	float read_bytes=0, write_bytes=0, seek_count=0;
	int buffer_size=0, block_size=0;
	float wall_clock=-1;

	char owner[256];

	ad->EvalInteger(ATTR_CLUSTER_ID,NULL,cluster);
	ad->EvalInteger(ATTR_PROC_ID,NULL,proc);
	ad->EvalString(ATTR_OWNER,NULL,owner);

	ad->EvalFloat(ATTR_FILE_READ_BYTES,NULL,read_bytes);
	ad->EvalFloat(ATTR_FILE_WRITE_BYTES,NULL,write_bytes);
	ad->EvalFloat(ATTR_FILE_SEEK_COUNT,NULL,seek_count);
	ad->EvalFloat(ATTR_JOB_REMOTE_WALL_CLOCK,NULL,wall_clock);
	ad->EvalInteger(ATTR_BUFFER_SIZE,NULL,buffer_size);
	ad->EvalInteger(ATTR_BUFFER_BLOCK_SIZE,NULL,block_size);

	sprintf( return_buff, "%4d.%-3d %-14s", cluster, proc,
			 format_owner( owner, ad ) );

	/* If the jobAd values are not set, OR the values are all zero,
	   report no data collected.  This could be true for a vanilla
	   job, or for a standard job that has not checkpointed yet. */

	if(wall_clock<0 || ((read_bytes < 1.0) && (write_bytes < 1.0) && (seek_count < 1.0)) ) {
		strcat(return_buff, "   [ no i/o data collected ]\n");
	} else {
		if(wall_clock < 1.0) wall_clock=1;

		/*
		Note: metric_units() cannot be used twice in the same
		statement -- it returns a pointer to a static buffer.
		*/

		sprintf( return_buff,"%s %8s", return_buff, metric_units(read_bytes) );
		sprintf( return_buff,"%s %8s", return_buff, metric_units(write_bytes) );
		sprintf( return_buff,"%s %8.0f", return_buff, seek_count );
		sprintf( return_buff,"%s %8s/s", return_buff, metric_units((int)((read_bytes+write_bytes)/wall_clock)) );
		sprintf( return_buff,"%s %8s", return_buff, metric_units(buffer_size) );
		sprintf( return_buff,"%s %8s\n", return_buff, metric_units(block_size) );
	}
	return ( return_buff );
}

static void
displayJobShort (ClassAd *ad)
{ 
	printf( "%s", bufferJobShort( ad ) );
}

static char *
bufferJobShort( ClassAd *ad ) {
	int cluster, proc, date, status, prio, image_size, memory_usage;

	char encoded_status;
	int last_susp_time;

	float utime  = 0.0;
	char owner[64];
	char *cmd = NULL;
	MyString buffer;

	if (!ad->EvalInteger (ATTR_CLUSTER_ID, NULL, cluster)		||
		!ad->EvalInteger (ATTR_PROC_ID, NULL, proc)				||
		!ad->EvalInteger (ATTR_Q_DATE, NULL, date)				||
		!ad->EvalFloat   (ATTR_JOB_REMOTE_USER_CPU, NULL, utime)||
		!ad->EvalInteger (ATTR_JOB_STATUS, NULL, status)		||
		!ad->EvalInteger (ATTR_JOB_PRIO, NULL, prio)			||
		!ad->EvalInteger (ATTR_IMAGE_SIZE, NULL, image_size)	||
		!ad->EvalString  (ATTR_OWNER, NULL, owner)				||
		!ad->EvalString  (ATTR_JOB_CMD, NULL, &cmd) )
	{
		sprintf (return_buff, " --- ???? --- \n");
		return( return_buff );
	}
	
	// print memory usage unless it's unavailable, then print image size
	// note that memory usage is megabytes but imagesize is kilobytes.
	double memory_used_mb = image_size / 1024.0;
	if (ad->EvalInteger(ATTR_MEMORY_USAGE, NULL, memory_usage)) {
		memory_used_mb = memory_usage;
	}

	MyString args_string;
	ArgList::GetArgsStringForDisplay(ad,&args_string);
	if (!args_string.IsEmpty()) {
		buffer.sprintf( "%s %s", condor_basename(cmd), args_string.Value() );
	} else {
		buffer.sprintf( "%s", condor_basename(cmd) );
	}
	free(cmd);
	utime = job_time(utime,ad);

	encoded_status = encode_status( status );

	/* The suspension of a job is a second class citizen and is not a true
		status that can exist as a job status ad and is instead
		inferred, so therefore the processing and display of
		said suspension is also second class. */
	if (param_boolean("REAL_TIME_JOB_SUSPEND_UPDATES", false)) {
			if (!ad->EvalInteger(ATTR_LAST_SUSPENSION_TIME,NULL,last_susp_time))
			{
				last_susp_time = 0;
			}
			/* sanity check the last_susp_time against if the job is running
				or not in case the schedd hasn't synchronized the
				last suspension time attribute correctly to job running
				boundaries. */
			if ( status == RUNNING && last_susp_time != 0 )
			{
				encoded_status = 'S';
			}
	}

	sprintf( return_buff,
			 widescreen ? "%4d.%-3d %-14s %-11s %-12s %-2c %-3d %-4.1f %s\n"
			            : "%4d.%-3d %-14s %-11s %-12s %-2c %-3d %-4.1f %-18.18s\n",
			 cluster,
			 proc,
			 format_owner( owner, ad ),
			 format_date( (time_t)date ),
			 /* In the next line of code there is an (int) typecast. This
			 	has to be there otherwise the compiler produces incorrect code
				here and performs a structural typecast from the float to an
				int(like how a union works) and passes a garbage number to the
				format_time function. The compiler is *supposed* to do a
				functional typecast, meaning generate code that changes the
				float to an int legally. Apparently, that isn't happening here.
				-psilord 09/06/01 */
			 format_time( (int)utime ),
			 encoded_status,
			 prio,
			 memory_used_mb,
			 buffer.Value() );

	return return_buff;
}

static void 
short_header (void)
{
	printf( " %-7s %-14s ", "ID", dag ? "OWNER/NODENAME" : "OWNER" );
	if( goodput ) {
		printf( "%11s %12s %-16s\n", "SUBMITTED", JOB_TIME,
				"GOODPUT CPU_UTIL   Mb/s" );
	} else if ( globus ) {
		printf( "%-10s %-8s %-18s  %-18s\n", 
				"STATUS", "MANAGER", "HOST", "EXECUTABLE" );
	} else if ( dash_grid ) {
		printf( "%-10s  %-16s %-16s  %-18s\n", 
				"STATUS", "GRID->MANAGER", "HOST", "GRID-JOB-ID" );
	} else if ( show_held ) {
		printf( "%11s %-30s\n", "HELD_SINCE", "HOLD_REASON" );
	} else if ( show_io ) {
		printf( "%8s %8s %8s %10s %8s %8s\n",
				"READ", "WRITE", "SEEK", "XPUT", "BUFSIZE", "BLKSIZE" );
	} else if( run ) {
		printf( "%11s %12s %-16s\n", "SUBMITTED", JOB_TIME, "HOST(S)" );
	} else {
		printf( "%11s %12s %-2s %-3s %-4s %-18s\n",
			"SUBMITTED",
			JOB_TIME,
			"ST",
			"PRI",
			"SIZE",
			"CMD"
		);
	}
}

static char *
format_remote_host (char *, AttrList *ad)
{
	static char host_result[MAXHOSTNAMELEN];
	static char unknownHost [] = "[????????????????]";
	condor_sockaddr addr;

	int universe = CONDOR_UNIVERSE_STANDARD;
	ad->LookupInteger( ATTR_JOB_UNIVERSE, universe );
	if (universe == CONDOR_UNIVERSE_SCHEDULER &&
		addr.from_sinful(scheddAddr) == true) {
		MyString hostname = get_hostname(addr);
		if (hostname.Length() > 0) {
			strcpy( host_result, hostname.Value() );
			return host_result;
		} else {
			return unknownHost;
		}
	} else if (universe == CONDOR_UNIVERSE_GRID) {
		if (ad->LookupString(ATTR_GRID_RESOURCE,host_result) == 1 )
			return host_result;
		else if (ad->LookupString(ATTR_EC2_REMOTE_VM_NAME,host_result) == 1)
			return host_result;
		else
			return unknownHost;
	}

	if (ad->LookupString(ATTR_REMOTE_HOST, host_result) == 1) {
		if( is_valid_sinful(host_result) && 
			addr.from_sinful(host_result) == true ) {
			MyString hostname = get_hostname(addr);
			if (hostname.Length() > 0) {
				strcpy(host_result, hostname.Value());
			} else {
				return unknownHost;
			}
		}
		return host_result;
	}
	return unknownHost;
}

static const char *
format_cpu_time (float utime, AttrList *ad)
{
	return format_time( (int) job_time(utime,(ClassAd *)ad) );
}

static const char *
format_goodput (int job_status, AttrList *ad)
{
	static char put_result[9];
	int ckpt_time = 0, shadow_bday = 0, last_ckpt = 0;
	float wall_clock = 0.0;
	ad->LookupInteger( ATTR_JOB_COMMITTED_TIME, ckpt_time );
	ad->LookupInteger( ATTR_SHADOW_BIRTHDATE, shadow_bday );
	ad->LookupInteger( ATTR_LAST_CKPT_TIME, last_ckpt );
	ad->LookupFloat( ATTR_JOB_REMOTE_WALL_CLOCK, wall_clock );
	if ((job_status == RUNNING || job_status == TRANSFERRING_OUTPUT || job_status == SUSPENDED) &&
		shadow_bday && last_ckpt > shadow_bday)
	{
		wall_clock += last_ckpt - shadow_bday;
	}
	if (wall_clock <= 0.0) return " [?????]";
	float goodput_time = ckpt_time/wall_clock*100.0;
	if (goodput_time > 100.0) goodput_time = 100.0;
	else if (goodput_time < 0.0) return " [?????]";
	sprintf(put_result, " %6.1f%%", goodput_time);
	return put_result;
}

static const char *
format_mbps (float bytes_sent, AttrList *ad)
{
	static char result_format[10];
	float wall_clock=0.0, bytes_recvd=0.0, total_mbits;
	int shadow_bday = 0, last_ckpt = 0, job_status = IDLE;
	ad->LookupFloat( ATTR_JOB_REMOTE_WALL_CLOCK, wall_clock );
	ad->LookupInteger( ATTR_SHADOW_BIRTHDATE, shadow_bday );
	ad->LookupInteger( ATTR_LAST_CKPT_TIME, last_ckpt );
	ad->LookupInteger( ATTR_JOB_STATUS, job_status );
	if ((job_status == RUNNING || job_status == TRANSFERRING_OUTPUT || job_status == SUSPENDED) && shadow_bday && last_ckpt > shadow_bday) {
		wall_clock += last_ckpt - shadow_bday;
	}
	ad->LookupFloat(ATTR_BYTES_RECVD, bytes_recvd);
	total_mbits = (bytes_sent+bytes_recvd)*8/(1024*1024); // bytes to mbits
	if (total_mbits <= 0) return " [????]";
	sprintf(result_format, " %6.2f", total_mbits/wall_clock);
	return result_format;
}

static const char *
format_cpu_util (float utime, AttrList *ad)
{
	static char result_format[10];
	int ckpt_time = 0;
	ad->LookupInteger( ATTR_JOB_COMMITTED_TIME, ckpt_time);
	if (ckpt_time == 0) return " [??????]";
	float util = utime/ckpt_time*100.0;
	if (util > 100.0) util = 100.0;
	else if (util < 0.0) return " [??????]";
	sprintf(result_format, "  %6.1f%%", util);
	return result_format;
}

static const char *
format_owner_common (char *owner, AttrList *ad)
{
	static char result_str[100] = "";

	// [this is a somewhat kludgey place to implement DAG formatting,
	// but for a variety of reasons (maintainability, allowing future
	// changes to be made in only one place, etc.), Todd & I decided
	// it's the best way to do it given the existing code...  --pfc]

	// if -dag is specified, check whether this job was started by a
	// DAGMan (by seeing if it has a valid DAGManJobId attribute), and
	// if so, print DAGNodeName in place of owner

	// (we need to check that the DAGManJobId is valid because DAGMan
	// >= v6.3 inserts "unknown..." into DAGManJobId when run under a
	// pre-v6.3 schedd)

	if ( dag && ad->LookupExpr( ATTR_DAGMAN_JOB_ID ) ) {
			// We have a DAGMan job ID, this means we have a DAG node
			// -- don't worry about what type the DAGMan job ID is.
		if ( ad->LookupString( ATTR_DAG_NODE_NAME, result_str, COUNTOF(result_str) ) ) {
			return result_str;
		} else {
			fprintf(stderr, "DAG node job with no %s attribute!\n",
					ATTR_DAG_NODE_NAME);
		}
	}

	int niceUser;
	if (ad->LookupInteger( ATTR_NICE_USER, niceUser) && niceUser ) {
		char tmp[100];
		strncpy(tmp,NiceUserName,80);
		strcat(tmp, ".");
		strcat(tmp, owner);
		owner = tmp;
	} else {
	}
	strcpy_len(result_str, owner, COUNTOF(result_str));
	return result_str;
}

static const char *
format_owner (char *owner, AttrList *ad)
{
	static char result_format[24];
	sprintf(result_format, "%-14.14s", format_owner_common(owner, ad));
	return result_format;
}

static const char *
format_owner_wide (char *owner, AttrList *ad, Formatter & /*fmt*/)
{
	return format_owner_common(owner, ad);
}

static const char *
format_globusStatus( int globusStatus, AttrList * /* ad */ )
{
	static char result_str[64];
#if defined(HAVE_EXT_GLOBUS)
	sprintf(result_str, " %7.7s", GlobusJobStatusName( globusStatus ) );
#else
	static const struct {
		int status;
		const char * psz;
	} gram_states[] = {
		{ 1, "PENDING" },	 //GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING = 1,
		{ 2, "ACTIVE" },	 //GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE = 2,
		{ 4, "FAILED" },	 //GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED = 4,
		{ 8, "DONE" },	 //GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE = 8,
		{16, "SUSPEND" },	 //GLOBUS_GRAM_PROTOCOL_JOB_STATE_SUSPENDED = 16,
		{32, "UNSUBMIT" },	 //GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED = 32,
		{64, "STAGE_IN" },	 //GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_IN = 64,
		{128,"STAGE_OUT" },	 //GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_OUT = 128,
	};
	for (size_t ii = 0; ii < COUNTOF(gram_states); ++ii) {
		if (globusStatus == gram_states[ii].status) {
			return gram_states[ii].psz;
		}
	}
	sprintf(result_str, "%d", globusStatus);
#endif
	return result_str;
}

// The remote hostname may be in GlobusResource or GridResource.
// We want this function to be called if at least one is defined,
// but it will only be called if the one attribute it's registered
// with is defined. So we register it with an attribute we know will
// always be present and be a string. We then ignore that attribute
// and examine GlobusResource and GridResource.
static const char *
format_globusHostAndJM( char *, AttrList *ad )
{
	static char result_format[64];
	char	host[80] = "[?????]";
	char	jm[80] = "fork";
	char	*tmp;
	int	p;
	char *attr_value = NULL;
	char *resource_name = NULL;
	char *grid_type = NULL;

	if ( ad->LookupString( ATTR_GRID_RESOURCE, &attr_value ) ) {
			// If ATTR_GRID_RESOURCE exists, skip past the initial
			// '<job type> '.
		resource_name = strchr( attr_value, ' ' );
		if ( resource_name ) {
			*resource_name = '\0';
			grid_type = strdup( attr_value );
			resource_name++;
		}
	}

	if ( resource_name != NULL ) {

		if ( grid_type == NULL || !strcasecmp( grid_type, "gt2" ) ||
			 !strcasecmp( grid_type, "gt5" ) ||
			 !strcasecmp( grid_type, "globus" ) ) {

			// copy the hostname
			p = strcspn( resource_name, ":/" );
			if ( p >= (int) sizeof(host) )
				p = sizeof(host) - 1;
			strncpy( host, resource_name, p );
			host[p] = '\0';

			if ( ( tmp = strstr( resource_name, "jobmanager-" ) ) != NULL ) {
				tmp += 11; // 11==strlen("jobmanager-")

				// copy the jobmanager name
				p = strcspn( tmp, ":" );
				if ( p >= (int) sizeof(jm) )
					p = sizeof(jm) - 1;
				strncpy( jm, tmp, p );
				jm[p] = '\0';
			}

		} else if ( !strcasecmp( grid_type, "gt4" ) ) {

			strcpy( jm, "Fork" );

				// GridResource is of the form '<service url> <jm type>'
				// Find the space, zero it out, and grab the jm type from
				// the end (if it's non-empty).
			tmp = strchr( resource_name, ' ' );
			if ( tmp ) {
				*tmp = '\0';
				if ( tmp[1] != '\0' ) {
					strcpy( jm, &tmp[1] );
				}
			}

				// Pick the hostname out of the URL
			if ( strncmp( "https://", resource_name, 8 ) == 0 ) {
				strncpy( host, &resource_name[8], sizeof(host) );
				host[sizeof(host)-1] = '\0';
			} else {
				strncpy( host, resource_name, sizeof(host) );
				host[sizeof(host)-1] = '\0';
			}
			p = strcspn( host, ":/" );
			host[p] = '\0';
		}
	}

	if ( grid_type ) {
		free( grid_type );
	}

	if ( attr_value ) {
		free( attr_value );
	}

	// done --- pack components into the result string and return
	sprintf( result_format, " %-8.8s %-18.18s  ", jm, host );
	return( result_format );
}

static const char *
format_gridStatus( int jobStatus, AttrList * ad, Formatter & /*fmt*/ )
{
	static char result_str[32];
	if (ad->LookupString( ATTR_GRID_JOB_STATUS, result_str, COUNTOF(result_str) )) {
		return result_str;
	} 
	int globusStatus = 0;
	if (ad->LookupInteger( ATTR_GLOBUS_STATUS, globusStatus )) {
		return format_globusStatus(globusStatus, ad);
	} 
	static const struct {
		int status;
		const char * psz;
	} states[] = {
		{ IDLE, "IDLE" },
		{ RUNNING, "RUNNING" },
		{ COMPLETED, "COMPLETED" },
		{ HELD, "HELD" },
		{ SUSPENDED, "SUSPENDED" },
		{ REMOVED, "REMOVED" },
		{ TRANSFERRING_OUTPUT, "XFER_OUT" },
	};
	for (size_t ii = 0; ii < COUNTOF(states); ++ii) {
		if (jobStatus == states[ii].status) {
			return states[ii].psz;
		}
	}
	sprintf(result_str, "%d", jobStatus);
	return result_str;
}

#if 0 // not currently used, disabled to shut up fedora.
static const char *
format_gridType( int , AttrList * ad )
{
	static char result[64];
	char grid_res[64];
	if (ad->LookupString( ATTR_GRID_RESOURCE, grid_res, COUNTOF(grid_res) )) {
		char * p = result;
		char * r = grid_res;
		*p++ = ' ';
		while (*r && *r != ' ') {
			*p++ = *r++;
		}
		while (p < &result[5]) *p++ = ' ';
		*p++ = 0;
	} else {
		strcpy_len(result, "   ?  ", sizeof(result));
	}
	return result;
}
#endif

static const char *
format_gridResource( char * grid_res, AttrList * /*ad*/, Formatter & /*fmt*/ )
{
	std::string grid_type;
	std::string str = grid_res;
	std::string mgr = "[?]";
	std::string host = "[???]";
	const bool fshow_host_port = false;
	const unsigned int width = 1+6+1+8+1+18+1;

	// GridResource is a string with the format 
	//      "type host_url manager" (where manager can contain whitespace)
	// or   "type host_url/jobmanager-manager"
	unsigned int ixHost = str.find_first_of(' ');
	if (ixHost < str.length()) {
		grid_type = str.substr(0, ixHost);
		ixHost += 1; // skip over space.
	} else {
		grid_type = "globus";
		ixHost = 0;
	}

	//if ((MATCH == grid_type.find("gt")) || (MATCH == grid_type.compare("globus"))){
	//	return format_globusHostAndJM( grid_res, ad );
	//}

	unsigned int ix2 = str.find_first_of(' ', ixHost);
	if (ix2 < str.length()) {
		mgr = str.substr(ix2+1);
	} else {
		unsigned int ixMgr = str.find("jobmanager-", ixHost);
		if (ixMgr < str.length()) 
			mgr = str.substr(ixMgr+11);	//sizeof("jobmanager-") == 11
		ix2 = ixMgr;
	}

	unsigned int ix3 = str.find("://", ixHost);
	ix3 = (ix3 < str.length()) ? ix3+3 : ixHost;
	unsigned int ix4 = str.find_first_of(fshow_host_port ? "/" : ":/",ix3);
	if (ix4 > ix2) ix4 = ix2;
	host = str.substr(ix3, ix4-ix3);

	MyString mystr = mgr.c_str();
	mystr.replaceString(" ", "/");
	mgr = mystr.Value();

	static char result_str[1024];
	//sprintf(result, " %-6.6s %-8.8s %-18.18s  ", grid_type.c_str(), mgr.c_str(), host.c_str());
	//sprintf(result, " %-6s %-8s %18s  ", grid_type.c_str(), mgr.c_str(), host.c_str());
	sprintf(result_str, "%s->%s %s", grid_type.c_str(), mgr.c_str(), host.c_str());
	ix2 = strlen(result_str);
	/*
	while (ix2 < width) {
		result[ix2++] = ' ';
		result[ix2] = 0;
	}
	*/
	if ( ! widescreen) ix2 = width;
	//result[ix2++] = ' ';
	result_str[ix2] = 0;
	return result_str;
}

static const char *
format_gridJobId( char * grid_jobid, AttrList *ad, Formatter & /*fmt*/ )
{
	std::string str = grid_jobid;
	std::string jid;
	std::string host;

	std::string grid_type = "globus";
	char grid_res[64];
	if (ad->LookupString( ATTR_GRID_RESOURCE, grid_res, COUNTOF(grid_res) )) {
		char * r = grid_res;
		while (*r && *r != ' ') {
			++r;
		}
		*r = 0;
		grid_type = grid_res;
	}
	bool gram = (MATCH == grid_type.compare("gt5")) || (MATCH == grid_type.compare("gt2"));

	unsigned int ix2 = str.find_last_of(" ");
	ix2 = (ix2 < str.length()) ? ix2 + 1 : 0;

	unsigned int ix3 = str.find("://", ix2);
	ix3 = (ix3 < str.length()) ? ix3+3 : ix2;
	unsigned int ix4 = str.find_first_of("/",ix3);
	ix4 = (ix4 < str.length()) ? ix4 : ix3;
	host = str.substr(ix3, ix4-ix3);

	if (gram) {
		jid += host;
		jid += " : ";
		if (str[ix4] == '/') ix4 += 1;
		unsigned int ix5 = str.find_first_of("/",ix4);
		jid = str.substr(ix4, ix5-ix4);
		if (ix5 < str.length()) {
			if (str[ix5] == '/') ix5 += 1;
			unsigned int ix6 = str.find_first_of("/",ix5);
			jid += ".";
			jid += str.substr(ix5, ix6-ix5);
		}
	} else {
		//jid = grid_type;
		//jid += " : ";
		jid += str.substr(ix4);
	}

	static char result_str[1024];
	sprintf(result_str, "%s", jid.c_str());
	return result_str;
}

static const char *
format_q_date (int d, AttrList *)
{
	return format_date(d);
}

		
static void
usage (const char *myName)
{
	printf ("Usage: %s [options]\n\twhere [options] are\n"
		"\t\t-global\t\t\tGet global queue\n"
		"\t\t-debug\t\t\tDisplay debugging info to console\n"
		"\t\t-submitter <submitter>\tGet queue of specific submitter\n"
		"\t\t-help\t\t\tThis screen\n"
		"\t\t-name <name>\t\tName of schedd\n"
		"\t\t-pool <host>\t\tUse host as the central manager to query\n"
		"\t\t-long\t\t\tVerbose output (entire classads)\n"
		"\t\t-wide\t\t\tWidescreen output\n"
		"\t\t-xml\t\t\tDisplay entire classads, but in XML\n"
		"\t\t-attributes X,Y,...\tAttributes to show in -xml and -long\n"
		"\t\t-format <fmt> <attr>\tPrint attribute attr using format fmt\n"
		"\t\t-analyze\t\tPerform schedulability analysis on jobs\n"
		"\t\t-run\t\t\tGet information about running jobs\n"
		"\t\t-hold\t\t\tGet information about jobs on hold\n"
		"\t\t-globus\t\t\tGet information about Condor-G jobs of type globus\n"
		"\t\t-goodput\t\tDisplay job goodput statistics\n"	
		"\t\t-cputime\t\tDisplay CPU_TIME instead of RUN_TIME\n"
		"\t\t-currentrun\t\tDisplay times only for current run\n"
		"\t\t-io\t\t\tShow information regarding I/O\n"
		"\t\t-dag\t\t\tSort DAG jobs under their DAGMan\n"
		"\t\t-expert\t\t\tDisplay shorter error messages\n"
		"\t\t-constraint <expr>\tAdd constraint on classads\n"
		"\t\t-jobads <file>\t\tFile of job ads to display\n"
		"\t\t-machineads <file>\tFile of machine ads for analysis\n"
#ifdef HAVE_EXT_POSTGRESQL
		"\t\t-direct <rdbms | schedd>\n"
		"\t\t\tPerform a direct query to the rdbms\n"
		"\t\t\tor to the schedd without falling back to the queue\n"
		"\t\t\tlocation discovery algortihm, even in case of error\n"
		"\t\t-avgqueuetime\t\tAverage queue time for uncompleted jobs\n"
#endif
		"\t\t-stream-results \tProduce output as ads are fetched\n"
		"\t\t-version\t\tPrint the Condor Version and exit\n"
		"\t\trestriction list\n"
		"\twhere each restriction may be one of\n"
		"\t\t<cluster>\t\tGet information about specific cluster\n"
		"\t\t<cluster>.<proc>\tGet information about specific job\n"
		"\t\t<owner>\t\t\tInformation about jobs owned by <owner>\n",
			myName);
}

void full_header(bool useDB,char const *quill_name,char const *db_ipAddr, char const *db_name,char const *lastUpdate, char const *scheddName, char const *scheddAddress,char const *scheddMachine)
{
	if (! customFormat && !verbose ) {
		if (useDB) {
			printf ("\n\n-- Quill: %s : %s : %s : %s\n", quill_name, 
					db_ipAddr, db_name, lastUpdate);
		} else if( querySchedds ) {
			printf ("\n\n-- Schedd: %s : %s\n", scheddName, scheddAddress);
		} else {
			printf ("\n\n-- Submitter: %s : %s : %s\n", scheddName, 
					scheddAddress, scheddMachine);	
		}
			// Print the output header
		if (usingPrintMask && mask_head.Length() > 0) {
#if 0
			if (mask_headings) {
				List<const char> headings;
				const char * pszz = mask_headings;
				size_t cch = strlen(pszz);
				while (cch > 0) {
					headings.Append(pszz);
					pszz += cch+1;
					cch = strlen(pszz);
				}
				mask.display_Headings(stdout, headings);
			} else 
#endif
			mask.display_Headings(stdout, mask_head);
		} else {
			short_header();
		}
	}
	if (customFormat && mask_head.Length() > 0) {
		mask.display_Headings(stdout, mask_head);
	}
	if( use_xml ) {
			// keep this consistent with AttrListList::fPrintAttrListList()
		ClassAdXMLUnparser  unparser;
		MyString xml;
		unparser.SetUseCompactSpacing(false);
		unparser.AddXMLFileHeader(xml);
		printf("%s\n", xml.Value());
	}
}

void edit_string(clusterProcString *cps)
{
	if(!cps->parent) {
		return;	// Nothing to do
	}
	std::string s;
	int generations = 0;
	for( clusterProcString* ccps = cps->parent; ccps; ccps = ccps->parent ) {
		++generations;
	}
	int state = 0;
	for(const char* p = cps->string; *p;){
		switch(state) {
		case 0:
			if(!isspace(*p)){
				state = 1;
			} else {
				s += *p;
				++p;
			}
			break;
		case 1:
			if(isspace(*p)){
				state = 2;
			} else {
				s += *p;
				++p;
			}
			break;
		case 2: if(isspace(*p)){
				s+=*p;
				++p;
			} else {
				for(int i=0;i<generations;++i){
					s+=' ';
				}
				s +="|-";
				state = 3;
			}
			break;
		case 3:
			if(isspace(*p)){
				state = 4;
			} else {
				s += *p;
				++p;	
			}
			break;
		case 4:
			int gen_i;
			for(gen_i=0;gen_i<=generations+1;++gen_i){
				if(isspace(*p)){
					++p;
				} else {
					break;
				}
			}
			if( gen_i < generations || !isspace(*p) ) {
				std::string::iterator sp = s.end();
				--sp;
				*sp = ' ';
			}
			state = 5;
			break;
		case 5:
			s += *p;
			++p;
			break;
		}
	}
	char* cpss = cps->string;
	cps->string = strnewp( s.c_str() );
	delete[] cpss;
}

void write_node(clusterProcString* cps,int level)
{
	if(cps->parent && level <= 0){
		return;
	}
	printf("%s",cps->string);
	for(std::vector<clusterProcString*>::iterator p = cps->children.begin();
			p != cps->children.end(); ++p) {
		write_node(*p,level+1);
	}
}


static void init_output_mask()
{
	// just  in case we re-enter this function, only setup the mask once
	static bool	setup_mask = false;
	// TJ: before my 2012 refactoring setup_mask didn't protect summarize, so I'm preserving that.
	if ( run || goodput || globus || dash_grid ) 
		summarize = false;
	else if (customFormat && ! show_held)
		summarize = false;

	if (setup_mask)
		return;
	setup_mask = true;

	int console_width = getConsoleWindowSize();

	const char * mask_headings = NULL;

	if ( run || goodput ) {
		//mask.SetAutoSep("<","{","},",">\n"); // for testing.
		mask.SetAutoSep(NULL," ",NULL,"\n");
		mask.registerFormat ("%4d.", 5, FormatOptionAutoWidth | FormatOptionNoSuffix, ATTR_CLUSTER_ID);
		mask.registerFormat ("%-3d", 3, FormatOptionAutoWidth | FormatOptionNoPrefix, ATTR_PROC_ID);
		mask.registerFormat (NULL, -14, 0, format_owner_wide, ATTR_OWNER, "[????????????]" );
		//mask.registerFormat(" ", "*bogus*", " ");  // force space
		mask.registerFormat (NULL,  11, 0, (IntCustomFmt) format_q_date, ATTR_Q_DATE, "[????????????]");
		//mask.registerFormat(" ", "*bogus*", " ");  // force space
		mask.registerFormat (NULL,  12, 0, (FloatCustomFmt) format_cpu_time,
							  ATTR_JOB_REMOTE_USER_CPU,
							  "[??????????]");
		if( run && !goodput ) {
			mask_headings = (cputime) ? " ID\0 \0OWNER\0  SUBMITTED\0    CPU_TIME\0HOST(S)\0"
			                          : " ID\0 \0OWNER\0. SUBMITTED\0    RUN_TIME\0HOST(S)\0";
			//mask.registerFormat(" ", "*bogus*", " "); // force space
			// We send in ATTR_OWNER since we know it is always
			// defined, and we need to make sure
			// format_remote_host() is always called. We are
			// actually displaying ATTR_REMOTE_HOST if defined,
			// but we play some tricks if it isn't defined.
			mask.registerFormat ( (StringCustomFmt) format_remote_host,
								  ATTR_OWNER, "[????????????????]");
		} else {			// goodput
			mask_headings = (cputime) ? " ID\0 \0OWNER\0  SUBMITTED\0    CPU_TIME\0GOODPUT\0CPU_UTIL\0Mb/s\0"
			                          : " ID\0 \0OWNER\0  SUBMITTED\0    RUN_TIME\0GOODPUT\0CPU_UTIL\0Mb/s\0";
			mask.registerFormat (NULL, 8, 0, (IntCustomFmt) format_goodput,
								  ATTR_JOB_STATUS,
								  "[?????]");
			mask.registerFormat (NULL, 9, 0, (FloatCustomFmt) format_cpu_util,
								  ATTR_JOB_REMOTE_USER_CPU,
								  "[??????]");
			mask.registerFormat (NULL, 7, 0, (FloatCustomFmt) format_mbps,
								  ATTR_BYTES_SENT,
								  "[????]");
		}
		//mask.registerFormat("\n", "*bogus*", "\n");  // force newline
		usingPrintMask = true;
	} else if( globus ) {
		mask_headings = " ID\0 \0OWNER\0STATUS\0MANAGER     HOST\0EXECUTABLE\0";
		mask.SetAutoSep(NULL," ",NULL,"\n");
		mask.registerFormat ("%4d.", 5, FormatOptionAutoWidth | FormatOptionNoSuffix, ATTR_CLUSTER_ID);
		mask.registerFormat ("%-3d", 3, FormatOptionAutoWidth | FormatOptionNoPrefix,  ATTR_PROC_ID);
		mask.registerFormat (NULL, -14, 0, format_owner_wide, ATTR_OWNER, "[?]" );
		mask.registerFormat(NULL, -8, 0, (IntCustomFmt) format_globusStatus, ATTR_GLOBUS_STATUS, "[?]" );
		if (widescreen) {
			mask.registerFormat(NULL, -30, FormatOptionAutoWidth | FormatOptionNoTruncate, 
				(StringCustomFmt)format_globusHostAndJM, ATTR_GRID_RESOURCE, "fork    [?????]" );
			mask.registerFormat("%v", -18, FormatOptionAutoWidth | FormatOptionNoTruncate, ATTR_JOB_CMD );
		} else {
			mask.registerFormat(NULL, 30, 0, 
				(StringCustomFmt)format_globusHostAndJM, ATTR_JOB_CMD, "fork    [?????]" );
			mask.registerFormat("%-18.18s", ATTR_JOB_CMD);
		}
		usingPrintMask = true;
	} else if( dash_grid ) {
		mask_headings = " ID\0 \0OWNER\0STATUS\0GRID->MANAGER    HOST\0GRID_JOB_ID\0";
		//mask.SetAutoSep("<","{","},",">\n"); // for testing.
		mask.SetAutoSep(NULL," ",NULL,"\n");
		mask.registerFormat ("%4d.", 5, FormatOptionAutoWidth | FormatOptionNoSuffix, ATTR_CLUSTER_ID);
		mask.registerFormat ("%-3d", 3, FormatOptionAutoWidth | FormatOptionNoPrefix, ATTR_PROC_ID);
		if (widescreen) {
			int excess = (console_width - (8+1 + 14+1 + 10+1 + 27+1 + 16));
			int w2 = 27 + MAX(0, (excess-8)/3);
			mask.registerFormat (NULL, -14, FormatOptionAutoWidth | FormatOptionNoTruncate, format_owner_wide, ATTR_OWNER);
			mask.registerFormat (NULL, -10, FormatOptionAutoWidth | FormatOptionNoTruncate, format_gridStatus, ATTR_JOB_STATUS);
			mask.registerFormat (NULL, -w2, FormatOptionAutoWidth | FormatOptionNoTruncate, format_gridResource, ATTR_GRID_RESOURCE);
			mask.registerFormat (NULL, 0, FormatOptionNoTruncate, format_gridJobId, ATTR_GRID_JOB_ID);
		} else {
			mask.registerFormat (NULL, -14, 0, format_owner_wide, ATTR_OWNER);
			mask.registerFormat (NULL, -10,0, format_gridStatus, ATTR_JOB_STATUS);
			mask.registerFormat ("%-27.27s", 0,0, format_gridResource, ATTR_GRID_RESOURCE);
			mask.registerFormat ("%-16.16s", 0,0, format_gridJobId, ATTR_GRID_JOB_ID);
		}
		usingPrintMask = true;
	} else if ( show_held ) {
		mask_headings = " ID\0 \0OWNER\0HELD_SINCE\0HOLD_REASON\0";
		mask.SetAutoSep(NULL," ",NULL,"\n");
		mask.registerFormat ("%4d.", 5, FormatOptionAutoWidth | FormatOptionNoSuffix, ATTR_CLUSTER_ID);
		mask.registerFormat ("%-3d", 3, FormatOptionAutoWidth | FormatOptionNoPrefix, ATTR_PROC_ID);
		mask.registerFormat (NULL, -14, 0, format_owner_wide, ATTR_OWNER, "[????????????]" );
		//mask.registerFormat(" ", "*bogus*", " ");  // force space
		mask.registerFormat (NULL, 11, 0, (IntCustomFmt) format_q_date,
							  ATTR_ENTERED_CURRENT_STATUS, "[????????????]");
		//mask.registerFormat(" ", "*bogus*", " ");  // force space
		if (widescreen) {
			mask.registerFormat("%v", -43, FormatOptionAutoWidth | FormatOptionNoTruncate, ATTR_HOLD_REASON );
		} else {
			mask.registerFormat("%-43.43s", ATTR_HOLD_REASON);
		}
		usingPrintMask = true;
	}

	if (mask_headings) {
		const char * pszz = mask_headings;
		size_t cch = strlen(pszz);
		while (cch > 0) {
			mask_head.Append(pszz);
			pszz += cch+1;
			cch = strlen(pszz);
		}
	}
}

/* The parameters v1, v2, and v3 will be intepreted immediately on the top 
   of the function based on the value of useDB. For more details, please 
   refer to the prototype of this function on the top of this file 
*/

static bool
show_queue_buffered( const char* v1, const char* v2, const char* v3, const char* v4, bool useDB )
{
	const char *scheddAddress = 0;
	const char *scheddName = 0;
	const char *scheddMachine = 0;

	const char *quill_name = 0;
	const char *db_ipAddr = 0;
	const char *db_name = 0;
	const char *query_password;

	char *lastUpdate=NULL;

		/* intepret the parameters accordingly based on whether we are querying database */
	if (useDB) {
		quill_name = v1;
		db_ipAddr = v2;
		db_name = v3;		
		query_password = v4;
	}
	else {
		scheddAddress = v1;
		scheddName = v2;
		scheddMachine = v3;
	}

		// initialize counters
	idle = running = held = malformed = suspended = completed = removed = 0;

#if 1
#else
	static bool	setup_mask = false;
	if ( run || goodput ) {
		summarize = false;
		if (!setup_mask) {
			mask.registerFormat ("%4d.", ATTR_CLUSTER_ID);
			mask.registerFormat ("%-3d ", ATTR_PROC_ID);
			mask.registerFormat ( (StringCustomFmt) format_owner,
								  ATTR_OWNER, "[????????????] " );
			mask.registerFormat(" ", "*bogus*", " ");  // force space
			mask.registerFormat ( (IntCustomFmt) format_q_date,
								  ATTR_Q_DATE, "[????????????]");
			mask.registerFormat(" ", "*bogus*", " ");  // force space
			mask.registerFormat ( (FloatCustomFmt) format_cpu_time,
								  ATTR_JOB_REMOTE_USER_CPU,
								  "[??????????]");
			if( run && !goodput ) {
				mask.registerFormat(" ", "*bogus*", " "); // force space
				// We send in ATTR_OWNER since we know it is always
				// defined, and we need to make sure
				// format_remote_host() is always called. We are
				// actually displaying ATTR_REMOTE_HOST if defined,
				// but we play some tricks if it isn't defined.
				mask.registerFormat ( (StringCustomFmt) format_remote_host,
									  ATTR_OWNER, "[????????????????]");
			} else {			// goodput
				mask.registerFormat ( (IntCustomFmt) format_goodput,
									  ATTR_JOB_STATUS,
									  " [?????]");
				mask.registerFormat ( (FloatCustomFmt) format_cpu_util,
									  ATTR_JOB_REMOTE_USER_CPU,
									  " [??????]");
				mask.registerFormat ( (FloatCustomFmt) format_mbps,
									  ATTR_BYTES_SENT,
									  " [????]");
			}
			mask.registerFormat("\n", "*bogus*", "\n");  // force newline
			setup_mask = true;
			usingPrintMask = true;
		}
	} else if( globus ) {
		summarize = false;
		if (!setup_mask) {
			mask.SetAutoSep(NULL," ",NULL,"\n");
			mask.registerFormat ("%4d.", 5, FormatOptionAutoWidth | FormatOptionNoSuffix, ATTR_CLUSTER_ID);
			mask.registerFormat ("%-3d ", 3, FormatOptionAutoWidth | FormatOptionNoPrefix,  ATTR_PROC_ID);
			mask.registerFormat (NULL, -14, 0, format_owner_wide, ATTR_OWNER, "[?]" );
			mask.registerFormat(NULL, -8, 0, (IntCustomFmt) format_globusStatus, ATTR_GLOBUS_STATUS, "[?]" );
			if (widescreen) {
				mask.registerFormat(NULL, -30, FormatOptionAutoWidth | FormatOptionNoTruncate, 
					(StringCustomFmt)format_globusHostAndJM, ATTR_GRID_RESOURCE, "fork    [?????]" );
				mask.registerFormat("%v", -18, FormatOptionAutoWidth | FormatOptionNoTruncate, ATTR_JOB_CMD );
			} else {
				mask.registerFormat(NULL, 30, 0, 
					(StringCustomFmt)format_globusHostAndJM, ATTR_JOB_CMD, "fork    [?????]" );
				mask.registerFormat("%-18.18s", ATTR_JOB_CMD);
			}
			setup_mask = true;
			usingPrintMask = true;
		}
	} else if( dash_grid ) {
		summarize = false;
		if (!setup_mask) {
			//mask.SetAutoSep("<","{","},",">\n"); // for testing.
			mask.SetAutoSep(NULL," ",NULL,"\n");
			mask.registerFormat ("%4d.", 5, FormatOptionAutoWidth | FormatOptionNoSuffix, ATTR_CLUSTER_ID);
			mask.registerFormat ("%-3d", 3, FormatOptionAutoWidth | FormatOptionNoPrefix, ATTR_PROC_ID);
			if (widescreen) {
				mask.registerFormat (NULL, -14, FormatOptionAutoWidth | FormatOptionNoTruncate, format_owner_wide, ATTR_OWNER);
				mask.registerFormat (NULL, -10, FormatOptionAutoWidth | FormatOptionNoTruncate, format_gridStatus, ATTR_JOB_STATUS);
				mask.registerFormat (NULL, -30, FormatOptionAutoWidth | FormatOptionNoTruncate, format_gridResource, ATTR_GRID_RESOURCE);
				mask.registerFormat (NULL, -18, FormatOptionAutoWidth | FormatOptionNoTruncate, format_gridJobId, ATTR_GRID_JOB_ID);
			} else {
				mask.registerFormat (NULL, -14, 0, format_owner_wide, ATTR_OWNER);
				mask.registerFormat (NULL, -10,0, format_gridStatus, ATTR_JOB_STATUS);
				mask.registerFormat ("%-30.30s", 0,0, format_gridResource, ATTR_GRID_RESOURCE);
				mask.registerFormat ("%-18.18s", 0,0, format_gridJobId, ATTR_GRID_JOB_ID);
			}
			setup_mask = true;
			usingPrintMask = true;
		}
	} else if ( show_held ) {
		if (!setup_mask) {
			mask.registerFormat ("%4d.", ATTR_CLUSTER_ID);
			mask.registerFormat ("%-3d ", ATTR_PROC_ID);
			mask.registerFormat ( (StringCustomFmt) format_owner,
								  ATTR_OWNER, "[????????????] " );
			mask.registerFormat(" ", "*bogus*", " ");  // force space
			mask.registerFormat ( (IntCustomFmt) format_q_date,
								  ATTR_ENTERED_CURRENT_STATUS, "[????????????]");
			mask.registerFormat(" ", "*bogus*", " ");  // force space
			mask.registerFormat( widescreen ? "%s\n" : "%-43.43s\n", ATTR_HOLD_REASON );
			setup_mask = true;
			usingPrintMask = true;
		}
	} else if ( customFormat ) {
		summarize = false;
	}
#endif

	if( g_cur_schedd_for_process_buffer_line ) {
		delete g_cur_schedd_for_process_buffer_line;
		g_cur_schedd_for_process_buffer_line = NULL;
	}

	if( g_stream_results ) {
		full_header(useDB,quill_name,db_ipAddr,db_name,lastUpdate,scheddName,scheddAddress,scheddMachine);
	}

	CondorError errstack;

		/* get the job ads from database if database can be queried */
	if (useDB) {
#ifdef HAVE_EXT_POSTGRESQL

		char *dbconn=NULL;
		dbconn = getDBConnStr(quill_name, db_ipAddr, db_name, query_password);

		if( Q.fetchQueueFromDBAndProcess( dbconn,
											lastUpdate,
											process_buffer_line,
											&errstack) != Q_OK ) {
			fprintf( stderr, 
					"\n-- Failed to fetch ads from db [%s] at database "
					"server %s\n%s\n",
					db_name, db_ipAddr, errstack.getFullText(true) );

			if(dbconn) {
				free(dbconn);
			}
			if(lastUpdate) {
				free(lastUpdate);
			}
			return false;
		}
		if(dbconn) {
			free(dbconn);
		}
#else
		if (query_password) {} /* Done to suppress set-but-not-used warnings */
#endif /* HAVE_EXT_POSTGRESQL */
	} else {
			// fetch queue from schedd and stash it in output_buffer.
		Daemon schedd(DT_SCHEDD, scheddName, pool ? pool->addr() : NULL );
		const char *version = schedd.version();
		bool useFastPath = false;
		if (version) {
			CondorVersionInfo v(version);
			useFastPath = v.built_since_version(6,9,3);
		}

			// stash the schedd daemon object for use by process_buffer_line
		g_cur_schedd_for_process_buffer_line = new Daemon( schedd );

		int fetchResult;
		if( (fetchResult = Q.fetchQueueFromHostAndProcess( scheddAddress, attrs,
											process_buffer_line,
											useFastPath,
											&errstack)) != Q_OK) {
			
			// The parse + fetch failed, print out why
			switch(fetchResult) {
				case Q_PARSE_ERROR:
				case Q_INVALID_CATEGORY:
					fprintf(stderr, "\n-- Parse error in constraint expression \"%s\"\n", user_constraint);
					break;
				default:
					fprintf(stderr,
						"\n-- Failed to fetch ads from: %s : %s\n%s\n",
						scheddAddress, scheddMachine, errstack.getFullText(true) );
			}

			return false;
		}
	}

	// If this is a global, don't print anything if this schedd is empty.
	// If this is NOT global, print out the header and footer to show that we
	//    did something.
	if (!global || dag_map.size() > 0 || g_stream_results) {
		if( !g_stream_results ) {
			full_header(useDB,quill_name,db_ipAddr,db_name,lastUpdate,scheddName,scheddAddress,scheddMachine);
		}

			// Assumptions of this code: DAG Parent nodes always
			// have cluster ids that are less than those of child
			// nodes. condor_dagman processes have ProcID == 0 (only one per
			// cluster)

			// First Pass: Find all the DAGman nodes, and link them up
		if( dag ) {
			for(dag_map_type::iterator cps = dag_map.begin(); cps != dag_map.end(); ++cps) {
				clusterProcString* cpps = cps->second;
				if(cpps->dagman_cluster_id != cpps->cluster) {
						// Its probably a DAGman job
						// This next line is where we assume all condor_dagman
						// jobs have ProcID == 0
					clusterProcMapper parent_id(cpps->dagman_cluster_id);
					dag_map_type::iterator dmp = dag_map.find(parent_id);
					if( dmp != dag_map.end() ) { // found it!
						cpps->parent = dmp->second;
						dmp->second->children.push_back(cpps);
					} else { // Now search dag_cluster_map
							// Necessary to find children of dags
							// which are themselves children (that is,
							// subdags)
						clusterIDProcIDMapper cipim(cpps->dagman_cluster_id);
						dag_cluster_map_type::iterator dcmti = dag_cluster_map.find(cipim);
						if(dcmti != dag_cluster_map.end() ) {
							cpps->parent = dcmti->second;
							dcmti->second->children.push_back(cpps);
						}
					}
				}
			}

				// Second pass: edit the strings
			for(dag_map_type::iterator cps = dag_map.begin(); cps != dag_map.end(); ++cps) {
				edit_string(cps->second);
			}
		}

			// Third pass: write the strings
		for(dag_map_type::iterator cps = dag_map.begin(); cps != dag_map.end(); ++cps) {
			write_node(cps->second,0);
		}
		// If we want to summarize, do that too.
		if( summarize ) {
			printf( "\n%d jobs; "
					"%d completed, %d removed, %d idle, %d running, %d held, %d suspended",
					idle+running+held+malformed+suspended+completed+removed,
					completed,removed,idle,running,held,suspended);
			if (malformed>0) printf( ", %d malformed",malformed);
           	printf("\n");
		}
		if( use_xml ) {
				// keep this consistent with AttrListList::fPrintAttrListList()
			ClassAdXMLUnparser  unparser;
			MyString xml;
			unparser.SetUseCompactSpacing(false);
			unparser.AddXMLFileFooter(xml);
			printf("%s\n", xml.Value());
		}
	}

	for(std::map<clusterProcMapper,clusterProcString*,CompareProcMaps>::iterator
			cps = dag_map.begin(); cps != dag_map.end(); ++cps) {
		delete[] cps->second->string;
		delete cps->second;
	}
	dag_map.clear();
	dag_cluster_map.clear();
	if(lastUpdate) {
		free(lastUpdate);
	}
	return true;
}


// process_buffer_line returns 1 so that the ad that is passed
// to it should be deleted.


static bool
process_buffer_line( ClassAd *job )
{
	int status = 0;

	clusterProcString * tempCPS = new clusterProcString;

	job->LookupInteger( ATTR_CLUSTER_ID, tempCPS->cluster );
	job->LookupInteger( ATTR_PROC_ID, tempCPS->proc );
	job->LookupInteger( ATTR_JOB_STATUS, status );

	switch (status)
	{
		case IDLE:                idle++;      break;
		case TRANSFERRING_OUTPUT: 
		case RUNNING:             running++;   break;
		case SUSPENDED:           suspended++; break;
		case COMPLETED:           completed++; break;
		case REMOVED:             removed++;   break;
		case HELD:		          held++;	   break;
	}

	// If it's not a DAGMan job (and this includes the DAGMan process
	// itself), then set the dagman_cluster_id equal to cluster so that
	// it sorts properly against dagman jobs.
	char *dagman_job_string = NULL;
	bool dci_initialized = false;
	if (!job->LookupString(ATTR_DAGMAN_JOB_ID, &dagman_job_string)) {
			// we failed to find an DAGManJobId string attribute, 
			// let's see if we find one that is an integer.
		int temp_cluster = -1;
		if (!job->LookupInteger(ATTR_DAGMAN_JOB_ID,temp_cluster)) {
				// could not job DAGManJobId, so fall back on 
				// just the regular job id
			tempCPS->dagman_cluster_id = tempCPS->cluster;
			tempCPS->dagman_proc_id    = tempCPS->proc;
			dci_initialized = true;
		} else {
				// in this case, we found DAGManJobId set as
				// an integer, not a string --- this means it is
				// the cluster id.
			tempCPS->dagman_cluster_id = temp_cluster;
			tempCPS->dagman_proc_id    = 0;
			dci_initialized = true;
		}
	} else {
		// We've gotten a string, probably something like "201.0"
		// we want to convert it to the numbers 201 and 0. To be safe, we
		// use atoi on either side of the period. We could just use
		// sscanf, but I want to know each fail case, so I can set them
		// to reasonable values. 
		char *loc_period = strchr(dagman_job_string, '.');
		char *proc_string_start = NULL;
		if (loc_period != NULL) {
			*loc_period = 0;
			proc_string_start = loc_period+1;
		}
		if (isdigit(*dagman_job_string)) {
			tempCPS->dagman_cluster_id = atoi(dagman_job_string);
			dci_initialized = true;
		} else {
			// It must not be a cluster id, because it's not a number.
			tempCPS->dagman_cluster_id = tempCPS->cluster;
			dci_initialized = true;
		}

		if (proc_string_start != NULL && isdigit(*proc_string_start)) {
			tempCPS->dagman_proc_id = atoi(proc_string_start);
			dci_initialized = true;
		} else {
			tempCPS->dagman_proc_id = 0;
			dci_initialized = true;
		}
		free(dagman_job_string);
	}
	if( !g_stream_results && dci_initialized ) {
		clusterProcMapper cpm(*tempCPS);
		std::pair<dag_map_type::iterator,bool> pp = dag_map.insert(
			std::pair<clusterProcMapper,clusterProcString*>(
				cpm, tempCPS ) );
		if( !pp.second ) {
			fprintf( stderr, "Error: Two clusters with the same ID.\n" );
			fprintf( stderr, "tempCPS: %d %d %d %d\n", tempCPS->dagman_cluster_id,
				tempCPS->dagman_proc_id, tempCPS->cluster, tempCPS->proc );
			dag_map_type::iterator ppp = dag_map.find(cpm);
			fprintf( stderr, "Comparing against: %d %d %d %d\n",
				ppp->second->dagman_cluster_id, ppp->second->dagman_proc_id,
				ppp->second->cluster, ppp->second->proc );
			exit( 1 );
		}
		clusterIDProcIDMapper cipim(*tempCPS);
		std::pair<dag_cluster_map_type::iterator,bool> pq = dag_cluster_map.insert(
			std::pair<clusterIDProcIDMapper,clusterProcString*>(
				cipim,tempCPS ) );
		if( !pq.second ) {
			fprintf( stderr, "Error: Clusters have nonunique IDs.\n" );
			exit( 1 );
		}
	}

	if (use_xml) {
		MyString s;
		StringList *attr_white_list = attrs.isEmpty() ? NULL : &attrs;
		job->sPrintAsXML(s,attr_white_list);
		tempCPS->string = strnewp( s.Value() );
	} else if( verbose ) {
		MyString s;
		StringList *attr_white_list = attrs.isEmpty() ? NULL : &attrs;
		job->sPrint(s,attr_white_list);
		s += "\n";
		tempCPS->string = strnewp( s.Value() );
	} else if( better_analyze ) {
		tempCPS->string = strnewp( doRunAnalysisToBuffer( job, g_cur_schedd_for_process_buffer_line ) );
	} else if ( show_io ) {
		tempCPS->string = strnewp( buffer_io_display( job ) );
	} else if ( usingPrintMask ) {
		char * tempSTR = mask.display ( job );
		// strnewp the mask.display return, since its an 8k string.
		tempCPS->string = strnewp( tempSTR );
		delete [] tempSTR;
	} else {
		tempCPS->string = strnewp( bufferJobShort( job ) );
	}

	if( g_stream_results ) {
		printf("%s",tempCPS->string);
		delete[] tempCPS->string;
		delete tempCPS;
		tempCPS = NULL;
	}
	return true;
}

/* The parameters v1, v2, and v3 will be intepreted immediately on the top 
   of the function based on the value of useDB. For more details, please 
   refer to the prototype of this function on the top of this file 
*/
static bool
show_queue( const char* v1, const char* v2, const char* v3, const char* v4, bool useDB )
{
	const char *scheddAddress;
	const char *scheddName;
	const char *scheddMachine;
	const char *scheddVersion;

	const char *quill_name = 0;
	const char *db_ipAddr = 0;
	const char *db_name = 0;
	const char *query_password = 0;

	ClassAdList jobs; 
	ClassAd		*job;
#if 0
	static bool	setup_mask = false;
#endif

	/* assume this will be true. And it will be if we aren't using the DB */
	scheddAddress = v1;
	scheddName = v2;
	scheddMachine = v3;		
	scheddVersion = v4;

	char *lastUpdate=NULL;

    if (jobads_file != NULL) {
		/* get the "q" from the job ads file */
        if (!read_classad_file(jobads_file, jobs)) {
            return false;
        }
		
		/* The variable UseDB should be false in this branch since it was set 
			in main() because jobads_file had a good value. */

    } else {
		/* else get the job queue either from quill or the schedd. */

		/* interpret the parameters accordingly based on whether
			we are querying a database */
		if (useDB) {
			quill_name = v1;
			db_ipAddr = v2;
			db_name = v3;		
			query_password = v4;
		}

		CondorError errstack;

			/* get the job ads from a database if available */
		if (useDB) {
#ifdef HAVE_EXT_POSTGRESQL

			char *dbconn=NULL;
			dbconn = getDBConnStr(quill_name, db_ipAddr, db_name, query_password);

				// fetch queue from database
			if( Q.fetchQueueFromDB(jobs, lastUpdate, dbconn, &errstack) != Q_OK ) {
				fprintf( stderr,
						"\n-- Failed to fetch ads from: %s : %s\n%s\n",
						db_ipAddr, db_name, errstack.getFullText(true) );
				if(dbconn) {
					free(dbconn);
				}
				if(lastUpdate) {
					free(lastUpdate);
				}
				return false;
			}

			if(dbconn) {
				free(dbconn);
			}
#else
			if (query_password) {} /* Done to suppress set-but-not-used warnings */
#endif /* HAVE_EXT_POSTGRESQL */
		} else {
				// fetch queue from schedd	
			int fetchResult;
			if( (fetchResult = Q.fetchQueueFromHost(jobs, attrs,scheddAddress, scheddVersion, &errstack) != Q_OK)) {
			// The parse + fetch failed, print out why
			switch(fetchResult) {
				case Q_PARSE_ERROR:
				case Q_INVALID_CATEGORY:
					fprintf(stderr, "\n-- Parse error in constraint expression \"%s\"\n", user_constraint);
					break;
				default:
					fprintf(stderr,
						"\n-- Failed to fetch ads from: %s : %s\n%s\n",
						scheddAddress, scheddMachine, errstack.getFullText(true) );
			}
			return false;
			}
		}
	}

		// sort jobs by (cluster.proc) if don't query database
	if (!useDB) {
		jobs.Sort( (SortFunctionType)JobSort );
	}

		// check if job is being analyzed
	if( better_analyze ) {
			// print header
		if (useDB) {
			printf ("\n\n-- Quill: %s : %s : %s\n", quill_name, 
					db_ipAddr, db_name);
		} else if( querySchedds ) {
			printf ("\n\n-- Schedd: %s : %s\n", scheddName, scheddAddress);
		} else {
			printf ("\n\n-- Submitter: %s : %s : %s\n", scheddName, 
					scheddAddress, scheddMachine);	
		}

		Daemon schedd_daemon(DT_SCHEDD,scheddName,pool ? pool->addr() : NULL);
		schedd_daemon.locate();

		jobs.Open();
		while( ( job = jobs.Next() ) ) {
			doRunAnalysis( job, &schedd_daemon );
		}
		jobs.Close();

		if(lastUpdate) {
			free(lastUpdate);
		}
		return true;
	}

		// display the jobs from this submittor
	if( jobs.MyLength() != 0 || !global ) {
			// print header
		if ( ! customFormat ) {
			if (useDB) {
				printf ("\n\n-- Quill: %s : %s : %s\n", quill_name, 
						db_ipAddr, db_name);
			} else if( querySchedds ) {
				printf ("\n\n-- Schedd: %s : %s\n", scheddName, scheddAddress);
			} else {
				printf ("\n\n-- Submitter: %s : %s : %s\n", scheddName, 
					scheddAddress, scheddMachine);	
			}
		}

			// initialize counters
		malformed = idle = running = held = completed = suspended = 0;
		
		if( verbose || use_xml ) {
			StringList *attr_white_list = attrs.isEmpty() ? NULL : &attrs;
			jobs.fPrintAttrListList( stdout, use_xml ? true : false, attr_white_list);
		} else if( customFormat ) {
			summarize = false;
			if (mask_head.Length() > 0) {
				mask.display( stdout, &jobs, NULL, &mask_head );
			} else {
				mask.display( stdout, &jobs);
			}
#if 1
		} else if( globus || dash_grid || show_held || run || goodput ) {
			init_output_mask();
#if 0
			if (mask_headings) {
				List<const char> headings;
				const char * pszz = mask_headings;
				size_t cch = strlen(pszz);
				while (cch > 0) {
					headings.Append(pszz);
					pszz += cch+1;
					cch = strlen(pszz);
				}
				mask.display(stdout, &jobs, NULL, &headings);
			} else
#endif
			mask.display(stdout, &jobs, NULL, &mask_head);
#else
		} else if( globus ) {
			summarize = false;
			printf( " %-7s %-14s %-11s %-8s %-18s  %-18s\n", 
				"ID", "OWNER", "STATUS", "MANAGER", "HOST", "EXECUTABLE" );
			if (!setup_mask) {
				mask.registerFormat ("%4d.", ATTR_CLUSTER_ID);
				mask.registerFormat ("%-3d ", ATTR_PROC_ID);
				mask.registerFormat ( (StringCustomFmt) format_owner,
									  ATTR_OWNER, "[????????????] " );
				mask.registerFormat( (IntCustomFmt) format_globusStatus,
									 ATTR_GLOBUS_STATUS, "[?????]" );
				mask.registerFormat( (StringCustomFmt)
									 format_globusHostAndJM,
									 ATTR_JOB_CMD, "fork    [?????]" );
				mask.registerFormat( widescreen ? "%s\n" : "%-18.18s\n", ATTR_JOB_CMD );
				setup_mask = true;
				usingPrintMask = true;
			}
			mask.display( stdout, &jobs );
		} else if( dash_grid ) {
			summarize = false;
			printf( " %-7s %-14s %-10s  %-16s %-16s  %-18s\n", 
				"ID", "OWNER", "STATUS", "GRID->MANAGER", "HOST", "GRID-JOB-ID" );
			if (!setup_mask) {
				mask.registerFormat ("%4d.", ATTR_CLUSTER_ID);
				mask.registerFormat ("%-3d ", ATTR_PROC_ID);
				mask.registerFormat (NULL, -14, 0, format_owner_wide, ATTR_OWNER, "[?]" );
				mask.registerFormat( format_gridStatus, ATTR_JOB_STATUS, "[?????]" );
				//mask.registerFormat( format_gridType, ATTR_JOB_STATUS, "[???]" );
				mask.registerFormat( format_gridResource, ATTR_GRID_RESOURCE, "[??]->[??] [?????]" );
				mask.registerFormat (widescreen ? "%s\n" : "%-18.18s\n", 0,0, format_gridJobId, ATTR_GRID_JOB_ID, "\n" );
				setup_mask = true;
				usingPrintMask = true;
			}
			mask.display( stdout, &jobs );
		} else if ( show_held ) {
			printf( " %-7s %-14s %11s %-30s\n", 
				"ID", "OWNER", "HELD_SINCE", "HOLD_REASON" );
			if (!setup_mask) {
				mask.registerFormat ("%4d.", ATTR_CLUSTER_ID);
				mask.registerFormat ("%-3d ", ATTR_PROC_ID);
				mask.registerFormat ( (StringCustomFmt) format_owner,
									  ATTR_OWNER, "[????????????] " );
				mask.registerFormat(" ", "*bogus*", " ");  // force space
				mask.registerFormat ( (IntCustomFmt) format_q_date,
									  ATTR_ENTERED_CURRENT_STATUS, "[????????????]");
				mask.registerFormat(" ", "*bogus*", " ");  // force space
				mask.registerFormat( widescreen ? "%s\n" : "%-43.43s\n", ATTR_HOLD_REASON );
				setup_mask = true;
				usingPrintMask = true;
			}
			mask.display( stdout, &jobs );
		} else if ( run || goodput ) {
			summarize = false;
			printf( " %-7s %-14s %11s %12s %-16s\n", "ID", "OWNER",
					"SUBMITTED", JOB_TIME,
					run ? "HOST(S)" : "GOODPUT CPU_UTIL   Mb/s" );
			if (!setup_mask) {
				mask.registerFormat ("%4d.", ATTR_CLUSTER_ID);
				mask.registerFormat ("%-3d ", ATTR_PROC_ID);
				mask.registerFormat ( (StringCustomFmt) format_owner,
									  ATTR_OWNER, "[????????????] " );
				mask.registerFormat(" ", "*bogus*", " ");  // force space
				mask.registerFormat ( (IntCustomFmt) format_q_date,
									  ATTR_Q_DATE, "[????????????]");
				mask.registerFormat(" ", "*bogus*", " ");  // force space
				mask.registerFormat ( (FloatCustomFmt) format_cpu_time,
									  ATTR_JOB_REMOTE_USER_CPU,
									  "[??????????]");
				if ( run ) {
					mask.registerFormat(" ", "*bogus*", " "); // force space
					// We send in ATTR_OWNER since we know it is always
					// defined, and we need to make sure
					// format_remote_host() is always called. We are
					// actually displaying ATTR_REMOTE_HOST if defined,
					// but we play some tricks if it isn't defined.
					mask.registerFormat ( (StringCustomFmt) format_remote_host,
										  ATTR_OWNER, "[????????????????]");
				} else {			// goodput
					mask.registerFormat ( (IntCustomFmt) format_goodput,
										  ATTR_JOB_STATUS,
										  " [?????]");
					mask.registerFormat ( (FloatCustomFmt) format_cpu_util,
										  ATTR_JOB_REMOTE_USER_CPU,
										  " [??????]");
					mask.registerFormat ( (FloatCustomFmt) format_mbps,
										  ATTR_BYTES_SENT,
										  " [????]");
				}
				mask.registerFormat("\n", "*bogus*", "\n");  // force newline
				setup_mask = true;
				usingPrintMask = true;
			}
			mask.display(stdout, &jobs);
#endif
		} else if( show_io ) {
			short_header();
			jobs.Open();
			while( (job=jobs.Next()) ) {
				io_display( job );
			}
			jobs.Close();
		} else {
			short_header();
			jobs.Open();
			while( (job=jobs.Next()) ) {
				displayJobShort( job );
			}
			jobs.Close();
		}

		if( summarize ) {
			printf( "\n%d jobs; "
					"%d completed, %d removed, %d idle, %d running, %d held, %d suspended",
					idle+running+held+malformed+suspended+completed+removed,
					completed,removed,idle,running,held,suspended);
			if (malformed>0) printf( ", %d malformed",malformed);

            printf("\n");
		}
	}

	if(lastUpdate) {
		free(lastUpdate);
	}
	return true;
}


static void
setupAnalysis()
{
	CondorQuery	query(STARTD_AD);
	int			rval;
	char		buffer[64];
	char		*preq;
	ClassAd		*ad;
	char		remoteUser[128];
	int			index;

	// fetch startd ads
    if (machineads_file != NULL) {
        if (!read_classad_file(machineads_file, startdAds)) {
            exit ( 1 );
        }
    } else {
        rval = Collectors->query (query, startdAds);
        if( rval != Q_OK ) {
            fprintf( stderr , "Error:  Could not fetch startd ads\n" );
            exit( 1 );
        }
    }

	// fetch submittor prios
	fetchSubmittorPrios();

	// populate startd ads with remote user prios
	startdAds.Open();
	while( ( ad = startdAds.Next() ) ) {
		if( ad->LookupString( ATTR_REMOTE_USER , remoteUser ) ) {
			if( ( index = findSubmittor( remoteUser ) ) != -1 ) {
				sprintf( buffer , "%s = %f" , ATTR_REMOTE_USER_PRIO , 
							prioTable[index].prio );
				ad->Insert( buffer );
			}
		}
#if !defined(WANT_OLD_CLASSADS)
		ad->AddTargetRefs( TargetJobAttrs );
#endif
	}
	startdAds.Close();
	

	// setup condition expressions
    sprintf( buffer, "MY.%s > MY.%s", ATTR_RANK, ATTR_CURRENT_RANK );
    ParseClassAdRvalExpr( buffer, stdRankCondition );

    sprintf( buffer, "MY.%s >= MY.%s", ATTR_RANK, ATTR_CURRENT_RANK );
    ParseClassAdRvalExpr( buffer, preemptRankCondition );

	sprintf( buffer, "MY.%s > TARGET.%s + %f", ATTR_REMOTE_USER_PRIO, 
			ATTR_SUBMITTOR_PRIO, PriorityDelta );
	ParseClassAdRvalExpr( buffer, preemptPrioCondition ) ;

	// setup preemption requirements expression
	if( !( preq = param( "PREEMPTION_REQUIREMENTS" ) ) ) {
		fprintf( stderr, "\nWarning:  No PREEMPTION_REQUIREMENTS expression in"
					" config file --- assuming FALSE\n\n" );
		ParseClassAdRvalExpr( "FALSE", preemptionReq );
	} else {
		if( ParseClassAdRvalExpr( preq , preemptionReq ) ) {
			fprintf( stderr, "\nError:  Failed parse of "
				"PREEMPTION_REQUIREMENTS expression: \n\t%s\n", preq );
			exit( 1 );
		}
#if !defined(WANT_OLD_CLASSADS)
		ExprTree *tmp_expr = AddTargetRefs( preemptionReq, TargetJobAttrs );
		delete preemptionReq;
		preemptionReq = tmp_expr;
#endif
		free( preq );
	}

}


static void
fetchSubmittorPrios()
{
	AttrList	al;
	char  	attrName[32], attrPrio[32];
  	char  	name[128];
  	float 	priority;
	int		i = 1;

	Daemon	negotiator( DT_NEGOTIATOR, NULL, pool ? pool->addr() : NULL );

	// connect to negotiator
	Sock* sock;

	if (!(sock = negotiator.startCommand( GET_PRIORITY, Stream::reli_sock, 0))) {
		fprintf( stderr, "Error: Could not connect to negotiator (%s)\n",
				 negotiator.fullHostname() );
		exit( 1 );
	}

	sock->end_of_message();
	sock->decode();
	if( !al.initAttrListFromStream(*sock) || !sock->end_of_message() ) {
		fprintf( stderr, 
				 "Error:  Could not get priorities from negotiator (%s)\n",
				 negotiator.fullHostname() );
		exit( 1 );
	}
	sock->close();
	delete sock;


	i = 1;
	while( i ) {
    	sprintf( attrName , "Name%d", i );
    	sprintf( attrPrio , "Priority%d", i );

    	if( !al.LookupString( attrName, name ) || 
			!al.LookupFloat( attrPrio, priority ) )
            break;

		prioTable[i-1].name = name;
		prioTable[i-1].prio = priority;
		i++;
	}

	if( i == 1 ) {
		printf( "Warning:  Found no submitters\n" );
	}
}


static void
doRunAnalysis( ClassAd *request, Daemon *schedd )
{
	printf("%s", doRunAnalysisToBuffer( request, schedd ) );
}

static const char *
doRunAnalysisToBuffer( ClassAd *request, Daemon *schedd )
{
	char	owner[128];
	char	remoteUser[128];
	char	buffer[128];
	int		index;
	ClassAd	*offer;
	classad::Value	eval_result;
	bool	val;
	int		cluster, proc;
	int		jobState;
	int		niceUser;
	int		universe;
	int		jobMatched = false;

	int 	fReqConstraint 	= 0;
	int		fOffConstraint 	= 0;
	int		fRankCond		= 0;
	int		fPreemptPrioCond= 0;
	int		fPreemptReqTest	= 0;
	int     fOffline        = 0;
	int		available		= 0;
	int		totalMachines	= 0;

	return_buff[0]='\0';

#if !defined(WANT_OLD_CLASSADS)
	request->AddTargetRefs( TargetMachineAttrs );
#endif

	if( schedd ) {
		MyString buf;
		warnScheddLimits(schedd,request,buf);
		snprintf( return_buff, sizeof(return_buff), "%s", buf.Value() );
	}

	if( !request->LookupString( ATTR_OWNER , owner ) ) return "Nothing here.\n";
	if( !request->LookupInteger( ATTR_NICE_USER , niceUser ) ) niceUser = 0;

	if( ( index = findSubmittor( fixSubmittorName( owner, niceUser ) ) ) < 0 ) 
		return "Nothing here.\n";

	sprintf( buffer , "%s = %f" , ATTR_SUBMITTOR_PRIO , prioTable[index].prio );
	request->Insert( buffer );


	int last_match_time=0, last_rej_match_time=0;
	request->LookupInteger(ATTR_LAST_MATCH_TIME, last_match_time);
	request->LookupInteger(ATTR_LAST_REJ_MATCH_TIME, last_rej_match_time);

	request->LookupInteger( ATTR_CLUSTER_ID, cluster );
	request->LookupInteger( ATTR_PROC_ID, proc );
	request->LookupInteger( ATTR_JOB_STATUS, jobState );
	request->LookupBool( ATTR_JOB_MATCHED, jobMatched );
	if( jobState == RUNNING || jobState == TRANSFERRING_OUTPUT || jobState == SUSPENDED) {
		sprintf( return_buff,
			"---\n%03d.%03d:  Request is being serviced\n\n", cluster, 
			proc );
		return return_buff;
	}
	if( jobState == HELD ) {
		sprintf( return_buff,
			"---\n%03d.%03d:  Request is held.\n\n", cluster, 
			proc );
		MyString hold_reason;
		request->LookupString( ATTR_HOLD_REASON, hold_reason );
		if( hold_reason.Length() ) {
			size_t offset = strlen(return_buff);
			snprintf( return_buff + offset, sizeof(return_buff)-offset, "Hold reason: %s\n\n", hold_reason.Value() );
		}
		return return_buff;
	}
	if( jobState == REMOVED ) {
		sprintf( return_buff,
			"---\n%03d.%03d:  Request is removed.\n\n", cluster, 
			proc );
		return return_buff;
	}
	if( jobState == COMPLETED ) {
		sprintf( return_buff,
			"---\n%03d.%03d:  Request is completed.\n\n", cluster, 
			proc );
		return return_buff;
	}
	if ( jobMatched ) {
		sprintf( return_buff,
			"---\n%03d.%03d:  Request has been matched.\n\n", cluster, 
			proc );
		return return_buff;
	}

	startdAds.Open();

	std::string fReqConstraintStr("[");
	std::string fOffConstraintStr("[");
	std::string fOfflineStr("[");
	std::string fPreemptPrioStr("[");
	std::string fPreemptReqTestStr("[");
	std::string fRankCondStr("[");

	while( ( offer = startdAds.Next() ) ) {
		// 0.  info from machine
		remoteUser[0] = '\0';
		totalMachines++;
		offer->LookupString( ATTR_NAME , buffer );
		if( verbose ) sprintf( return_buff, "%-15.15s ", buffer );

		// 1. Request satisfied? 
		if( !IsAHalfMatch( request, offer ) ) {
			if( verbose ) sprintf( return_buff,
				"%sFailed request constraint\n", return_buff );
			fReqConstraint++;
			if (fReqConstraint != 1) {
				fReqConstraintStr += ", ";
			} 
			fReqConstraintStr += buffer;
			continue;
		} 

		// 2. Offer satisfied? 
		if ( !IsAHalfMatch( offer, request ) ) {
			if( verbose ) strcat( return_buff, "Failed offer constraint\n");
			fOffConstraint++;
			if (fOffConstraint != 1) {
				fOffConstraintStr += ", ";
			}
			fOffConstraintStr += buffer;
			continue;
		}	

		int offline = 0;
		if( offer->EvalBool( ATTR_OFFLINE, NULL, offline ) && offline ) {
			fOffline++;
			if (fOffline != 1) {
				fOfflineStr += ", ";
			}
			fOfflineStr += buffer;
			continue;
		}

		// 3. Is there a remote user?
		if( !offer->LookupString( ATTR_REMOTE_USER, remoteUser ) ) {
			if( EvalExprTree( stdRankCondition, offer, request, eval_result ) &&
				eval_result.IsBooleanValue(val) && val ) {
				// both sides satisfied and no remote user
				if( verbose ) sprintf( return_buff, "%sAvailable\n",
					return_buff );
				available++;
				continue;
			} else {
				// no remote user, but std rank condition failed
			  if (last_rej_match_time != 0) {
  				fRankCond++;
				if (fRankCond != 1) {
					fRankCondStr += ", ";
				}
				fRankCondStr += buffer;
				if( verbose ) {
					sprintf( return_buff,
						"%sFailed rank condition: MY.Rank > MY.CurrentRank\n",
						return_buff);
				}
				continue;
			  } else {
			    sprintf( return_buff,
				     "---\n%03d.%03d:  Request has not yet been considered by the matchmaker.\n\n", cluster,
				     proc );
			    return return_buff;
			  }
			}
		}

		// 4. Satisfies preemption priority condition?
		if( EvalExprTree( preemptPrioCondition, offer, request, eval_result ) &&
			eval_result.IsBooleanValue(val) && val ) {

			// 5. Satisfies standard rank condition?
			if( EvalExprTree( stdRankCondition, offer , request , eval_result ) &&
				eval_result.IsBooleanValue(val) && val )  
			{
				if( verbose )
					sprintf( return_buff, "%sAvailable\n", return_buff );
				available++;
				continue;
			} else {
				// 6.  Satisfies preemption rank condition?
				if( EvalExprTree( preemptRankCondition, offer, request, eval_result ) &&
					eval_result.IsBooleanValue(val) && val )
				{
					// 7.  Tripped on PREEMPTION_REQUIREMENTS?
					if( EvalExprTree( preemptionReq, offer , request , eval_result ) &&
						eval_result.IsBooleanValue(val) && !val ) 
					{
						fPreemptReqTest++;
						if (fPreemptReqTest != 1) {
							fPreemptReqTestStr += ", ";
						}
						fPreemptReqTestStr += buffer;
						if( verbose ) {
							sprintf( return_buff,
									"%sCan preempt %s, but failed "
									"PREEMPTION_REQUIREMENTS test\n",
									return_buff,
									remoteUser);
						}
						continue;
					} else {
						// not held
						if( verbose ) {
							sprintf( return_buff,
								"%sAvailable (can preempt %s)\n",
								return_buff, remoteUser);
						}
						available++;
					}
				} else {
					// failed 6 and 5, but satisfies 4; so have priority
					// but not better or equally preferred than current
					// customer
					// NOTE: In practice this often indicates some
					// unknown problem.
				  if (last_rej_match_time != 0) {
					fRankCond++;
				  } else {
				    sprintf( return_buff,
					     "---\n%03d.%03d:  Request has not yet been considered by the matchmaker.\n\n", cluster,
					     proc );
				    return return_buff;
				  }
				}
			} 
		} else {
			// failed 4
			fPreemptPrioCond++;
			if (fPreemptPrioCond != 1) {
				fPreemptPrioStr += ", ";
			}
			fPreemptPrioStr += buffer;
			if( verbose ) {
				sprintf( return_buff,
					"%sInsufficient priority to preempt %s\n" , 
					return_buff, remoteUser );
			}
			continue;
		}
	}
	startdAds.Close();

	fReqConstraintStr += "]";
	fOffConstraintStr += "]";
	fOfflineStr += "]";
	fPreemptPrioStr += "]";
	fPreemptReqTestStr += "]";
	fRankCondStr += "]";

	sprintf( return_buff, 
		 "%s---\n%03d.%03d:  Run analysis summary.  Of %d machines,\n"
		 "  %5d are rejected by your job's requirements %s\n"
		 "  %5d reject your job because of their own requirements %s\n"
		 "  %5d match but are serving users with a better priority in the pool%s %s\n"
		 "  %5d match but reject the job for unknown reasons %s\n"
		 "  %5d match but will not currently preempt their existing job %s\n"
         "  %5d match but are currently offline %s\n"
		 "  %5d are available to run your job\n",
		return_buff, cluster, proc, totalMachines,
		fReqConstraint, verbose ? fReqConstraintStr.c_str() : "",
		fOffConstraint, verbose ? fOffConstraintStr.c_str() : "",
		fPreemptPrioCond, niceUser ? "(*)" : "", verbose ? fPreemptPrioStr.c_str() : "",
		fRankCond, verbose ? fRankCondStr.c_str() : "",
		fPreemptReqTest,  verbose ? fPreemptReqTestStr.c_str() : "",
		fOffline, verbose ? fOfflineStr.c_str() : "",
		available );

	if (last_match_time) {
		time_t t = (time_t)last_match_time;
		sprintf( return_buff, "%s\tLast successful match: %s",
				 return_buff, ctime(&t) );
	} else if (last_rej_match_time) {
		strcat( return_buff, "\tNo successful match recorded.\n" );
	}
	if (last_rej_match_time > last_match_time) {
		time_t t = (time_t)last_rej_match_time;
		string timestring(ctime(&t));
		string rej_str="\tLast failed match: " + timestring + '\n';
		strcat(return_buff, rej_str.c_str());
		string rej_reason;
		if (request->LookupString(ATTR_LAST_REJ_MATCH_REASON, rej_reason)) {
			rej_str="\tReason for last match failure: " + rej_reason + '\n';
			strcat(return_buff, rej_str.c_str());	
		}
	}

	if( niceUser ) {
		sprintf( return_buff, 
				 "%s\n\t(*)  Since this is a \"nice-user\" request, this request "
				 "has a\n\t     very low priority and is unlikely to preempt other "
				 "requests.\n", return_buff );
	}
			

	if( fReqConstraint == totalMachines ) {
		strcat( return_buff, "\nWARNING:  Be advised:\n");
		strcat( return_buff, "   No resources matched request's constraints\n");
        if (!better_analyze) {
            ExprTree *reqExp;
            sprintf( return_buff, "%s   Check the %s expression below:\n\n" , 
                     return_buff, ATTR_REQUIREMENTS );
            if( !(reqExp = request->LookupExpr( ATTR_REQUIREMENTS) ) ) {
                sprintf( return_buff, "%s   ERROR:  No %s expression found" ,
                         return_buff, ATTR_REQUIREMENTS );
            } else {
				sprintf( return_buff, "%s%s = %s\n\n", return_buff,
						 ATTR_REQUIREMENTS, ExprTreeToString( reqExp ) );
            }
        }
	}

    if (better_analyze) {
        std::string buffer_string = "";
        char ana_buffer[SHORT_BUFFER_SIZE];
        
        if( fReqConstraint > 0 ) {
            analyzer.AnalyzeJobReqToBuffer( request, startdAds, buffer_string );
            strncpy( ana_buffer, buffer_string.c_str( ), SHORT_BUFFER_SIZE );
			ana_buffer[SHORT_BUFFER_SIZE-1] = '\0';
            strcat( return_buff, ana_buffer );
        }
    }

	if( fOffConstraint == totalMachines ) {
        strcat(return_buff, "\nWARNING:  Be advised:\n   Request did not match any resource's constraints\n");
	}

    if (better_analyze) {
        std::string buffer_string = "";
        char ana_buffer[SHORT_BUFFER_SIZE];
        if( fOffConstraint > 0 ) {
            buffer_string = "";
            analyzer.AnalyzeJobAttrsToBuffer( request, startdAds, buffer_string );
            strncpy( ana_buffer, buffer_string.c_str( ), SHORT_BUFFER_SIZE);
			ana_buffer[SHORT_BUFFER_SIZE-1] = '\0';
            strcat( return_buff, ana_buffer );
        }
    }

	request->LookupInteger( ATTR_JOB_UNIVERSE, universe );
	bool uses_matchmaking = false;
	MyString resource;
	switch(universe) {
			// Known valid
		case CONDOR_UNIVERSE_STANDARD:
		case CONDOR_UNIVERSE_JAVA:
		case CONDOR_UNIVERSE_VANILLA:
			break;

			// Unknown
		case CONDOR_UNIVERSE_PARALLEL:
		case CONDOR_UNIVERSE_VM:
			break;

			// Maybe
		case CONDOR_UNIVERSE_GRID:
			/* We may be able to detect when it's valid.  Check for existance
			 * of "$$(FOO)" style variables in the classad. */
			request->LookupString(ATTR_GRID_RESOURCE, resource);
			if ( strstr(resource.Value(),"$$") ) {
				uses_matchmaking = true;
				break;
			}  
			if (!uses_matchmaking) {
				sprintf( return_buff, "%s\nWARNING: Analysis is only meaningful for Grid universe jobs using matchmaking.\n", return_buff);
			}
			break;

			// Specific known bad
		case CONDOR_UNIVERSE_MPI:
			sprintf( return_buff, "%s\nWARNING: Analysis is meaningless for MPI universe jobs.\n", return_buff );
			break;

			// Specific known bad
		case CONDOR_UNIVERSE_SCHEDULER:
			/* Note: May be valid (although requiring a different algorithm)
			 * starting some time in V6.7. */
			sprintf( return_buff, "%s\nWARNING: Analysis is meaningless for Scheduler universe jobs.\n", return_buff );
			break;

			// Unknown
			/* These _might_ be meaningful, especially if someone adds a 
			 * universe but fails to update this code. */
		//case CONDOR_UNIVERSE_PIPE:
		//case CONDOR_UNIVERSE_LINDA:
		//case CONDOR_UNIVERSE_MAX:
		//case CONDOR_UNIVERSE_MIN:
		//case CONDOR_UNIVERSE_PVM:
		//case CONDOR_UNIVERSE_PVMD:
		default:
			sprintf( return_buff, "%s\nWARNING: Job universe unknown.  Analysis may not be meaningful.\n", return_buff );
			break;
	}


	//printf("%s",return_buff);
	return return_buff;
}


static int
findSubmittor( char *name ) 
{
	MyString 	sub(name);
	int			last = prioTable.getlast();
	int			i;
	
	for( i = 0 ; i <= last ; i++ ) {
		if( prioTable[i].name == sub ) return i;
	}

	prioTable[i].name = sub;
	prioTable[i].prio = 0.5;

	return i;
}


static char*
fixSubmittorName( char *name, int niceUser )
{
	static 	bool initialized = false;
	static	char * uid_domain = 0;
	static	char buffer[128];

	if( !initialized ) {
		uid_domain = param( "UID_DOMAIN" );
		if( !uid_domain ) {
			fprintf( stderr, "Error: UID_DOMAIN not found in config file\n" );
			exit( 1 );
		}
		initialized = true;
	}

    // potential buffer overflow! Hao
	if( strchr( name , '@' ) ) {
		sprintf( buffer, "%s%s%s", 
					niceUser ? NiceUserName : "",
					niceUser ? "." : "",
					name );
		return buffer;
	} else {
		sprintf( buffer, "%s%s%s@%s", 
					niceUser ? NiceUserName : "",
					niceUser ? "." : "",
					name, uid_domain );
		return buffer;
	}

	return NULL;
}

static bool read_classad_file(const char *filename, ClassAdList &classads)
{
    int is_eof, is_error, is_empty;
    bool success;
    ClassAd *classad;
    FILE *file;

    file = safe_fopen_wrapper_follow(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Can't open file of job ads: %s\n", filename);
		return false;
    } else {
        do {
            classad = new ClassAd(file, "\n", is_eof, is_error, is_empty);
            if (!is_error && !is_empty) {
                classads.Insert(classad);
            }
			else {
				delete classad;
			}
        } while (!is_eof && !is_error);
        if (is_error) {
            success = false;
        } else {
            success = true;
        }
		fclose(file);
    }
    return success;
}

#ifdef HAVE_EXT_POSTGRESQL

/* get the quill address for the quillName specified */
static QueryResult getQuillAddrFromCollector(char *quill_name, char *&quill_addr) {
	QueryResult query_result = Q_OK;
	char		query_constraint[1024];
	CondorQuery	quillQuery(QUILL_AD);
	ClassAdList quillList;
	ClassAd		*ad;

	sprintf (query_constraint, "%s == \"%s\"", ATTR_NAME, quill_name);
	quillQuery.addORConstraint (query_constraint);

	query_result = Collectors->query ( quillQuery, quillList );

	quillList.Open();	
	while ((ad = quillList.Next())) {
		ad->LookupString(ATTR_MY_ADDRESS, &quill_addr);
	}
	quillList.Close();
	return query_result;
}


static char * getDBConnStr(char const *&quill_name,
                           char const *&databaseIp,
                           char const *&databaseName,
                           char const *&query_password) {
	char            *host, *port, *dbconn;
	const char *ptr_colon;
	char            *tmpquillname, *tmpdatabaseip, *tmpdatabasename, *tmpquerypassword;
	int             len, tmp1, tmp2, tmp3;

	if((!quill_name && !(tmpquillname = param("QUILL_NAME"))) ||
	   (!databaseIp && !(tmpdatabaseip = param("QUILL_DB_IP_ADDR"))) ||
	   (!databaseName && !(tmpdatabasename = param("QUILL_DB_NAME"))) ||
	   (!query_password && !(tmpquerypassword = param("QUILL_DB_QUERY_PASSWORD")))) {
		fprintf( stderr, "Error: Could not find database related parameter\n");
		fprintf(stderr, "\n");
		print_wrapped_text("Extra Info: "
                       "The most likely cause for this error "
                       "is that you have not defined "
                       "QUILL_NAME/QUILL_DB_IP_ADDR/"
                       "QUILL_DB_NAME/QUILL_DB_QUERY_PASSWORD "
                       "in the condor_config file.  You must "
						   "define this variable in the config file", stderr);

		exit( 1 );
	}

	if(!quill_name) {
		quill_name = tmpquillname;
	}
	if(!databaseIp) {
		if(tmpdatabaseip[0] != '<') {
				//2 for the two brackets and 1 for the null terminator
			char *tstr = (char *) malloc(strlen(tmpdatabaseip)+3);
			sprintf(tstr, "<%s>", tmpdatabaseip);
			free(tmpdatabaseip);
			databaseIp = tstr;
		}
		else {
			databaseIp = tmpdatabaseip;
		}
	}

	if(!databaseName) {
		databaseName = tmpdatabasename;
	}
	if(!query_password) {
		query_password = tmpquerypassword;
	}

	tmp1 = strlen(databaseName);
	tmp2 = strlen(query_password);
	len = strlen(databaseIp);

		//the 6 is for the string "host= " or "port= "
		//the rest is a subset of databaseIp so a size of
		//databaseIp is more than enough
	host = (char *) malloc((len+6) * sizeof(char));
	port = (char *) malloc((len+6) * sizeof(char));

		//here we break up the ipaddress:port string and assign the
		//individual parts to separate string variables host and port
	ptr_colon = strchr((char *)databaseIp, ':');
	strcpy(host, "host=");
	strncat(host,
			databaseIp+1,
			ptr_colon - databaseIp -1);
	strcpy(port, "port=");
	strcat(port, ptr_colon+1);
	port[strlen(port)-1] = '\0';

		//tmp3 is the size of dbconn - its size is estimated to be
		//(2 * len) for the host/port part, tmp1 + tmp2 for the
		//password and dbname part and 1024 as a cautiously
		//overestimated sized buffer
	tmp3 = (2 * len) + tmp1 + tmp2 + 1024;
	dbconn = (char *) malloc(tmp3 * sizeof(char));
	sprintf(dbconn, "%s %s user=quillreader password=%s dbname=%s",
			host, port, query_password, databaseName);

	free(host);
	free(port);
	return dbconn;
}

static void exec_db_query(const char *quill_name, const char *db_ipAddr, const char *db_name, const char *query_password) {
	char *dbconn=NULL;
	
	dbconn = getDBConnStr(quill_name, db_ipAddr, db_name, query_password);

	printf ("\n\n-- Quill: %s : %s : %s\n", quill_name, 
			db_ipAddr, db_name);

	if (avgqueuetime) {
		Q.rawDBQuery(dbconn, AVG_TIME_IN_QUEUE);
	}
	if(dbconn) {
		free(dbconn);
	}

}

#endif /* HAVE_EXT_POSTGRESQL */

void warnScheddLimits(Daemon *schedd,ClassAd *job,MyString &result_buf) {
	if( !schedd ) {
		return;
	}
	ASSERT( job );

	ClassAd *ad = schedd->daemonAd();
	if (ad) {
		bool exhausted = false;
		ad->LookupBool("SwapSpaceExhausted", exhausted);
		if (exhausted) {
			result_buf.sprintf_cat("WARNING -- this schedd is not running jobs because it believes that doing so\n");
			result_buf.sprintf_cat("           would exhaust swap space and cause thrashing.\n");
			result_buf.sprintf_cat("           Set RESERVED_SWAP to 0 to tell the scheduler to skip this check\n");
			result_buf.sprintf_cat("           Or add more swap space.\n");
			result_buf.sprintf_cat("           The analysis code does not take this into consideration\n");
		}

		int maxJobsRunning 	= -1;
		int totalRunningJobs= -1;

		ad->LookupInteger( ATTR_MAX_JOBS_RUNNING, maxJobsRunning);
		ad->LookupInteger( ATTR_TOTAL_RUNNING_JOBS, totalRunningJobs);

		if ((maxJobsRunning > -1) && (totalRunningJobs > -1) && 
			(maxJobsRunning == totalRunningJobs)) { 
			result_buf.sprintf_cat("WARNING -- this schedd has hit the MAX_JOBS_RUNNING limit of %d\n", maxJobsRunning);
			result_buf.sprintf_cat("       to run more concurrent jobs, raise this limit in the config file\n");
			result_buf.sprintf_cat("       NOTE: the matchmaking analysis does not take the limit into consideration\n");
		}

		int status = -1;
		job->LookupInteger(ATTR_JOB_STATUS,status);
		if( status != RUNNING && status != TRANSFERRING_OUTPUT && status != SUSPENDED ) {

			int universe = -1;
			job->LookupInteger(ATTR_JOB_UNIVERSE,universe);

			char const *schedd_requirements_attr = NULL;
			switch( universe ) {
			case CONDOR_UNIVERSE_SCHEDULER:
				schedd_requirements_attr = ATTR_START_SCHEDULER_UNIVERSE;
				break;
			case CONDOR_UNIVERSE_LOCAL:
				schedd_requirements_attr = ATTR_START_LOCAL_UNIVERSE;
				break;
			}

			if( schedd_requirements_attr ) {
				MyString schedd_requirements_expr;
				ExprTree *expr = ad->LookupExpr(schedd_requirements_attr);
				if( expr ) {
					schedd_requirements_expr = ExprTreeToString(expr);
				}
				else {
					schedd_requirements_expr = "UNDEFINED";
				}

				int req = 0;
				if( !ad->EvalBool(schedd_requirements_attr,job,req) ) {
					result_buf.sprintf_cat("WARNING -- this schedd's policy %s failed to evalute for this job.\n",schedd_requirements_expr.Value());
				}
				else if( !req ) {
					result_buf.sprintf_cat("WARNING -- this schedd's policy %s evalutes to false for this job.\n",schedd_requirements_expr.Value());
				}
			}
		}
	}
}
