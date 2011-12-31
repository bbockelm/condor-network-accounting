
/*
    network_namespaces.h

    There's three essential pieces to network namespaces:
      * The outer-script: this is executed by the starter prior to doing anything else.
        It takes two arguments: a unique job identifier, and a device name.  The script
        should assume the device name is one end of a network pipe; the other end is the
        only network device available to the job.  Routing and IP should be hooked up
        appropriately.  The script should setup an iptables chain with the same name as
        the job identifier.  This chain will be used for accounting.  This script should 
        print an IP address to stdout; this IP address will be used for the internal
        side of the pipe.
      * daemon_core code: After the child forks, but before it execs, the parent will
        assign the internal network pipe to the namespace, and the child will assign
        the pipe the IP address.
      * Job accounting: Given the name of the chain, the current byte count for all
        the associated rules in the chain are inserted into the job's classad and
        sent to the schedd for the next update.
 */

#ifndef __NETWORK_NAMESPACES_H
#define __NETWORK_NAMESPACES_H

#include <string>
#include <sys/types.h>

#include "classad/classad.h"
#include "condor_sockaddr.h"

class NetworkNamespaceManager {

public:

	NetworkNamespaceManager(std::string &uniq_namespace);
	int CreateNamespace();

	/*
	 * Functions to invoke after child has been created with clone.
	 * PostCloneParent must first be called, followed by PostCloneChild,
	 * in a race-free fashion.
	 * - pid: the PID of the child process.
	 */
	int PostCloneParent(pid_t pid);
	int PostCloneChild();

	/*
	 * Perform any network accounting for this namespace.
	 * - classad: Reference to a classad to insert network accounting into.
	 */
	int PerformJobAccounting(classad::ClassAd *classad);

	/*
	 * Cleanup any persistent OS structures created by the manager.
	 */
	int Cleanup();

private:

	int CreateNetworkPipe();
	int RunCleanupScript();
	static int JobAccountingCallback(const unsigned char * rule_name, long long bytes, void * callback_data);

	enum NAMESPACE_STATE {
		UNCREATED,
		CREATED,
		PASSED,
		INTERNAL_CONFIGURED,
		FAILED,
		CLEANED
	} m_state;
	std::string m_network_namespace;
	std::string m_internal_pipe;
	std::string m_external_pipe;
	condor_sockaddr m_internal_address;
	MyString m_internal_address_str;
	int m_sock;
	bool m_created_pipe;
	classad::ClassAd m_statistics;

};

#endif

