
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

	NetworkNamespaceManager(std::string uniq_namespace);
	int CreateNamespace();
	int PassNamespaceToPid(pid_t pid);
	int SetInternalIP();
	int PerformJobAccounting(classad::ClassAd &);
	int Cleanup();

private:

	int CreateNetworkPipe();

	enum NAMESPACE_STATE {
		UNCREATED,
		CREATED,
		PASSED,
		INTERNAL_CONFIGURED,
		FAILED
	} state;
	std::string network_namespace;
	std::string internal_pipe;
	std::string external_pipe;
	condor_sockaddr internal_address;
	int m_sock;

};

// Decls for all the internal raw netlink / netfilter functions

extern "C" {

// Parse the firewall, look for a particular chain, and callback with the
// statistics for each matching rule with a comment.
int perform_accounting(const char * chain, int (*match_fcn)(const char *, long long));

// Add a network device of type veth
// Equivalent to: ip link add name $veth0 type veth peer name $veth1
int create_veth(int sock, const char * veth0, const char * veth1);

// Delete the network device named `eth`
// Equivalent to: ip link delete eth
int delete_veth(int sock, const char * eth);

// Change the status of the device named `eth`; to bring up, set status=IFF_UP
int set_status(int sock, const char * eth, int status);

// Add an IPv4 address (IPv6 support coming upon request) to a given device.
// Equivalent to: ip addr add $addr dev $eth
int add_address(int sock, const char * addr, const char * eth);

// Add a local route to a given destination / prefix via a device `eth`
// Equivalent to: ip route add $dest/$dst_len dev $eth
int add_local_route(int sock, const char * dest, const char * eth, int dst_len);

// Set the default route for the namespace to be through $gw
// Equivalent to: ip route add default via $gw
int add_default_route(int sock, const char * gw);

}

#endif

