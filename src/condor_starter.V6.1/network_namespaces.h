
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

#include "classad/classad_distribution.h"
#include "condor_sockaddr.h"

class NetworkNamespaceManager {

public:

    NetworkNamespaceManager(std::string uniq_namespace);
    int CreateNamespace();
    int PassNamespaceToPid(pid_t pid);
    int SetInternalIP();
    int PerformJobAccounting(classad::ClassaAd &);
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

};

#endif

