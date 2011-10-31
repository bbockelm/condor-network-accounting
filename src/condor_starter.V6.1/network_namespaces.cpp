
#include <net/if.h>

#include "condor_common.h"
#include "condor_config.h"
#include "condor_arglist.h"
#include "my_popen.h"

#include "network_namespaces.h"
#include "network_manipulation.h"

NetworkNamespaceManager::NetworkNamespaceManager(std::string uniq_namespace) :
	m_state(UNCREATED), m_network_namespace(uniq_namespace),
	m_internal_pipe("i_" + m_network_namespace), m_external_pipe("e_" + m_network_namespace),
	m_sock(-1)
	{
	}

int NetworkNamespaceManager::CreateNamespace() {
	if (m_state != UNCREATED) {
		dprintf(D_FULLDEBUG, "Internal bug: NetworkNamespaceManager::CreateNamespace has already been invoked.\n");
		m_state = FAILED;
		return 1;
	}

	if ((m_sock = create_socket()) < 0) {
		dprintf(D_ALWAYS, "Unable to create a socket to talk to the kernel for network namespaces.\n");
		m_state = FAILED;
		return 1;
	}

	const char * namespace_script;
	int rc = 0;

	namespace_script = param("NETWORK_NAMESPACE_SCRIPT");

	if ((rc = CreateNetworkPipe())) {
		dprintf(D_ALWAYS, "Unable to create a new set of network pipes; cannot create a namespace.\n");
		m_state = FAILED;
		return rc;
	}

	ArgList args;
	args.AppendArg(namespace_script);
	args.AppendArg(m_network_namespace);
	args.AppendArg(m_external_pipe);

	FILE *fp = my_popen(args, "r", TRUE);
	if (fp == NULL) {
		dprintf(D_ALWAYS, "NetworkNamespaceManager::CreateNamespace: my_popen failure on %s: (errno=%d) %s\n", args.GetArg(0), errno, strerror(errno));
		m_state = FAILED;
		return 1;
	}

	while (m_internal_address_str.readLine(fp, true));
	int ret = my_pclose(fp);
	m_internal_address_str.trim();
	if (ret) {
		dprintf(D_ALWAYS, "NetworkNamespaceManager::CreateNamespace: %s "
			"exited with status %d and following output: %s\n",
			 args.GetArg(0), ret, m_internal_address_str.Value());
		m_state = FAILED;
		return ret;
	}

	if (!m_internal_address.from_ip_string(m_internal_address_str)) {
		dprintf(D_ALWAYS, "NetworkNamespaceManager::CreateNamespace: Invalid IP %s for internal namespace.\n", m_internal_address_str.Value());
		m_state = FAILED;
		return 1;
	}

	m_state = CREATED;
	return 0;
}

int NetworkNamespaceManager::CreateNetworkPipe() {
	int rc, sock;
        if ((sock = create_socket()) < 0) {
                dprintf(D_ALWAYS, "Unable to create socket to talk to kernel.\n");
                m_state = FAILED;
                return -sock;
        }
	m_sock = sock;

	m_internal_pipe = "i_" + m_network_namespace;
        if ((rc = create_veth(m_sock, m_external_pipe.c_str(), m_internal_pipe.c_str()))) {
                dprintf(D_ALWAYS, "Failed to create veth devices %s/%s.\n", m_external_pipe.c_str(), m_internal_pipe.c_str());
                m_state = FAILED;
		return rc;
        }

	dprintf(D_FULLDEBUG, "Created a pair of veth devices (%s, %s).\n", m_external_pipe.c_str(), m_internal_pipe.c_str());
        
	return 0;
}

int NetworkNamespaceManager::PostCloneChild() {

	if (m_state != PASSED) {
		dprintf(D_ALWAYS, "Called PostCloneChild before PostCloneParent; current state is %d.\n", m_state);
		m_state = FAILED;
		return 1;
	}

	// Manipulate our network configuration in the child.
	// Notice that we open a new socket to the kernel - this is because the
	// other socket still talks to the original namespace.
	//
	// Note: Because we may be in a shared-memory clone, do NOT modify the heap.
	// This is why we saved the IPv4 address in m_internal_address_str instead of just
	// recreating it from m_internal_address
	int sock, rc = 0;
	if ((sock = create_socket()) < 0) {
		dprintf(D_ALWAYS, "Unable to create socket to talk to kernel for child.\n");
		rc = 1;
		goto failed_socket;
	}
	if (add_address(sock, m_internal_address_str.Value(), m_internal_pipe.c_str())) {
		dprintf(D_ALWAYS, "Unable to add address %s to %s.\n", m_internal_address_str.Value(), m_internal_pipe.c_str());
		rc = 2;
		goto finalize_child;
	}
	if (set_status(sock, m_internal_pipe.c_str(), IFF_UP)) {
		dprintf(D_ALWAYS, "Unable to bring up interface %s.\n", m_internal_pipe.c_str());
		rc = 3;
		goto finalize_child;
	}
	if (add_local_route(sock, m_internal_address_str.Value(), m_internal_pipe.c_str(), 24)) {
		dprintf(D_ALWAYS, "Unable to add local route via %s\n", m_internal_address_str.Value());
		rc = 4;
		goto finalize_child;
	}
	if (add_default_route(sock, m_internal_address_str.Value())) {
		dprintf(D_ALWAYS, "Unable to add default route via %s\n", m_internal_address_str.Value());
		rc = 5;
		goto finalize_child;
	}

finalize_child:
	close(sock);
failed_socket:
	return rc;

}
