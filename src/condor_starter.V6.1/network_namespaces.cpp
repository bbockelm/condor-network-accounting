
#include "condor_common.h"
#include "condor_arglist.h"
#include "my_popen.h"

#include "network_namespaces.h"

NetworkNamespaceManager::NetworkNamespaceManager(std::string uniq_namespace) :
	network_namespace(uniq_namespace), state(UNCREATED)
	{}

int NetworkNamespaceManager::CreateNamespace() {
	if (state != UNCREATED) {
		dprintf(D_FULLDEBUG, "Internal bug: NetworkNamespaceManager::CreateNamespace has already been invoked.\n");
		state = FAILED;
		return 1;
	}

	const char * namespace_script;
	int rc = 0;

	namespace_script = param("NETWORK_NAMESPACE_SCRIPT");

	if ((rc = CreateNetworkPipe())) {
		dprintf(D_ALWAYS, "Unable to create a new set of network pipes; cannot create a namespace.\n");
		state = FAILED;
		return rc;
	}

	ArgList args;
	args.AppendArg(namespace_script);
	args.AppendArg(network_namespace);
	args.AppendArg(external_pipe);

	FILE *fp = my_popen(args, "r", TRUE);
	if (fp == NULL) {
		dprintf(D_ALWAYS, "NetworkNamespaceManager::CreateNamespace: my_popen failure on %s: (errno=%d) %s\n", args.GetArg(0), errno, strerror(errno));
		state = FAILED;
		return 1;
	}

	MyString str;
	while (str.readLine(fp, true));
	int ret = my_pclose(fp);
	str.trim();
	if (ret) {
		dprintf(D_ALWAYS, "NetworkNamespaceManager::CreateNamespace: %s exited with status %d and following output:\n %s\n", args.GetArg(0), ret, str.Value());
		state = FAILED;
		return ret;
	}

	if (!internal_address.from_ip_string(str)) {
		dprintf(D_ALWAYS, "NetworkNamespaceManager::CreateNamespace: Invalid IP %s for internal namespace.\n", str.Value());
		state = FAILED;
		return 1;
	}

	state = CREATED;
	return 0;
}

CreateNetworkPipe() {
	lxc_veth_create("veth0", "veth1");
}

