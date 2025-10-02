add_vpp_plugin(detunnel
	SOURCES
		detunnel.c
		ethernet_node.c
		plugin.c
		vlan_node.c

	MULTIARCH_SOURCES
        ethernet_node.c
		vlan_node.c

	INSTALL_HEADERS
        detunnel.h
)