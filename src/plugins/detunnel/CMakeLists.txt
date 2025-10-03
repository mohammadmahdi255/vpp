add_vpp_plugin(detunnel
	SOURCES
		detunnel.c
		ethernet_detunnel.c
		plugin.c
		vlan_node.c

	MULTIARCH_SOURCES
        ethernet_detunnel.c
		vlan_node.c

	INSTALL_HEADERS
        detunnel.h
)