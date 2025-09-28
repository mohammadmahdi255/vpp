add_vpp_plugin(detunnel
	SOURCES
		plugin.c
		ethernet_node.c

	MULTIARCH_SOURCES
        ethernet_node.c

	INSTALL_HEADERS
        detunnel.h
)