add_vpp_plugin(session
	SOURCES
		ethernet_node.c

	MULTIARCH_SOURCES
        ethernet_node.c

	INSTALL_HEADERS
        detunnel.h
)