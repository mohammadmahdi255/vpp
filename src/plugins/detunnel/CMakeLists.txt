find_package(PkgConfig REQUIRED)

add_vpp_library(detunnel_commons
	SOURCES
		detunnel.c

	MULTIARCH_SOURCES
		detunnel.c

	INSTALL_HEADERS
		detunnel.h
)

add_vpp_plugin(detunnel
	SOURCES
		cli.c
		ethernet_detunnel.c
		failed_detunnel.c
		gre_detunnel.c
		gtpu_detunnel.c
		ipv4_detunnel.c
		ipv6_detunnel.c
		l2tp_detunnel.c
		mpls_detunnel.c
		plugin.c
		ppp_detunnel.c
		pppoe_detunnel.c
		tcp_detunnel.c
		udp_detunnel.c
		vlan_detunnel.c

	MULTIARCH_SOURCES
		ethernet_detunnel.c
		failed_detunnel.c
		gre_detunnel.c
		gtpu_detunnel.c
		ipv4_detunnel.c
		ipv6_detunnel.c
		l2tp_detunnel.c
		mpls_detunnel.c
		ppp_detunnel.c
		pppoe_detunnel.c
		tcp_detunnel.c
		udp_detunnel.c
		vlan_detunnel.c

	LINK_LIBRARIES
		detunnel_commons
)