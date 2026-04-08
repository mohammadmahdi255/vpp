find_package(PkgConfig REQUIRED)

add_vpp_library(detunnel_commons
	SOURCES
		detunnel.c

	MULTIARCH_SOURCES
		detunnel.c

	INSTALL_HEADERS
		detunnel.h
		simd_type.h
)

set(MULTIARCH_SOURCES
	detunnel_output.c
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
)

add_vpp_plugin(detunnel
	SOURCES
		${MULTIARCH_SOURCES}
		cli.c
		plugin.c

	MULTIARCH_SOURCES
		${MULTIARCH_SOURCES}

	LINK_LIBRARIES
		detunnel_commons
)