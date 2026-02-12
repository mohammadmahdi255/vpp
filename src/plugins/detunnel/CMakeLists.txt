find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)

include_directories(
	${DPDK_INCLUDE_DIRS}
)

link_directories(
	${DPDK_LIBRARY_DIRS}
)

add_vpp_plugin(detunnel
	SOURCES
		cli.c
		detunnel.c
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
		detunnel.c
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

	LINK_FLAGS
		${DPDK_LDFLAGS}

	INSTALL_HEADERS
        detunnel.h

	LINK_LIBRARIES
		${DPDK_LIBRARIES}
)