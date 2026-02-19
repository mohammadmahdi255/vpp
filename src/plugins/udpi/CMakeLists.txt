find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)

include_directories(
	${DPDK_INCLUDE_DIRS}
)

link_directories(
	${DPDK_LIBRARY_DIRS}
)

add_vpp_plugin(udpi
	SOURCES
		ipv4_tcp_session_lookup.c
		ipv4_udp_session_lookup.c
		ipv6_tcp_session_lookup.c
		ipv6_udp_session_lookup.c
		plugin.c
		session_classifier.c

	MULTIARCH_SOURCES
		ipv4_tcp_session_lookup.c
		ipv4_udp_session_lookup.c
		ipv6_tcp_session_lookup.c
		ipv6_udp_session_lookup.c
		session_classifier.c

	LINK_FLAGS
		${DPDK_LDFLAGS}

	LINK_LIBRARIES
		${DPDK_LIBRARIES}
		detunnel_commons
)