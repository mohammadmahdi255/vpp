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
		ipv4_session_lookup.c
		ipv6_session_lookup.c
		plugin.c
		udpi_classifier.c

	MULTIARCH_SOURCES
		ipv4_session_lookup.c
		ipv6_session_lookup.c
		udpi_classifier.c

	LINK_FLAGS
		${DPDK_LDFLAGS}

	LINK_LIBRARIES
		${DPDK_LIBRARIES}
		detunnel_commons
)