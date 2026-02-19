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
		session_v4_lookup.c
		session_v6_lookup.c
		plugin.c
		session_classifier.c

	MULTIARCH_SOURCES
		session_v4_lookup.c
		session_v6_lookup.c
		session_classifier.c

	LINK_FLAGS
		${DPDK_LDFLAGS}

	LINK_LIBRARIES
		${DPDK_LIBRARIES}
		detunnel_commons
)