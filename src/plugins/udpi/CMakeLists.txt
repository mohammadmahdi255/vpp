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
		plugin.c

	MULTIARCH_SOURCES

	LINK_FLAGS
		${DPDK_LDFLAGS}

	INSTALL_HEADERS
        detunnel.h

	LINK_LIBRARIES
		${DPDK_LIBRARIES}
)