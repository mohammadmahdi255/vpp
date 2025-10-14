find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)

include_directories(
	${DPDK_INCLUDE_DIRS}
)

message(${DPDK_INCLUDE_DIRS})

link_directories(
	${DPDK_LIBRARY_DIRS}
)

add_vpp_plugin(detunnel
	SOURCES
		detunnel.c
		ethernet_detunnel.c
		plugin.c
		vlan_detunnel.c

	MULTIARCH_SOURCES
        ethernet_detunnel.c
		vlan_detunnel.c

	LINK_FLAGS
		${DPDK_LDFLAGS}

	INSTALL_HEADERS
        detunnel.h

	LINK_LIBRARIES
		${DPDK_LIBRARIES}
)