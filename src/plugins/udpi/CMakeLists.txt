find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)
pkg_check_modules(RDKAFKA REQUIRED IMPORTED_TARGET rdkafka)

enable_language(CXX)                          # <-- this is the fix

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost 1.90 REQUIRED)

include_directories(
	${DPDK_INCLUDE_DIRS}
	${RDKAFKA_INCLUDE_DIRS}
)

link_directories(
	${DPDK_LIBRARY_DIRS}
	${RDKAFKA_LIBRARY_DIRS}
)

add_vpp_plugin(udpi
	SOURCES
		config.c
		kafka_producer.c
		metadata_generator.c
		plugin.c
		producer.c
		session_classifier.c
		session_v4_lookup.c
		session_v6_lookup.c
		boost_flat_map_template.cpp

	MULTIARCH_SOURCES
		producer.c
		session_classifier.c
		session_v4_lookup.c
		session_v6_lookup.c

	LINK_FLAGS
		${DPDK_LDFLAGS}
		${RDKAFKA_LDFLAGS}

	LINK_LIBRARIES
		${DPDK_LIBRARIES}
		${RDKAFKA_LIBRARIES}
		detunnel_commons
)