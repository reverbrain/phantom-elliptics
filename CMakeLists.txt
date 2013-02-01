cmake_minimum_required (VERSION 2.6 FATAL_ERROR)
cmake_policy (VERSION 2.6.0)

project (phantom-elliptics)
FILE (READ "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog" DEBCHANGELOG)

string(REGEX MATCH "([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)" DEBFULLVERSION "${DEBCHANGELOG}")
string(REGEX MATCH "([0-9]+\\.[0-9]+)" PHANTOM_ELLIPTICS_VERSION_ABI "${DEBFULLVERSION}")
string(REGEX MATCH "([0-9]+\\.[0-9]+$)" PHANTOM_ELLIPTICS_VERSION_MINOR "${DEBFULLVERSION}")

set(PHANTOM_ELLIPTICS_VERSION "${PHANTOM_ELLIPTICS_VERSION_ABI}.${PHANTOM_ELLIPTICS_VERSION_MINOR}")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(Elliptics REQUIRED)
find_package(Phantom REQUIRED)

add_definitions(-std=gnu++0x -D_GNU_SOURCE=1)

include_directories(${ELLIPTICS_INCLUDE_DIRS} ${PHANTOM_INCLUDE_DIRS})

add_library(mod_io_benchmark_method_elliptics SHARED src/method_elliptics.C)
set_target_properties(mod_io_benchmark_method_elliptics PROPERTIES PREFIX "")
target_link_libraries(mod_io_benchmark_method_elliptics ${ELLIPTICS_LIBRARIES})

add_library(mod_io_benchmark_method_elliptics_source_log SHARED src/source_log/source_log.C)
set_target_properties(mod_io_benchmark_method_elliptics_source_log PROPERTIES PREFIX "")

install(FILES
	src/method_elliptics.H
	src/source.H
	DESTINATION include/phantom/io_benchmark/method_elliptics/
        )

install(TARGETS
	mod_io_benchmark_method_elliptics
	mod_io_benchmark_method_elliptics_source_log
	LIBRARY DESTINATION lib/phantom
	ARCHIVE DESTINATION lib/phantom
	BUNDLE DESTINATION library/phantom
	)

install(FILES
	example/yandex-tank-elliptics
	DESTINATION bin
	)
