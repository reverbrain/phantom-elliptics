find_path(ELLIPTICS_INCLUDE_DIR elliptics/cppdef.h PATHS ${ELLIPTICS_PREFIX}/include /usr/include)
find_path(eblob_INCLUDE_DIR eblob/blob.h PATHS ${EBLOB_PREFIX}/include /usr/include)
find_path(cocaine_INCLUDE_DIR cocaine/binary.hpp PATHS ${COCAINE_PREFIX}/include /usr/include)

find_library(ELLIPTICS_LIBRARY NAMES elliptics PATHS ${ELLIPTICS_PREFIX}/lib ${ELLIPTICS_PREFIX}/lib64 /usr/lib /usr/lib64)
find_library(ELLIPTICS_cpp_LIBRARY NAMES elliptics_cpp PATHS ${ELLIPTICS_PREFIX}/lib ${ELLIPTICS_PREFIX}/lib64 /usr/lib /usr/lib64)
find_library(eblob_LIBRARY NAMES eblob PATHS ${EBLOB_PREFIX}/lib ${EBLOB_PREFIX}/lib64 /usr/lib /usr/lib64)

set(ELLIPTICS_LIBRARIES ${ELLIPTICS_LIBRARY} ${ELLIPTICS_cpp_LIBRARY} ${eblob_LIBRARY})
set(ELLIPTICS_INCLUDE_DIRS ${ELLIPTICS_INCLUDE_DIR} ${eblob_INCLUDE_DIR} ${cocaine_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBXML2_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(elliptics DEFAULT_MSG	ELLIPTICS_LIBRARIES ELLIPTICS_INCLUDE_DIRS)

mark_as_advanced(ELLIPTICS_INCLUDE_DIRS ELLIPTICS_LIBRARIES)
