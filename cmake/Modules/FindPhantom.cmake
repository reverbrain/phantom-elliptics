find_path(PHANTOM_INCLUDE_DIRS phantom/io_logger_file.H PATHS ${PHANTOM_PREFIX}/include /usr/include)

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBXML2_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(phantom DEFAULT_MSG PHANTOM_INCLUDE_DIRS)

mark_as_advanced(PHANTOM_INCLUDE_DIRS)
