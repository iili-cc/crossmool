#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "crossmool::crossmool" for configuration "Debug"
set_property(TARGET crossmool::crossmool APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(crossmool::crossmool PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/lib/crossmool.lib"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/bin/crossmool.dll"
  )

list(APPEND _cmake_import_check_targets crossmool::crossmool )
list(APPEND _cmake_import_check_files_for_crossmool::crossmool "${_IMPORT_PREFIX}/lib/crossmool.lib" "${_IMPORT_PREFIX}/bin/crossmool.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
