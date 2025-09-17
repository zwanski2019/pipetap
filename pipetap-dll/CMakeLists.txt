file(GLOB_RECURSE PIPETAP_DLL_SOURCES
  CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/inject/*.cpp"
)

add_library(pipetap-dll SHARED ${PIPETAP_DLL_SOURCES})

target_include_directories(pipetap-dll
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_precompile_headers(pipetap-dll PRIVATE include/pch.h)

# vcpkg detours
find_path(DETOURS_INCLUDE_DIR "detours/detours.h" REQUIRED)
find_library(DETOURS_LIBRARY_RELEASE NAMES detours REQUIRED)
find_library(DETOURS_LIBRARY_DEBUG   NAMES detours detoursd)

add_library(detours::detours INTERFACE IMPORTED)
set_target_properties(detours::detours PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${DETOURS_INCLUDE_DIR}"
  INTERFACE_LINK_LIBRARIES
    "$<$<CONFIG:Debug>:${DETOURS_LIBRARY_DEBUG}>;$<$<NOT:$<CONFIG:Debug>>:${DETOURS_LIBRARY_RELEASE}>"
)

target_link_libraries(pipetap-dll
  PRIVATE
    detours::detours
    pipetap-shared
)

set_target_properties(pipetap-dll PROPERTIES
  OUTPUT_NAME "pipetap-dll"
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)
