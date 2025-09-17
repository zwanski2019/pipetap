add_library(pipetap-shared INTERFACE)

target_include_directories(pipetap-shared
  INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(pipetap-shared
  INTERFACE
    UNICODE _UNICODE
)
