file(GLOB PTC_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(pipe-test-client ${PTC_SOURCES})
target_link_libraries(pipe-test-client PRIVATE pipetap-shared)
set_target_properties(pipe-test-client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
