file(GLOB PTS_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(pipe-test-server ${PTS_SOURCES})
target_link_libraries(pipe-test-server PRIVATE pipetap-shared)
set_target_properties(pipe-test-server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
