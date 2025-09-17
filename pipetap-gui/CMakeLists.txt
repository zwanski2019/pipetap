# app sources
file(GLOB_RECURSE PIPETAP_GUI_APP_SOURCES
  CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/app/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/app/ui/*.cpp"
)

# ImGui core
file(GLOB PIPETAP_IMGUI_CORE
  CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/imgui/imgui.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/imgui/imgui_draw.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/imgui/imgui_tables.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/imgui/imgui_widgets.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/imgui/imgui_demo.cpp"
)

# backends live under include/imgui/backends
set(PIPETAP_IMGUI_BACKENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/include/imgui/backends/imgui_impl_win32.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/include/imgui/backends/imgui_impl_dx11.cpp
)

add_executable(pipetap-gui WIN32
  ${PIPETAP_GUI_APP_SOURCES}
  ${PIPETAP_IMGUI_CORE}
  ${PIPETAP_IMGUI_BACKENDS}
  ${CMAKE_CURRENT_SOURCE_DIR}/resource.rc
)

# Include paths:
#  - include/          (public headers)
#  - include/imgui     (imgui headers we vendor)
#  - include/imgui/backends  (so #include "imgui_impl_win32.h" works)
#  - imgui/            (imgui .cpp headers alongside sources)
target_include_directories(pipetap-gui
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/imgui
    ${CMAKE_CURRENT_SOURCE_DIR}/include/imgui/backends
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui
)

find_package(nlohmann_json CONFIG REQUIRED)

target_link_libraries(pipetap-gui
  PRIVATE
    pipetap-shared
    nlohmann_json::nlohmann_json
    d3d11
    dxgi
    d3dcompiler
)

set_target_properties(pipetap-gui PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
