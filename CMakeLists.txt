cmake_minimum_required(VERSION 3.26)

# require vcpkg via environment variable unless toolchain already provided
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VCPKG_ROOT} AND EXISTS "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE FILEPATH "vcpkg toolchain")
  else()
    message(FATAL_ERROR
      "VCPKG_ROOT must be set to your vcpkg path (e.g. C:/src/vcpkg), or pass -DCMAKE_TOOLCHAIN_FILE=<...>/vcpkg.cmake")
  endif()
endif()

project(pipetap LANGUAGES CXX)

# global C++ settings
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus /EHsc)
endif()

# subprojects
add_subdirectory(pipetap-shared)
add_subdirectory(pipetap-dll)
add_subdirectory(pipetap-gui)
add_subdirectory(pipe-test-client)
add_subdirectory(pipe-test-server)
