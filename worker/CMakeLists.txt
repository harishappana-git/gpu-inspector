cmake_minimum_required(VERSION 3.24)
# Select before project() so compiler probes also use the static MSVC runtime.
# This property has no effect on non-MSVC compilers.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
project(gri_worker VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(GRI_BUILD_CUDA "Build the CUDA worker (requires NVIDIA CUDA Toolkit)" OFF)

# Host validation is part of every measured sample. A single-config generator's
# unoptimized default can spend the entire method budget checking the readback.
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

enable_testing()
add_executable(gri-known-answer-test tests/known_answer.cpp)
target_include_directories(gri-known-answer-test PRIVATE include)
if(MSVC)
  target_compile_options(gri-known-answer-test PRIVATE /W4 /permissive-)
else()
  target_compile_options(gri-known-answer-test PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME cpu-known-answers-and-synthetic-corruption COMMAND gri-known-answer-test)

if(GRI_BUILD_CUDA)
  if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "The CUDA worker requires a 64-bit host toolchain")
  endif()
  if(WIN32)
    set(_gri_default_architectures "120-real;120-virtual")
  else()
    set(_gri_default_architectures "90-real;90-virtual")
  endif()
  set(GRI_CUDA_ARCHITECTURES "${_gri_default_architectures}" CACHE STRING
      "CUDA targets: 90 for H100; 120 for RTX 5080; semicolon-separated fat binaries are supported")
  set(CMAKE_CUDA_ARCHITECTURES "${GRI_CUDA_ARCHITECTURES}")
  enable_language(CUDA)
  find_package(CUDAToolkit 12.0 REQUIRED)
  foreach(_gri_arch IN LISTS GRI_CUDA_ARCHITECTURES)
    if(NOT _gri_arch MATCHES "^(90|120)(-real|-virtual)?$")
      message(FATAL_ERROR "GRI_CUDA_ARCHITECTURES supports only SM90 and SM120")
    endif()
    if(_gri_arch MATCHES "^120" AND CUDAToolkit_VERSION VERSION_LESS 12.8)
      message(FATAL_ERROR "RTX 5080 / SM120 requires CUDA Toolkit 12.8 or later")
    endif()
  endforeach()
  add_executable(gri-cuda-worker src/main.cu)
  target_include_directories(gri-cuda-worker PRIVATE include)
  target_link_libraries(gri-cuda-worker PRIVATE CUDA::cudart CUDA::cublas)
  set_target_properties(gri-cuda-worker PROPERTIES
    CUDA_STANDARD 17 CUDA_STANDARD_REQUIRED YES
    CUDA_RUNTIME_LIBRARY Shared
    CUDA_ARCHITECTURES "${GRI_CUDA_ARCHITECTURES}")
  if(WIN32)
    target_compile_definitions(gri-cuda-worker PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
  endif()
  target_compile_options(gri-cuda-worker PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--fmad=false;-lineinfo>)
  install(TARGETS gri-cuda-worker RUNTIME DESTINATION libexec)
endif()
