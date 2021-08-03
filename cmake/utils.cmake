#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

function(importLLVM)
  find_package(LLVM 10 REQUIRED)

  add_library(thirdparty_llvm INTERFACE)
  target_link_libraries(thirdparty_llvm INTERFACE
    LLVMMCJIT
    LLVMBPFCodeGen
    LLVMX86CodeGen
  )

  # Ubuntu/Debian workarounds
  if(EXISTS "/usr/include/llvm-${LLVM_VERSION_MAJOR}")
    list(APPEND LLVM_INCLUDE_DIRS "/usr/include/llvm-${LLVM_VERSION_MAJOR}")
  endif()

  target_include_directories(thirdparty_llvm SYSTEM INTERFACE
    ${LLVM_INCLUDE_DIRS}
  )

  target_compile_definitions(thirdparty_llvm INTERFACE
    ${LLVM_DEFINITIONS}
  )
endfunction()

function(generateSettingsTarget)
  add_library(cxx_target_settings INTERFACE)
  target_compile_options(cxx_target_settings INTERFACE
    -Wall
    -pedantic
    -Wconversion
    -Wunused
    -Wshadow
    -fvisibility=hidden
    -Werror
    -Wno-deprecated-declarations
  )

  set_target_properties(cxx_target_settings PROPERTIES
    INTERFACE_POSITION_INDEPENDENT_CODE ON
  )

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    list(APPEND compile_option_list -O0)
    list(APPEND compile_definition_list DEBUG)

  else()
    list(APPEND compile_option_list -O2)
    list(APPEND compile_definition_list NDEBUG)
  endif()

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    list(APPEND compile_option_list -g3)
  else()
    list(APPEND compile_option_list -g0)
  endif()

  target_compile_options(cxx_target_settings INTERFACE
    ${compile_option_list}
  )

  target_compile_definitions(cxx_target_settings INTERFACE
    ${compile_definition_list}
  )

  if(BPF_TUTORIALS_ENABLE_SANITIZERS)
    message(STATUS "bpf_tutorials: Sanitizers are enabled")

    target_compile_options(cxx_target_settings INTERFACE
      -fno-omit-frame-pointer
      -fsanitize=undefined,address
    )

    target_link_options(cxx_target_settings INTERFACE
      -fsanitize=undefined,address
    )

  else()
    message(STATUS "bpf_tutorials: Sanitizers are NOT enabled")
  endif()

  target_compile_features(cxx_target_settings INTERFACE cxx_std_14)
endfunction()
