#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.1)
project("bpf_tutorials")

include("cmake/options.cmake")
include("cmake/utils.cmake")

importLLVM()
generateSettingsTarget()

add_subdirectory("common")

set(project_folder_list
  "00-empty"
  "01-hello_open"
  "02-syscall_counter"
  "03-syscall_profiler"
)

foreach(project_folder ${project_folder_list})
  add_subdirectory("${project_folder}")
endforeach()
