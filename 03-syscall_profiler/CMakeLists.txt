#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

project("syscall_profiler")

add_executable("${PROJECT_NAME}"
  src/main.cpp
)

target_link_libraries("${PROJECT_NAME}" PRIVATE
  common
)
