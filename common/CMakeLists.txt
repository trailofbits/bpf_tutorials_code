#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library(common INTERFACE)
target_include_directories(common INTERFACE include)

target_link_libraries(common INTERFACE
  cxx_target_settings
  thirdparty_llvm
)
