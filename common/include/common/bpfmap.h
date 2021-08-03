/*
  Copyright (c) 2021-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

// Creates a new BPF map, using the provided settings
int createMap(bpf_map_type type, std::uint32_t key_size,
              std::uint32_t value_size, std::uint32_t key_count) {

  union bpf_attr attr = {};

  attr.map_type = type;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = key_count;

  return static_cast<int>(
      syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr)));
}

// Error codes for map operations; depending on the map type, reads may
// return NotFound if the specified key is not present
enum class ReadMapError { Succeeded, NotFound, Failed };

// Attempts to read a key from the specified map. Values in per-CPU maps
// actually have multiple entries (one per CPU)
ReadMapError readMapKey(std::vector<std::uint8_t> &value, int map_fd,
                        const void *key) {

  union bpf_attr attr = {};

  // Use memcpy to avoid string aliasing issues
  attr.map_fd = static_cast<__u32>(map_fd);
  std::memcpy(&attr.key, &key, sizeof(attr.key));

  auto value_ptr = value.data();
  std::memcpy(&attr.value, &value_ptr, sizeof(attr.value));

  auto err =
      ::syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(union bpf_attr));

  if (err >= 0) {
    return ReadMapError::Succeeded;
  }

  if (errno == ENOENT) {
    return ReadMapError::NotFound;
  } else {
    return ReadMapError::Failed;
  }
}

// Attempts to set a key in the specified map. When operating on a per-CPU map
// there should be a value for each CPU
ReadMapError setMapKey(std::vector<std::uint8_t> &value, int map_fd,
                       const void *key) {

  union bpf_attr attr = {};
  attr.flags = BPF_ANY; // Always set the value
  attr.map_fd = static_cast<__u32>(map_fd);

  // Use memcpy to avoid string aliasing issues
  std::memcpy(&attr.key, &key, sizeof(attr.key));

  auto value_ptr = value.data();
  std::memcpy(&attr.value, &value_ptr, sizeof(attr.value));

  auto err = ::syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));

  if (err < 0) {
    return ReadMapError::Failed;
  }

  return ReadMapError::Succeeded;
}
