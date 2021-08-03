/*
  Copyright (c) 2021-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <llvm/ExecutionEngine/SectionMemoryManager.h>

using SectionMap = std::unordered_map<std::string, std::vector<std::uint8_t>>;

// Helper class used with the execution engine (JIT) of LLVM to track section
// allocations. Useful to save our BPF opcodes.
class SectionMemoryManager final : public llvm::SectionMemoryManager {
  SectionMap &section_map;

  struct SectionBuffer final {
    std::uint8_t *buffer{nullptr};
    uintptr_t size{0U};
  };

  std::unordered_map<std::string, SectionBuffer> buffer_map;

public:
  SectionMemoryManager(SectionMap &section_map_) : section_map(section_map_) {
    section_map.clear();
  }

  virtual ~SectionMemoryManager() = default;

  virtual uint8_t *allocateCodeSection(uintptr_t size, unsigned alignment,
                                       unsigned section_id,
                                       llvm::StringRef section_name) override {

    auto buffer = llvm::SectionMemoryManager::allocateDataSection(
        size, alignment, section_id, section_name, false);

    if (buffer == nullptr) {
      return nullptr;
    }

    buffer_map.insert({section_name.str(), {buffer, size}});
    return buffer;
  }

  virtual bool finalizeMemory(std::string *error_messages) override {
    if (llvm::SectionMemoryManager::finalizeMemory(error_messages)) {
      return true;
    }

    for (const auto &p : buffer_map) {
      const auto &section_name = p.first;
      if (section_name.find("bpf_") != 0) {
        continue;
      }

      const auto &section_buffer = p.second;

      auto buffer_head = section_buffer.buffer;
      auto buffer_tail = section_buffer.buffer + section_buffer.size;

      auto buffer = std::vector<std::uint8_t>(buffer_head, buffer_tail);
      section_map.insert({section_name, std::move(buffer)});
    }

    return false;
  }
};
