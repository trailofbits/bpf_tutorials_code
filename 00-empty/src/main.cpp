/*
  Copyright (c) 2021-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <chrono>
#include <thread>

#include <common/utils.h>

// This function generates the BPF program entry point
std::unique_ptr<llvm::Module> generateBPFModule(llvm::LLVMContext &context) {
  // Create the LLVM module for the BPF program
  auto module = createBPFModule(context);

  // BPF programs are made of a single function; we don't care about parameters
  // for the time being
  llvm::IRBuilder<> builder(context);
  auto function_type = llvm::FunctionType::get(builder.getInt64Ty(), {}, false);

  auto function = llvm::Function::Create(
      function_type, llvm::Function::ExternalLinkage, "main", module.get());

  // Ask LLVM to put this function in its own section, so we can later find it
  // more easily after we have compiled it to BPF code
  function->setSection("bpf_main_section");

  // Create the entry basic block and assemble the printk code using the helper
  // we have written
  auto entry_bb = llvm::BasicBlock::Create(context, "entry", function);

  builder.SetInsertPoint(entry_bb);
  builder.CreateRet(builder.getInt64(0));

  return module;
}

int main() {
  initializeLLVM();

  // Generate our BPF program
  llvm::LLVMContext context;
  auto module = generateBPFModule(context);

  // JIT the module to BPF code using the execution engine
  auto section_map = compileModule(std::move(module));
  if (section_map.size() != 1U) {
    std::cerr << "Unexpected section count\n";
    return 1;
  }

  // We have previously asked LLVM to create our function inside a specific
  // section; get our code back from it and load it
  const auto &main_program = section_map.at("bpf_main_section");
  auto program_fd = loadProgram(main_program);
  if (program_fd < 0) {
    return 1;
  }

  releaseLLVM();
  return 0;
}
