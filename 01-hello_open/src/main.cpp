/*
  Copyright (c) 2021-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <chrono>
#include <thread>

#include <common/utils.h>

/*
  This program assembles and loads a BPF probe that prints the 'Hello!!' string
  to the trace pipe whenever the tracepoint of our choice emits a new event.

  Once the program is running, run the following command to inspect the output:

    sudo cat /sys/kernel/debug/tracing/trace_pipe
*/

// Event to trace
const std::string kSyscallName{"openat"};

// This function generates the code that prints a string to the trace pipe
void generatePrintk(llvm::IRBuilder<> &builder) {
  // The bpf_trace_printk() function prototype can be found inside
  // the /usr/include/linux/bpf.h header file
  std::vector<llvm::Type *> argument_type_list = {builder.getInt8PtrTy(),
                                                  builder.getInt32Ty()};

  auto function_type =
      llvm::FunctionType::get(builder.getInt64Ty(), argument_type_list, true);

  auto function =
      builder.CreateIntToPtr(builder.getInt64(BPF_FUNC_trace_printk),
                             llvm::PointerType::getUnqual(function_type));

  // Allocate 8 bytes on the stack
  auto buffer = builder.CreateAlloca(builder.getInt64Ty());

  // Copy the string characters to the 64-bit integer
  static const std::string kMessage{"Hello!!"};

  std::uint64_t message{0U};
  std::memcpy(&message, kMessage.c_str(), sizeof(message));

  // Store the characters inside the buffer we allocated on the stack
  builder.CreateStore(builder.getInt64(message), buffer);

  // Print the characters
  auto buffer_ptr = builder.CreateBitCast(buffer, builder.getInt8PtrTy());

#if LLVM_VERSION_MAJOR < 11
  auto function_callee = function;
#else
  auto function_callee = llvm::FunctionCallee(function_type, function);
#endif

  builder.CreateCall(function_callee, {buffer_ptr, builder.getInt32(8U)});
}

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
  generatePrintk(builder);
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

  // Create the tracepoint event; you can find the available events under
  // the following folder: /sys/kernel/debug/tracing/events
  std::string event_name{"syscalls/sys_enter_" + kSyscallName};

  auto event_fd = createTracepointEvent(event_name);
  if (event_fd == -1) {
    std::cerr << "Failed to create the tracepoint event fd\n";
    return 1;
  }

  // Attach the program to the event we have created
  if (!attachProgramToEvent(event_fd, program_fd)) {
    std::cerr << "Failed to attach the program to the tracepoint event\n";
    return 1;
  }

  std::cout << "Sleeping for 10 seconds...\n";
  std::cout << "Run: sudo cat /sys/kernel/debug/tracing/trace_pipe\n";
  std::this_thread::sleep_for(std::chrono::seconds(10U));

  releaseLLVM();
  return 0;
}
