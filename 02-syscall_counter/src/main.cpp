/*
  Copyright (c) 2021-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <chrono>
#include <thread>

#include <common/bpfmap.h>
#include <common/utils.h>

#include <sys/sysinfo.h>

/*
  In this program, we'll create and load a BPF probe that counts how many time
  a given syscall is used on each CPU core.

  Once the program is running, use the following commands to trigger new events:

    touch test_file
    chmod 777 test_file
*/

// Event to trace
const std::string kSyscallName{"fchmodat"};

// This function generates the BPF program entry point
std::unique_ptr<llvm::Module> generateBPFModule(llvm::LLVMContext &context,
                                                int map_fd) {
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

  // Create the entry basic block
  auto entry_bb = llvm::BasicBlock::Create(context, "entry", function);
  builder.SetInsertPoint(entry_bb);

  // Map keys are passed by pointer; create a buffer on the stack and initialize
  // it
  auto map_key_buffer = builder.CreateAlloca(builder.getInt32Ty());
  builder.CreateStore(builder.getInt32(0U), map_key_buffer);

  // Attempt to acquire a pointer to the first element of our map; since we are
  // using an array, this should never fail. Since we are dealing with a per-CPU
  // map, the pointer we get back refers to a private copy of this value that is
  // dedicated to the CPU we are currently being running on
  auto counter_ptr =
      bpfMapLookupElem(builder, map_key_buffer, builder.getInt32Ty(), map_fd);

  // Check the pointer and make sure the lookup has succeeded; this is
  // mandatory, or the BPF verifier will refuse to load our program
  auto null_ptr = llvm::Constant::getNullValue(counter_ptr->getType());
  auto cond = builder.CreateICmpEQ(null_ptr, counter_ptr);

  auto error_bb = llvm::BasicBlock::Create(context, "error", function);
  auto continue_bb = llvm::BasicBlock::Create(context, "continue", function);

  builder.CreateCondBr(cond, error_bb, continue_bb);

  // Terminate the program if the pointer is not valid
  builder.SetInsertPoint(error_bb);
  builder.CreateRet(builder.getInt64(0));

  // In this new basic block, the pointer is valid
  builder.SetInsertPoint(continue_bb);
  auto counter = builder.CreateLoad(counter_ptr);

  // Increment the counter and then update the value inside the map using
  // the pointer we have obtained
  auto new_value = builder.CreateAdd(counter, builder.getInt32(1));

  builder.CreateStore(new_value, counter_ptr);
  builder.CreateRet(builder.getInt64(0));

  return module;
}

int main() {
  initializeLLVM();

  // Create a per-CPU map to store the counters; there is no race condition
  // when incrementing them, since we have a value for each processor
  auto map_fd = createMap(BPF_MAP_TYPE_PERCPU_ARRAY, 4U, 8U, 1U);
  if (map_fd < 0) {
    std::cerr << "Failed to create the map\n";
    return 1;
  }

  // Generate our BPF program
  llvm::LLVMContext context;
  auto module = generateBPFModule(context, map_fd);

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

  // Wait for 5 seconds, allowing the BPF program to receive some events
  std::cout << "Create a new file, and then run chmod on it several times.\n";

  std::cout << "Sleeping for 5 seconds...\n";
  std::this_thread::sleep_for(std::chrono::seconds(5U));

  // Determine how many processors we have; when reading from a per-CPU
  // maps we'll get a value for each processor
  auto processor_count = getProcessorCount();
  std::vector<std::uint8_t> value(processor_count * sizeof(std::uint64_t));

  // Read the counters from the map
  std::uint32_t key{0U};
  auto map_error = readMapKey(value, map_fd, &key);

  if (map_error != ReadMapError::Succeeded) {
    std::cerr << "Failed to read from the map\n";
    return 1;
  }

  // Convert the counters to a vector of 64-bit integers. Use memcpy to avoid
  // strict aliasing issues
  std::vector<std::uint64_t> per_cpu_counters(processor_count);
  std::memcpy(per_cpu_counters.data(), value.data(), value.size());

  std::cout << "How many times the tracepoint " << event_name
            << " has been called on each processor?\n";

  for (auto i = 0U; i < processor_count; ++i) {
    std::cout << "CPU #" << i << ": " << per_cpu_counters[i] << "\n";
  }

  releaseLLVM();
  return 0;
}
