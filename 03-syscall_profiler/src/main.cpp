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
  In this program we'll generate two BPF probes and use them to measure how much
  time it takes to service a system call of our choice.

  Pseudo code for the enter program:
    1. Generate a map key (process id + thread id)
    2. Get the timestamp
    3. Save the timestamp inside the hash map

  Pseudo code for the exit program:
    1. Generate a map key (process id + thread id)
    2. Lookup the timestamp we have saved earlier in the map
    3. Get the current timestamp
    4. Subtract the old timestamp from the current one
    5. Send the result to the perf event array

  Once the program is running, use the following commands to trigger new events:

    touch test_file
    chmod 777 test_file
*/

// Event to trace
const std::string kSyscallName{"fchmodat"};

// This function generates the BPF program for the enter event
std::unique_ptr<llvm::Module> generateEnterBPFModule(llvm::LLVMContext &context,
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

  // Map keys and values are passed by pointer; create two buffers on the
  // stack and initialize them
  auto map_key_buffer = builder.CreateAlloca(builder.getInt64Ty());
  auto timestamp_buffer = builder.CreateAlloca(builder.getInt64Ty());

  auto current_pid_tgid = bpfGetCurrentPidTgid(builder);
  builder.CreateStore(current_pid_tgid, map_key_buffer);

  auto timestamp = bpfKtimeGetNs(builder);
  builder.CreateStore(timestamp, timestamp_buffer);

  // Save the timestamp inside the map
  bpfMapUpdateElem(builder, map_fd, map_key_buffer, timestamp_buffer, BPF_ANY);
  builder.CreateRet(builder.getInt64(0));

  return module;
}

// This function generates the BPF program for the exit event
std::unique_ptr<llvm::Module> generateExitBPFModule(llvm::LLVMContext &context,
                                                    int perf_fd, int map_fd) {

  // Create the LLVM module for the BPF program
  auto module = createBPFModule(context);

  // BPF programs are made of a single function; this time, we need to access
  // the first parameter so we can pass it as the 'ctx' parameter of the
  // bpf_perf_event_output() helper.
  //
  // We are not actually dereferencing it, so it doesn't matter how we define it
  // as long as we pass it as it is
  llvm::IRBuilder<> builder(context);
  auto context_ptr = builder.getInt8PtrTy();

  auto function_type =
      llvm::FunctionType::get(builder.getInt64Ty(), {context_ptr}, false);

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
  auto map_key_buffer = builder.CreateAlloca(builder.getInt64Ty());
  auto current_pid_tgid = bpfGetCurrentPidTgid(builder);
  builder.CreateStore(current_pid_tgid, map_key_buffer);

  // Check the pointer and make sure the lookup has succeeded; this is
  // mandatory, or the BPF verifier will refuse to load our program
  auto timestamp_ptr =
      bpfMapLookupElem(builder, map_key_buffer, builder.getInt64Ty(), map_fd);

  auto null_ptr = llvm::Constant::getNullValue(timestamp_ptr->getType());
  auto cond = builder.CreateICmpEQ(null_ptr, timestamp_ptr);

  auto error_bb = llvm::BasicBlock::Create(context, "error", function);
  auto continue_bb = llvm::BasicBlock::Create(context, "continue", function);

  builder.CreateCondBr(cond, error_bb, continue_bb);

  // Terminate the program if the pointer is not valid
  builder.SetInsertPoint(error_bb);
  builder.CreateRet(builder.getInt64(0));

  // In this new basic block, the pointer is valid
  builder.SetInsertPoint(continue_bb);

  // Read back the old timestamp and obtain the current one
  auto enter_timestamp =
      builder.CreateLoad(builder.getInt64Ty(), timestamp_ptr);
  auto exit_timestamp = bpfKtimeGetNs(builder);

  // Measure how much it took to go from the first instruction to the return
  auto time_consumed = builder.CreateSub(exit_timestamp, enter_timestamp);

  builder.CreateStore(time_consumed, timestamp_ptr);

  // Send the result to the perf event array
  auto ctx = function->arg_begin();
  bpfPerfEventOutput(builder, ctx, perf_fd, static_cast<std::uint32_t>(-1UL),
                     timestamp_ptr, builder.getInt64(8U));

  builder.CreateRet(builder.getInt64(0));
  return module;
}

int main() {
  initializeLLVM();

  // Remove the memory lock limits before we create the perf event array
  setRlimit();

  // Create the perf event array
  PerfEventArray perf_event_array;
  if (!createPerfEventArray(perf_event_array, 4)) {
    std::cerr << "Failed to create the perf event array\n";
    return 1;
  }

  // Create a map to store the counters
  auto map_fd = createMap(BPF_MAP_TYPE_HASH, 8U, 8U, 100U);
  if (map_fd < 0) {
    std::cerr << "Failed to create the map\n";
    return 1;
  }

  // Generate and load the enter program
  llvm::LLVMContext context;
  auto module = generateEnterBPFModule(context, map_fd);

  auto section_map = compileModule(std::move(module));
  if (section_map.size() != 1U) {
    std::cerr << "Unexpected section count\n";
    return 1;
  }

  const auto &enter_program = section_map.at("bpf_main_section");
  auto enter_program_fd = loadProgram(enter_program);
  if (enter_program_fd < 0) {
    std::cerr << "Exiting due to a load error in the enter program\n";
    return 1;
  }

  // Generate and load the exit program
  module = generateExitBPFModule(context, perf_event_array.fd, map_fd);

  section_map = compileModule(std::move(module));
  if (section_map.size() != 1U) {
    std::cerr << "Unexpected section count\n";
    return 1;
  }

  const auto &exit_program = section_map.at("bpf_main_section");
  auto exit_program_fd = loadProgram(exit_program);
  if (exit_program_fd < 0) {
    std::cerr << "Exiting due to a load error in the exit program\n";
    return 1;
  }

  // Attach the enter program
  std::string enter_event_name{"syscalls/sys_enter_" + kSyscallName};

  auto event_fd = createTracepointEvent(enter_event_name);
  if (event_fd == -1) {
    std::cerr << "Failed to create the tracepoint event fd\n";
    return 1;
  }

  if (!attachProgramToEvent(event_fd, enter_program_fd)) {
    std::cerr << "Failed to attach the enter program to the tracepoint event\n";
    return 1;
  }

  // Attach the exit program
  std::string exit_event_name{"syscalls/sys_exit_" + kSyscallName};

  event_fd = createTracepointEvent(exit_event_name);
  if (event_fd == -1) {
    std::cerr << "Failed to create the tracepoint event fd\n";
    return 1;
  }

  if (!attachProgramToEvent(event_fd, exit_program_fd)) {
    std::cerr << "Failed to attach the exit program to the tracepoint event\n";
    return 1;
  }

  // Incoming data is appended here
  PerfBufferList perf_buffer;

  std::uint64_t total_time_used{};
  std::uint64_t sample_count{};

  std::cout << "Tracing average time used to service the following syscall: "
            << kSyscallName << "\n";

  std::cout << "Collecting samples for 10 seconds...\n";

  auto start_time = std::chrono::system_clock::now();

  for (;;) {
    // Data that is ready for processing is moved inside here
    PerfBufferList data;
    if (!readPerfEventArray(data, perf_buffer, perf_event_array, 1)) {
      std::cerr << "Failed to read from the perf event array\n";
      return 1;
    }

    // Inspect the buffers we have received
    for (const auto &buffer : data) {
      if (buffer.size() != 8U) {
        std::cout << "Unexpected buffer size: " << buffer.size() << "\n";
        continue;
      }

      // Read each sample and update the counters; use memcpy to avoid
      // strict aliasing issues
      std::uint64_t time_used{};
      std::memcpy(&time_used, buffer.data(), 8U);

      total_time_used += time_used;
      ++sample_count;

      std::cout << time_used << "ns\n";
    }

    // Exit after 10 seconds
    auto elapsed_msecs = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::system_clock::now() - start_time)
                             .count();

    if (elapsed_msecs > 10000) {
      break;
    }
  }

  // Print a summary of the data we have collected
  std::cout << "Total time used: " << total_time_used << " nsecs\n";
  std::cout << "Sample count: " << sample_count << "\n";
  std::cout << "Average: " << (total_time_used / sample_count) << " nsecs\n";

  releaseLLVM();
  return 0;
}
