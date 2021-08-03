/*
  Copyright (c) 2021-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>

#include <common/bpfmap.h>
#include <common/sectionmemorymanager.h>

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/ManagedStatic.h>

#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <unistd.h>

namespace {
std::uint32_t getProcessorCountHelper() {
  const std::string kPossibleCPUCount{"/sys/devices/system/cpu/possible"};

  auto fd = open(kPossibleCPUCount.c_str(), O_RDONLY);
  if (fd == -1) {
    throw std::runtime_error(
        "Could not determine the processor count: open() failed");
  }

  struct stat file_stat {};
  if (fstat(fd, &file_stat) != 0) {
    throw std::runtime_error(
        "Could not determine the processor count: fstat() failed");
  }

  auto file_size = static_cast<std::size_t>(file_stat.st_size);

  std::string buffer(file_size, 0U);
  if (read(fd, &buffer[0], buffer.size()) < 0) {
    throw std::runtime_error(
        "Could not to determine the processor count: read() failed");
  }

  close(fd);

  auto separator_index = buffer.find_last_of("-");
  if (separator_index == std::string::npos ||
      separator_index + 1U >= buffer.size()) {
    std::cout << separator_index << std::endl;
    throw std::runtime_error("Could not to determine the processor count: the "
                             "group separator was not found");
  }

  const char *string_cpu_count = &buffer[separator_index + 1U];

  char *null_term_ptr{nullptr};
  auto processor_count = static_cast<std::uint32_t>(
      std::strtoul(string_cpu_count, &null_term_ptr, 10));

  if (processor_count == 0U || null_term_ptr == nullptr ||
      *null_term_ptr != '\n') {
    throw std::runtime_error(
        "Could not to determine the processor count: invalid format");
  }

  return processor_count + 1U;
}
} // namespace

// Returns the total amount of possible CPUs (online + offline + unconfigured)
std::uint32_t getProcessorCount() {
  static const std::uint32_t kProcessorCount = getProcessorCountHelper();
  return kProcessorCount;
}

// Creates a new LLVM module
std::unique_ptr<llvm::Module> createBPFModule(llvm::LLVMContext &context) {
  auto module = std::make_unique<llvm::Module>("BPFModule", context);
  module->setTargetTriple("bpf-pc-linux");
  module->setDataLayout("e-m:e-p:64:64-i64:64-n32:64-S128");

  return module;
}

// LLVM initialization
void initializeLLVM() {
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFAsmPrinter();
  LLVMLinkInMCJIT();
}

// Releases the LLVM resources
void releaseLLVM() { llvm::llvm_shutdown(); }

// Removes the memory lock limits, useful when mapping a lot of memory
// (i.e.: perf event outputs)
void setRlimit() {
  struct rlimit rl = {};
  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;

  auto error = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (error != 0) {
    throw std::runtime_error("Failed to set RLIMIT_MEMLOCK");
  }
}

// Compiles the LLVM module, using the execution engine and the
// SectionMemoryManager class to JIT the IR to BPF instructions
SectionMap compileModule(std::unique_ptr<llvm::Module> module) {
  // Create a new execution engine builder and configure it
  auto exec_engine_builder =
      std::make_unique<llvm::EngineBuilder>(std::move(module));

  exec_engine_builder->setMArch("bpf");

  SectionMap section_map;
  exec_engine_builder->setMCJITMemoryManager(
      std::make_unique<SectionMemoryManager>(section_map));

  // Create the execution engine and build the given module
  std::unique_ptr<llvm::ExecutionEngine> execution_engine(
      exec_engine_builder->create());

  execution_engine->setProcessAllSections(true);
  execution_engine->finalizeObject();

  return section_map;
}

// Loads the specified BPF program, returning its handle
int loadProgram(const std::vector<std::uint8_t> &program) {
  // The program needs to be aware how it is going to be used. We are
  // only interested in tracepoints, so we'll hardcode this value
  union bpf_attr attr = {};
  attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
  attr.log_level = 1U;

  // This is the array of (struct bpf_insn) instructions we have received
  // from the ExecutionEngine (see the compileModule() function for more
  // information)
  auto instruction_buffer_ptr = program.data();
  std::memcpy(&attr.insns, &instruction_buffer_ptr, sizeof(attr.insns));

  attr.insn_cnt =
      static_cast<std::uint32_t>(program.size() / sizeof(struct bpf_insn));

  // The license is important because we will not be able to call certain
  // helpers within the BPF VM if it is not compatible
  static const std::string kProgramLicense{"GPL"};

  auto license_ptr = kProgramLicense.c_str();
  std::memcpy(&attr.license, &license_ptr, sizeof(attr.license));

  // The verifier will provide a text disasm of our BPF program in here.
  // If there is anything wrong with our code, we'll also find some
  // diagnostic output
  std::vector<char> log_buffer(4096, 0);
  attr.log_size = static_cast<__u32>(log_buffer.size());

  auto log_buffer_ptr = log_buffer.data();
  std::memcpy(&attr.log_buf, &log_buffer_ptr, sizeof(attr.log_buf));

  auto program_fd =
      static_cast<int>(::syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr)));

  if (program_fd < 0) {
    std::cerr << "Failed to load the program: " << log_buffer.data() << "\n";
  }

  return program_fd;
}

// Creates a tracepoint-type event using the specified event name
int createTracepointEvent(const std::string &event_name) {
  const std::string kBaseEventPath = "/sys/kernel/debug/tracing/events/";

  // This special file contains the id of the tracepoint, which is
  // required to initialize the event with perf_event_open
  std::string event_id_path = kBaseEventPath + event_name + "/id";

  // Read the tracepoint id and convert it to an integer
  auto event_file = std::fstream(event_id_path, std::ios::in);
  if (!event_file) {
    return -1;
  }

  std::stringstream buffer;
  buffer << event_file.rdbuf();

  auto str_event_id = buffer.str();
  auto event_identifier = static_cast<std::uint32_t>(
      std::strtol(str_event_id.c_str(), nullptr, 10));

  // Create the event
  struct perf_event_attr perf_attr = {};
  perf_attr.type = PERF_TYPE_TRACEPOINT;
  perf_attr.size = sizeof(struct perf_event_attr);
  perf_attr.config = event_identifier;
  perf_attr.sample_period = 1;
  perf_attr.sample_type = PERF_SAMPLE_RAW;
  perf_attr.wakeup_events = 1;
  perf_attr.disabled = 1;

  int process_id{-1};
  int cpu_index{0};

  auto event_fd =
      static_cast<int>(::syscall(__NR_perf_event_open, &perf_attr, process_id,
                                 cpu_index, -1, PERF_FLAG_FD_CLOEXEC));

  return event_fd;
}

// Attaches the specified program to the event_fd event. If this succeeds, the
// event is enabled
bool attachProgramToEvent(int event_fd, int program_fd) {
  if (ioctl(event_fd, PERF_EVENT_IOC_SET_BPF, program_fd) < 0) {
    return false;
  }

  if (ioctl(event_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    return false;
  }

  return true;
}

// Returns the pseudo intrinsic, useful to convert file descriptors (like maps
// and perf event outputs) to map addresses so they can be used from the BPF VM
llvm::Function *getPseudoFunction(llvm::IRBuilder<> &builder) {
  auto &insert_block = *builder.GetInsertBlock();
  auto &module = *insert_block.getModule();

  auto pseudo_function = module.getFunction("llvm.bpf.pseudo");

  if (pseudo_function == nullptr) {
    // clang-format off
    auto pseudo_function_type = llvm::FunctionType::get(
      builder.getInt64Ty(),

      {
        builder.getInt64Ty(),
        builder.getInt64Ty()
      },

      false
    );
    // clang-format on

    pseudo_function = llvm::Function::Create(pseudo_function_type,
                                             llvm::GlobalValue::ExternalLinkage,
                                             "llvm.bpf.pseudo", module);
  }

  return pseudo_function;
}

// Converts the given (map or perf event output) file descriptor to a map
// address
llvm::Value *mapAddressFromFileDescriptor(int fd, llvm::IRBuilder<> &builder) {
  auto pseudo_function = getPseudoFunction(builder);

  // clang-format off
  auto map_integer_address_value = builder.CreateCall(
    pseudo_function,

    {
      builder.getInt64(BPF_PSEUDO_MAP_FD),
      builder.getInt64(static_cast<std::uint64_t>(fd))
    }
  );
  // clang-format on

  return builder.CreateIntToPtr(map_integer_address_value,
                                builder.getInt8PtrTy());
}

// Attempts to retrieve a pointer to the specified key inside the map_fd map
llvm::Value *bpfMapLookupElem(llvm::IRBuilder<> &builder, llvm::Value *key,
                              llvm::Type *value_type, int map_fd) {

  std::vector<llvm::Type *> argument_type_list = {builder.getInt8PtrTy(),
                                                  builder.getInt32Ty()};

  auto function_type = llvm::FunctionType::get(value_type->getPointerTo(),
                                               argument_type_list, false);

  auto function =
      builder.CreateIntToPtr(builder.getInt64(BPF_FUNC_map_lookup_elem),
                             llvm::PointerType::getUnqual(function_type));

  auto map_address = mapAddressFromFileDescriptor(map_fd, builder);

#if LLVM_VERSION_MAJOR < 11
  auto function_callee = function;
#else
  auto function_callee = llvm::FunctionCallee(function_type, function);
#endif

  return builder.CreateCall(function_callee, {map_address, key});
}

// Returns a 64-bit integer that contains both the process and thread id
llvm::Value *bpfGetCurrentPidTgid(llvm::IRBuilder<> &builder) {
  auto function_type = llvm::FunctionType::get(builder.getInt64Ty(), {}, false);

  auto function =
      builder.CreateIntToPtr(builder.getInt64(BPF_FUNC_get_current_pid_tgid),
                             llvm::PointerType::getUnqual(function_type));

#if LLVM_VERSION_MAJOR < 11
  auto function_callee = function;
#else
  auto function_callee = llvm::FunctionCallee(function_type, function);
#endif

  return builder.CreateCall(function_callee, {});
}

// Updates the value of the specified key inside the map_fd BPF map
llvm::Value *bpfMapUpdateElem(llvm::IRBuilder<> &builder, int map_fd,
                              llvm::Value *key, llvm::Value *value,
                              std::uint64_t flags) {

  // clang-format off
  std::vector<llvm::Type *> argument_type_list = {
    // Map address
    builder.getInt8PtrTy(),

    // Key
    key->getType(),

    // Value
    value->getType(),

    // Flags
    builder.getInt64Ty()
  };
  // clang-format on

  auto function_type =
      llvm::FunctionType::get(builder.getInt64Ty(), argument_type_list, false);

  auto function =
      builder.CreateIntToPtr(builder.getInt64(BPF_FUNC_map_update_elem),
                             llvm::PointerType::getUnqual(function_type));

  auto map_address = mapAddressFromFileDescriptor(map_fd, builder);

#if LLVM_VERSION_MAJOR < 11
  auto function_callee = function;
#else
  auto function_callee = llvm::FunctionCallee(function_type, function);
#endif

  return builder.CreateCall(function_callee,
                            {map_address, key, value, builder.getInt64(flags)});
}

// Returns the amount of nanoseconds elapsed from system boot
llvm::Value *bpfKtimeGetNs(llvm::IRBuilder<> &builder) {
  auto function_type = llvm::FunctionType::get(builder.getInt64Ty(), {}, false);

  auto function =
      builder.CreateIntToPtr(builder.getInt64(BPF_FUNC_ktime_get_ns),
                             llvm::PointerType::getUnqual(function_type));

#if LLVM_VERSION_MAJOR < 11
  auto function_callee = function;
#else
  auto function_callee = llvm::FunctionCallee(function_type, function);
#endif

  return builder.CreateCall(function_callee, {});
}

// Sends the specified buffer to the map_fd perf event output
llvm::Value *bpfPerfEventOutput(llvm::IRBuilder<> &builder, llvm::Value *ctx,
                                int map_fd, std::uint64_t flags,
                                llvm::Value *data, llvm::Value *size) {

  // clang-format off
  std::vector<llvm::Type *> argument_type_list = {
    // Context
    ctx->getType(),

    // Map address
    builder.getInt8PtrTy(),

    // Flags
    builder.getInt64Ty(),

    // Data pointer
    data->getType(),

    // Size
    builder.getInt64Ty()
  };
  // clang-format on

  auto function_type =
      llvm::FunctionType::get(builder.getInt32Ty(), argument_type_list, false);

  auto function =
      builder.CreateIntToPtr(builder.getInt64(BPF_FUNC_perf_event_output),
                             llvm::PointerType::getUnqual(function_type));

  auto map_address = mapAddressFromFileDescriptor(map_fd, builder);

#if LLVM_VERSION_MAJOR < 11
  auto function_callee = function;
#else
  auto function_callee = llvm::FunctionCallee(function_type, function);
#endif

  return builder.CreateCall(
      function_callee, {ctx, map_address, builder.getInt64(flags), data, size});
}

// Contains the perf event array file descriptor, and a perf event output
// for each online CPU (fd + memory mapping)
struct PerfEventArray final {
  int fd;

  std::vector<int> output_fd_list;
  std::vector<void *> mapped_memory_pointers;
};

// Uses poll() to wait for the next event happening on the perf even toutput
bool waitForPerfData(std::vector<std::size_t> &readable_outputs,
                     const PerfEventArray &obj, int timeout) {

  readable_outputs = {};

  // Collect all the perf event output file descriptors inside a
  // pollfd structure
  std::vector<struct pollfd> poll_fd_list;
  for (auto fd : obj.output_fd_list) {
    struct pollfd poll_fd = {};
    poll_fd.fd = fd;
    poll_fd.events = POLLIN;

    poll_fd_list.push_back(std::move(poll_fd));
  }

  // Use poll() to determine which outputs are readable
  auto err = ::poll(poll_fd_list.data(), poll_fd_list.size(), timeout);
  if (err < 0) {
    if (errno == EINTR) {
      return true;
    }

    return false;

  } else if (err == 0) {
    return true;
  }

  // Save the index of the outputs that can be read inside the vector
  for (auto it = poll_fd_list.begin(); it != poll_fd_list.end(); ++it) {
    auto ready = ((it->events & POLLIN) != 0);

    if (ready) {
      auto index = static_cast<std::size_t>(it - poll_fd_list.begin());
      readable_outputs.push_back(index);
    }
  }

  return true;
}

using PerfBuffer = std::vector<std::uint8_t>;
using PerfBufferList = std::vector<PerfBuffer>;

// Reads from the specified perf event array, appending new bytes to the
// perf_buffer_context. When a new complete buffer is found, it is moved
// inside the the 'data' vector
bool readPerfEventArray(PerfBufferList &data,
                        PerfBufferList &perf_buffer_context,
                        const PerfEventArray &obj, int timeout) {

  // Keep track of the offsets we are interested in to avoid
  // strict aliasing issues
  static const auto kDataOffsetPos{
      offsetof(struct perf_event_mmap_page, data_offset)};

  static const auto kDataSizePos{
      offsetof(struct perf_event_mmap_page, data_size)};

  static const auto kDataTailPos{
      offsetof(struct perf_event_mmap_page, data_tail)};

  static const auto kDataHeadPos{
      offsetof(struct perf_event_mmap_page, data_head)};

  data = {};

  if (perf_buffer_context.empty()) {
    auto processor_count = getProcessorCount();
    perf_buffer_context.resize(processor_count);
  }

  // Use poll() to determine which perf event outputs are readable
  std::vector<std::size_t> readable_outputs;
  if (!waitForPerfData(readable_outputs, obj, timeout)) {
    return false;
  }

  for (auto perf_output_index : readable_outputs) {
    // Read the static header fields
    auto perf_memory = static_cast<std::uint8_t *>(
        obj.mapped_memory_pointers.at(perf_output_index));

    std::uint64_t data_offset{};
    std::memcpy(&data_offset, perf_memory + kDataOffsetPos, 8U);

    std::uint64_t data_size{};
    std::memcpy(&data_size, perf_memory + kDataSizePos, 8U);

    auto edge = perf_memory + data_offset + data_size;

    for (;;) {
      // Read the dynamic header fields
      std::uint64_t data_head{};
      std::memcpy(&data_head, perf_memory + kDataHeadPos, 8U);

      std::uint64_t data_tail{};
      std::memcpy(&data_tail, perf_memory + kDataTailPos, 8U);

      if (data_head == data_tail) {
        break;
      }

      // Determine where the buffer starts and where it ends, taking into
      // account the fact that it may wrap around
      auto start = perf_memory + data_offset + (data_tail % data_size);
      auto end = perf_memory + data_offset + (data_head % data_size);

      auto byte_count = data_head - data_tail;
      auto read_buffer = PerfBuffer(byte_count);

      if (end < start) {
        auto bytes_until_wrap = static_cast<std::size_t>(edge - start);
        std::memcpy(read_buffer.data(), start, bytes_until_wrap);

        auto remaining_bytes =
            static_cast<std::size_t>(end - (perf_memory + data_offset));

        std::memcpy(read_buffer.data() + bytes_until_wrap,
                    perf_memory + data_offset, remaining_bytes);

      } else {
        std::memcpy(read_buffer.data(), start, byte_count);
      }

      // Append the new data to our perf buffer
      auto &perf_buffer = perf_buffer_context[perf_output_index];

      auto insert_point = perf_buffer.size();
      perf_buffer.resize(insert_point + read_buffer.size());

      std::memcpy(&perf_buffer[insert_point], read_buffer.data(),
                  read_buffer.size());

      // Confirm the read
      std::memcpy(perf_memory + kDataTailPos, &data_head, 8U);
    }
  }

  // Extract the data from the buffers we have collected
  for (auto &perf_buffer : perf_buffer_context) {
    // Get the base header
    struct perf_event_header header = {};
    if (perf_buffer.size() < sizeof(header)) {
      continue;
    }

    std::memcpy(&header, perf_buffer.data(), sizeof(header));
    if (header.size > perf_buffer.size()) {
      continue;
    }

    if (header.type == PERF_RECORD_LOST) {
      std::cout << "One or more records have been lost\n";

    } else {
      // Determine the buffer boundaries
      auto buffer_ptr = perf_buffer.data() + sizeof(header);
      auto buffer_end = perf_buffer.data() + header.size;

      for (;;) {
        if (buffer_ptr + 4U >= buffer_end) {
          break;
        }

        // Note: this is data_size itself + bytes used for the data
        std::uint32_t data_size = {};
        std::memcpy(&data_size, buffer_ptr, 4U);

        buffer_ptr += 4U;
        data_size -= 4U;

        if (buffer_ptr + data_size >= buffer_end) {
          break;
        }

        auto program_data = PerfBuffer(data_size);
        std::memcpy(program_data.data(), buffer_ptr, data_size);
        data.push_back(std::move(program_data));

        buffer_ptr += 8U;
        data_size -= 8U;
      }
    }

    // Erase the chunk we consumed from the buffer
    perf_buffer.erase(perf_buffer.begin(), perf_buffer.begin() + header.size);
  }

  return true;
}

// Creates a new, complete perf event output
bool createPerfEventArray(PerfEventArray &obj, std::size_t page_count) {
  auto processor_count = getProcessorCount();

  // Create the perf event array map
  obj.fd = createMap(BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4U, 4U, processor_count);
  if (obj.fd < 0) {
    return false;
  }

  // Create one output per CPU
  struct perf_event_attr attr {};
  attr.type = PERF_TYPE_SOFTWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_SW_BPF_OUTPUT;
  attr.sample_period = 1;
  attr.sample_type = PERF_SAMPLE_RAW;
  attr.wakeup_events = 1;

  std::uint32_t processor_index;
  for (processor_index = 0U; processor_index < processor_count;
       ++processor_index) {

    // clang-format off
    auto perf_event_fd = ::syscall(
      __NR_perf_event_open,
      &attr,
      -1,               // Process ID (unused)
      processor_index,  // 0 -> getProcessorCount()
      -1,               // Group ID (unused)
      0                 // Flags (unused)
    );
    // clang-format on

    if (perf_event_fd == -1) {
      return false;
    }

    obj.output_fd_list.push_back(static_cast<int>(perf_event_fd));
  }

  // Set the perf event output file descriptors inside the map
  processor_index = 0U;

  for (auto perf_event_fd : obj.output_fd_list) {
    std::vector<std::uint8_t> value(4);
    std::memcpy(value.data(), &perf_event_fd, sizeof(perf_event_fd));

    auto err = setMapKey(value, obj.fd, &processor_index);
    if (err != ReadMapError::Succeeded) {
      return false;
    }

    ++processor_index;
  }

  // Create a memory mapping for each output
  auto size = static_cast<std::size_t>(1 + std::pow(2, page_count));
  size *= static_cast<std::size_t>(getpagesize());

  for (auto &perf_event_fd : obj.output_fd_list) {
    // clang-format on
    auto ptr = mmap(nullptr,                // Desired base address (unused)
                    size,                   // Mapped memory size
                    PROT_READ | PROT_WRITE, // Memory protection
                    MAP_SHARED,             // Flags
                    perf_event_fd,          // The perf output handle
                    0                       // Offset (unused)
    );
    // clang-format on

    if (ptr == MAP_FAILED) {
      return false;
    }

    obj.mapped_memory_pointers.push_back(ptr);
  }

  return true;
}
