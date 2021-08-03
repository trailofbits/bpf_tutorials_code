# Companion code for All your tracing are belong to BPF

The blog post can be found at the following link: [Link to blog post](https://trailofbits.com)

# Build instructions

## Dependencies

The only real dependency is LLVM, while CMake is our build system of choice:

 * LLVM, version 10 or better
 * CMake, version 3.16.1

If you are running Debian or Ubuntu, you can install them both with the following command:

```
sudo apt install -y llvm-dev \
                    cmake
```

## Cloning the project

```
git clone https://github.com/trailofbits/bpf_tutorials_code
```

## Configuring the project

```
cmake -S bpf_tutorials_code \
      -B bpf_tutorials_build \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo
```

Additional options:

 * **BPF_TUTORIALS_ENABLE_SANITIZERS**: Set to true to enable the **undefined** and **address** sanitizers

## Starting the build

```
cmake --build bpf_tutorials_build -j
```
