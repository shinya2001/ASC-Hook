# ASC-Hook: System Call Interception for ARM

ASC-Hook is a user-space system call interception tool for ARM platforms, based on binary rewriting. It enables comprehensive and high-performance interception of system calls without requiring source code.

Compared to widely-used interception methods such as `ptrace`, ASC-Hook is significantly faster while maintaining flexibility and transparency. The current implementation assumes a Linux system with an arm64 architecture.

For detailed implementation and design, please refer to paper:  [https://doi.org/10.1145/3735452.3735524](https://doi.org/10.1145/3735452.3735524)

# Install dependencies:

**ASC-Hook** depends on `libopcodes` and the **Keystone engine**.

To install `libopcodes`:
```bash
sudo apt-get install binutils-dev
```
Install Keystone  
ASC-Hook uses the [Keystone Engine](https://github.com/keystone-engine/keystone) for disassembly.  
You can follow the official installation instructions on the Keystone GitHub page.

>  Please make sure both `libopcodes` and `keystone` are properly installed before compiling or running ASC-Hook.

# Build

ASC-Hook consists of two shared libraries: `ASC_hook_basic.so` and `ASC_hook.so`.

- `ASC_hook_basic.so` contains the core hook functions. To build it, run:

  ```bash
  make -C basic
  ```
- ASC_hook.so is the main interception library. To build it, simply run make in the root directory:
  ```bash
  make
  ```
# Usage

ASC-Hook requires memory to be mapped at lower virtual addresses.  
Before running any program, please run the following command:

```bash
sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"
```
This command only needs to be run once after each reboot.

Before executing your target application, you need to set the following environment variables:
  - LD_PRELOAD: path to ASC_hook.so
  - LIBASCHOOK: path to ASC_hook_basic.so

Here’s an example of how to run your program with ASC-Hook:
```bash
LD_PRELOAD=./ASC_hook.so LIBASCHOOK=./basic/ASC_hook_basic.so ./your_target_program
```
There are currently two hook functions defined in `basic/main.c`:

- `hook_function`:  
  This function is called before the `SVC` instruction is executed during normal system call interception.

- `final_signal_hook_function`:  
  This function is triggered by a signal-based interception handler.  It is rarely used under typical conditions.

Currently, both functions simply print the system call number.  
You can customize the behavior of ASC-Hook by modifying these functions to implement your own syscall-level logic.

# Other Notes

For most applications, ASC-Hook does not require signal-based interception.  
However, if you encounter a situation where it is necessary, you may need to modify the configuration file to enable the completeness policy.
See [Document/Completeness.pdf](./Document/Completeness.pdf) for more details.

Additionally, the MPI-based BFS program we developed (used as a benchmark), along with its data generator, is provided in the `test` directory. Feel free to check it out if needed.
