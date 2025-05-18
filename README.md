# ASC-Hook: System Call Interception for ARM

**ASC-Hook** is a user-space system call interception tool for ARM platforms, based on binary rewriting. It enables comprehensive and high-performance interception of system calls without requiring source code.

Compared to widely-used interception methods such as `ptrace`, ASC-Hook is significantly faster while maintaining flexibility and transparency.

For detailed implementation and design, please refer to paper:  [https://doi.org/10.1145/3735452.3735524](https://doi.org/10.1145/3735452.3735524)
