
# LibCall Sandbox — Part 1 + Part 2 (complete)

This repository combines:
- **Part 1 (LLVM pass)**: Extract per-function library-call automata, instrument calls with `dummy(int)`, emit DOT + JSON.
- **Part 2 (Kernel enforcement)**: A Linux kernel module that enforces the automata at runtime by hooking the **`dummy` system call** using a kprobe and killing the process on violations. Comes with a user-space loader **`sandboxctl`** and a tiny **`libdummy`** that implements `dummy(int)` as a syscall wrapper.

This follows the IISc project brief “Building an in-kernel, per-process sandbox” (Autumn 2024) and implements the **dummy syscall** approach for enforcing libc call policies in-kernel. fileciteturn1file0

---

## Contents

```
llvm-pass/      # Part 1 plugin (CMake project)
kernel-module/  # Part 2 kernel module (/dev/libcallsandbox + kprobe on __x64_sys_dummy)
sandboxctl/     # User-space loader to push the automaton to the kernel for a PID
libdummy/       # Userspace 'dummy(int)' wrapper issuing the dummy syscall
```

---

## Part 1 — LLVM pass (instrument + export automata)

### Build
```bash
cd llvm-pass
mkdir -p build && cd build
cmake -DLLVM_DIR=$(llvm-config --cmakedir) ..
cmake --build . -j
```

### Use on your program
Compile your C to LLVM IR and run the pass:
```bash
clang -S -emit-llvm app.c -o app.ll -g
opt -load-pass-plugin ./build/libLibCallPass.so -passes="libcall" \
    -libcall-dot-dir=./libcall_dot \
    -libcall-policy-json=./libcall_policy.json \
    -libcall-mod=200 \
    -libcall-id-mode=dummy \
    < app.ll > app.instrumented.ll
```

- IR now contains **`call void @dummy(i32 <ID>)`** before each libcall.
- DOT files per function in `libcall_dot/`.
- `libcall_policy.json` includes **full graph**: node labels, `(dummyID, uniqueID)` per node, and edges (with epsilon transitions and matching IDs).

> Choose `-libcall-id-mode=unique` if you want unique IDs instead. The JSON records both.

---

## Part 2 — Kernel enforcement (Linux 6.x)

### 2.1 Add the **dummy syscall** (one-time kernel change)

> The module **hooks** `__x64_sys_dummy` via kprobe. You still need to add the syscall to your kernel (so user-space `syscall(__NR_dummy, id)` resolves). Minimal steps (x86-64):

1. **Assign a syscall number** (example: `451`) in `arch/x86/entry/syscalls/syscall_64.tbl`:
   ```
   451     common  dummy           __x64_sys_dummy
   ```
2. **Declare** in `include/linux/syscalls.h`:
   ```c
   asmlinkage long sys_dummy(int id);
   ```
3. **Implement** in a new file `kernel/dummy_syscall.c`:
   ```c
   // SPDX-License-Identifier: GPL-2.0
   #include <linux/syscalls.h>
   SYSCALL_DEFINE1(dummy, int, id) { return 0; } // body empty; monitor lives in module
   ```
4. **Add to** kernel `Makefile/Kconfig` per your tree, then rebuild and boot the kernel.

> If you cannot patch the kernel right now, you can still **load the module** and tests will run **once the syscall exists** (the kprobe attaches to its entry).

### 2.2 Build and load the enforcement module
```bash
cd kernel-module
make
sudo insmod libcallsandbox.ko
# creates /dev/libcallsandbox and arms a kprobe on __x64_sys_dummy
```

### 2.3 Build the policy loader
```bash
cd ../sandboxctl
make
```

### 2.4 Link your app with `libdummy` (so the pass’s `dummy(int)` calls reach the syscall)
```bash
cd ../libdummy
gcc -c -O2 libdummy.c
ar rcs libdummy.a libdummy.o
# Compile/Link your instrumented app with libdummy.a
```

Ensure the macro `__NR_dummy` inside `libdummy.c` matches the number you assigned (e.g., `451`).

### 2.5 Load policy and run
1. Run your instrumented program in the VM with the patched kernel:
   ```bash
   ./your_app &
   APP_PID=$!
   ```

2. Load the **automaton** from Part 1 JSON for the function you want to enforce (start with main or a target function):
   ```bash
   ./sandboxctl/sandboxctl -p $APP_PID -j llvm-pass/libcall_policy.json -f 0
   ```

   Flags:
   - `-p <pid>`: target process PID
   - `-j <json>`: path to policy JSON
   - `-f <index>`: function index within JSON (0 = first function)
   - `--unique`: enforce by **unique** IDs instead of dummy modulo IDs

3. As your process calls library functions, it will first issue `sys_dummy(id)`. The module:
   - advances the **NFA frontier** using edges that match `id`,
   - applies **epsilon-closure**,
   - **SIGKILLs** the process if the frontier becomes empty (policy violation).

> The kernel module is intentionally strict: any unrecognized ordering of calls kills the process. This mirrors the project brief’s enforcement semantics. fileciteturn1file0

---

## Data structures and fidelity to spec

- **Automaton**: We export a **per-function NFA** (nodes=libcall sites, edges labeled by the *source* libcall name, plus `ϵ` edges across CFG forks/joins). This matches the course’s “library call flow graph”. fileciteturn1file0
- **Dummy ID scheme**: The pass assigns both **`uniqueID`** and **`dummyID` = counter % `mod`** (with `resetCount = counter / mod`). The kernel uses either `dummy` or `unique` match mode.
- **Hash-table with bucketed linked lists** (Part 1 internals) preserves your `mod200` idea for space efficiency and time-of-entry differentiation; JSON carries full info so Part 2 does not rehash.
- **Frontier handling**: We maintain a per-PID **bitset frontier**, perform **epsilon-closure**, and transition on observed IDs, killing when empty — i.e., standard NFA semantics mandated by the brief. fileciteturn1file0

---

## Security & portability notes

- The module uses a **kprobe** on `__x64_sys_dummy` to avoid kernel re-linking inside the module; you must still add the syscall to the kernel for user-space to invoke it.
- For other architectures, adjust the kprobe symbol and argument extraction (`regs->di` is x86-64 ABI).

---

## Testing with mbed-tls

The brief requires testing on **mbed-tls** variants. Build mbed-tls, compile test binaries to IR, run the pass, instrument, link `libdummy`, then load policies for the relevant functions with `sandboxctl`. Record which configuration you used in your report. fileciteturn1file0

---

## License

MIT for all code in this repo.
