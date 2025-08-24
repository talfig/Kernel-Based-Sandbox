
# LibCallPolicy (Part 1)

An LLVM pass plugin that:
1. Extracts a per-function **library call flow graph** from LLVM IR (over-approximated via the CFG).
2. Inserts a call to `void dummy(int)` **before each library call**.
3. Emits GraphViz **DOT** files and a JSON **policy** describing the sequence of library calls and assigned IDs.

It implements the data-structure idea we discussed: a hash table with modulo-bucketed linked lists (default `mod=200`), where each node (a libcall site) stores `nextNode`, a list of neighbors (`viewedCalls`), and a `dummyID`. Each bucket holds a linked list of nodes that share the same `dummyID` (modulo).

> Compatible with LLVM 14–18 (new pass manager).

---

## Build

```bash
# from this directory
mkdir -p build && cd build
cmake -DLLVM_DIR=$(llvm-config --cmakedir) ..
cmake --build . -j
```

This produces: `build/libLibCallPass.so`

## Usage

You can use `opt` to run the pass on an IR file:

```bash
opt -load-pass-plugin ./libLibCallPass.so \
    -passes="libcall" \
    -libcall-dot-dir=./libcall_dot \
    -libcall-policy-json=./libcall_policy.json \
    -libcall-mod=200 \
    -libcall-id-mode=dummy \
    < input.ll > instrumented.ll
```

- `-libcall-id-mode`:
  - `dummy` (default): inserts modulo-IDs (counter % mod) to `dummy(int)` for space-efficient IDs.
  - `unique`: inserts unique, increasing IDs (per function).

Outputs:
- One DOT per function into `./libcall_dot/<function>.dot`
- `libcall_policy.json` with a linear log of libcall sites and their `(uniqueID|dummyID, resetCount)` values.
- `instrumented.ll` contains IR where each libcall is preceded by `call void @dummy(i32 <ID>)`.

### What is a "library call"?
We conservatively treat **external declarations** that aren’t LLVM intrinsics (i.e., `@llvm.*`) as libcalls. This captures common libc functions such as `open`, `read`, `write`, `printf`, etc.

You can refine this by editing `isCandidateLibCall` in `LibCallPass.cpp` (e.g., add a whitelist/blacklist).

## Graph semantics

We construct an over-approximate NFA per function:

- Nodes correspond to **call sites** (positions “about to execute call X”). Node labels show the callee name and `(dummy=<id>)` if available.
- Edges:
  - Intra-basic-block **sequential** edges labeled with the callee name of the source call.
  - **ϵ-edges** from the last call of a basic block to the first call in each successor basic block.

This matches the **library call graph** idea from the spec (finite automaton).

## Data structure details

Internally, each function’s graph uses:

- `nodes[]`: stores `nextNode`, `viewedCalls` (neighbor node indices), and `dummyID`.
- `edges[]` + `adj[]` for labeled transitions.
- A hash table with `mod=M` buckets; each bucket is a head pointer into a pool of singly-linked
  `BucketNode{nodeIndex,next}` chains. Insertion uses `dummyID % M`.

This structure supports the **dummy-counter** scheme discussed (time-of-entry differentiation via `(resetCount, dummyID)` in the JSON).

## Example

Given `example.c`:

```c
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int foo(const char* path) {
  int fd = open(path, O_RDONLY);
  if (fd >= 0) {
    char buf[16];
    read(fd, buf, sizeof(buf));
  }
  close(fd);
  return 0;
}
```

Compile to IR and run the pass:

```bash
clang -S -emit-llvm example.c -o example.ll
opt -load-pass-plugin ./libLibCallPass.so -passes="libcall" < example.ll > instrumented.ll
```

Now `instrumented.ll` will have `call void @dummy(i32 <id>)` before each libcall; DOT files and JSON appear in the output paths you chose.

## Notes

- We do **not** implement kernel parts. This is strictly **Part 1**.
- The pass avoids editing functions without bodies.
- You may tune which calls count as libcalls, hashing modulus, and ID mode using flags.
- The JSON policy can be used by your in-kernel monitor to map observed dummy IDs to the allowed edges in the automaton.
