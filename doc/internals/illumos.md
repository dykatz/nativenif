# illumos/amd64 port: dynamic ELF and shared libraries

Status: **initial dynamic DSO subset implemented** in nifasm via the shared
Linux/illumos dynamic ELF writer ([dynamicelf.md](dynamicelf.md)); Arkham and
Nimony cannot yet target illumos. Dynamic ET_EXEC, imported data, TLS,
read-only address constants and automatic Nimony runtime initialization remain
unimplemented. Local writable globals, load-bias-safe pointers, libc function
imports and explicit DSO init/fini hooks work. The writer rejects these rather than
emitting misleading binaries. PIE remains deferred.

Smoke-test on illumos (outputs stay outside the repository):

```sh
nim c src/nifasm/nifasm.nim
nim c -r --out:/tmp/tdynamicelf tests/tdynamicelf.nim
mkdir -p /tmp/nativenif-illumos-probe
sh tests/test_dynamic_elf.sh # dlopen + libc import + init/fini + writable globals
src/nifasm/nifasm --shared --soname:libnative.so.1 \
  --init-proc:probe_init --fini-proc:probe_fini \
  -o:/tmp/nativenif-illumos-probe/libnative.so.1 tests/illumos_shared.nif
elfdump -e -p -d -r /tmp/nativenif-illumos-probe/libnative.so.1
```

This tests `dlopen`, `dlsym`, local writable globals, relative address
relocations, a `strlen` libc import and SysV argument/return registers using a nifasm-produced ET_DYN,
not merely the C reference probe. The lifecycle fixture also verifies load
and unload hooks. `(export S "C-name")` metadata (emitted by Arkham's x64
codegen from Leng `exportc`) or repeated `--export:NAME` flags keep lifecycle
hooks private. Exports from linked foreign modules are discovered on demand;
full ELF interposition rules remain outstanding.
No libc-free mode is planned. Dynamically linked executables and native
shared-library output are required for the first supported release. PIE is
explicitly deferred.
The native assembler/linker must produce final images without invoking a system
assembler, linker, or C compiler. Host C builds below are reference probes only.

## Host baseline (Tribblix, illumos 5.11, amd64)

`nim c src/arkham/arkham.nim` and `nim c src/nifasm/nifasm.nim` both succeed on
this host. `tools/illumos_abi_probe.c` builds as a 64-bit shared object using:

```sh
mkdir -p /tmp/nativenif-illumos-probe
gcc -m64 -O0 -fPIC -shared -DPROBE_SHARED \
  -Wl,-soname,libprobe.so.1 \
  -o /tmp/nativenif-illumos-probe/libprobe.so.1 tools/illumos_abi_probe.c
elfdump -e -p -d -r /tmp/nativenif-illumos-probe/libprobe.so.1
ldd /tmp/nativenif-illumos-probe/libprobe.so.1
gcc -m64 -O0 -o /tmp/nativenif-illumos-probe/probe-loader \
  tools/illumos_abi_loader.c -ldl
/tmp/nativenif-illumos-probe/probe-loader \
  /tmp/nativenif-illumos-probe/libprobe.so.1
# pair=5,7 callback=13 global=30 tls=17
```

The loader probe obtains a thread-local address through an exported function;
it does not assume `dlsym` on a TLS symbol yields an ordinary data pointer.

Observed: ELFCLASS64, EM_AMD64, ET_DYN, ELFOSABI_SOLARIS, two PT_LOADs,
PT_DYNAMIC and PT_TLS; `DT_NEEDED libc.so.1`, `DT_SONAME`, SysV `DT_HASH`,
`DT_STRTAB`, `DT_SYMTAB`, `DT_RELA`, `DT_JMPREL`, init/fini arrays; relocations
include `R_AMD64_RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, `DTPMOD64`, `DTPOFF64`.
These are *observations*, not a claim that every vendor-specific dynamic tag
in the system linker output is required for loading. Probe a minimal image
rather than blindly copying SUNW metadata.

**Deferred PIE:** this host's GCC 14.2 reports `-pie is not supported in
this configuration`. Its system linker accepts `-z type=exec|shared` but not
`-z type=pie`; `gcc -fPIE` without `-pie` emits ET_EXEC. This is not evidence
that illumos cannot run a PIE. PIE validation is a later milestone, not a gate
for the initial release.

Reference executable (non-PIE) for startup and symbol comparisons:

```sh
gcc -m64 -O0 -o /tmp/nativenif-illumos-probe/probe-exec tools/illumos_abi_probe.c
elfdump -e -p -d -r /tmp/nativenif-illumos-probe/probe-exec
/tmp/nativenif-illumos-probe/probe-exec
```

## Output contract

Expose `--os:illumos --cpu:amd64` (and asm-NIF `illumos_x64`). Select output
kind independently: the default is a dynamically linked ET_EXEC executable;
`--shared` produces an ET_DYN DSO with a SONAME and **no executable entry**.
Reject incompatible output flags and unsupported architectures explicitly.

The DSO needs an address-independent layout and relocation engine. All DSO
runtime addresses (including gvar initializers, rodata pointers, trace
metadata and unwind data) must be load-bias safe. Do not reuse `writeElf`'s
hard-coded `0x400000`/absolute pointer baking for ET_DYN. Avoid
text relocations; place mutable relocation targets in writable segments,
including address-bearing constants when needed. Validate page congruence,
W^X, PT_GNU/illumos stack policy, and loader acceptance on illumos itself.

For dynamically linked ET_EXEC, establish an illumos-compatible libc entry/exit contract: argc,
argv, envp, initialization and finalization, and exit status. For DSOs, never
run the executable entry or unconditional global initialization on `dlopen`;
provide proper init/fini arrays and a documented rule for module initialization
and destructor ordering, including across bundled NIF modules. Exported procs
and globals must be retained as roots even if unreachable from an entry proc.
Define the exported-symbol policy (including visibility, aliases, symbol
interposition, collision behavior and SONAME) explicitly. Test `dlopen`,
`dlsym`, calls from C and calls into libc; also link a C executable against
an emitted DSO. Test two separately produced DSOs with inter-DSO references.

Plan initial relocation coverage for local load-bias fixups (`RELATIVE`),
imports (`GLOB_DAT`/`JUMP_SLOT`), and TLS appropriate to the chosen model.
Audit internal function-pointer and global-address relocations separately from
external imports. Dynamic symbols need a loader-compatible hash table,
correct visibility/binding, and a defined unresolved-symbol policy. Check
whether non-PLT function addresses and imported data require distinct paths.
Explicitly validate symbol interposition instead of assuming locally defined
exports can always be bound directly. Record all patch sites through
`threadJumps`, `invertCondJumps`, `shortenX64Jumps` and alignment before writing
any ELF tables (see `src/nifasm/image/writeelf.nim`).

Use libc-owned TLS; never replace FS via Linux `arch_prctl`. For a DSO, use
PT_TLS with an illumos-supported dynamic TLS model (`__tls_get_addr` if
applicable). Check TLS initialization, per-thread addresses, `dlopen` after
threads start, and pthread callbacks. An ET_EXEC executable may use a different
TLS access model, but it must interoperate with libc and loaded DSOs. Account
for TLS helper calls in Arkham's register allocation and leaf analysis.

## Work breakdown and gates

1. **Targets and ABI probes.** Record loader/CRT behavior, C call ABI (SSE,
   aggregates, varargs, callbacks), TLS code sequences and debug/unwind
   expectations with `elfdump`, `dis`, `ldd`, `truss` and C probes. Separate
   target OS and output kind from CPU in Arkham and nifasm. No emit path should
   classify illumos `importc` as a Linux syscall. Relevant entry points:
   `src/arkham/arkham.nim`, `src/arkham/core/programs.nim`,
   `src/arkham/x64/driver.nim`, `src/nifasm/pass1.nim`,
   `src/nifasm/core/context.nim`, `src/nifasm/driver.nim`.
2. **Common dynamic ELF writer (in progress).** The shared Linux/illumos
   writer's first milestone emits a hand-authored NIF DSO exporting an integer
   function and loads the illumos image from C.
   Writable globals, local `R_AMD64_RELATIVE` address relocations, `DT_NEEDED`
   libraries, eager GOT-bound external function calls and explicit one-proc
   init/fini arrays now work. Next add imported data, module initialization
   ordering, TLS and broad interposition/visibility support. The current
   `writedynamicelf.nim` explicitly refuses unsupported image features.
3. **DSO and executable gates.** Add DSO SONAME/exports/init/fini/TLS and
   a dynamic ET_EXEC interpreter/entry/startup. Load a DSO from the executable,
   exchange callbacks, state and thread-local data, and check DSO load-bias
   changes across runs using `pmap` or equivalent.
4. **Arkham ABI and runtime.** Reuse x64 instruction selection, add libc extern
   declarations and SysV ABI boundaries, variadic calls, callbacks, process
   startup/exit, and TLS. Audit foreign modules and bundled symbol roots.
5. **Nimony integration.** Only after the above pass, lift the illumos native
   backend rejection in `../nimony/src/nimony/nimony.nim`. Keep libc linkage
   mandatory; reuse `../nimony/lib/std/posix/illumos/` bindings and the native
   allocator, audit `nimNativeIo`, pthreads, errno, command line and environment.
6. **Release gate.** In `tests/tester.nim`, run native illumos/amd64 programs
   plus DSO/dlopen/constructor/TLS/ABI tests on illumos CI. Inspect the
   resulting ELF with `elfdump` and verify no text relocations. Run Linux,
   Windows and macOS regressions. Reject unsupported modes with clear errors.

Defer PIE, SPARC, 32-bit x86 and other CPU targets. **Do not defer** shared
libraries or libc interoperability, and do not add a libc-free execution path.
