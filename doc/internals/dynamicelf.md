# Dynamic ELF64 image writer (x86-64)

`src/nifasm/image/dynamicelf.nim` defines target-independent ELF dynamic tags,
relocations, SysV hash construction, and on-disk records.
`src/nifasm/image/writedynamicelf.nim` owns the dynamic image layout: text,
dynamic symbols/strings/hash, writable `.dynamic` and GOT, program headers,
relocations, library dependencies, and export selection. `DynamicElfProfile`
supplies the OS ABI identity and page alignment;
`LinuxElf` and `IllumosElf` currently use the same layout and differ only in
ELF identification. The static Linux executable remains in `writeelf.nim`.
The eventual dynamic executable writer should reuse this layout, symbol/import
and relocation infrastructure rather than build an illumos-specific parallel
implementation.

The current `nifasm --shared` subset accepts `(arch x64)` and
`(arch illumos_x64)`. With no `--export` flag it exports all generated procs
and writable globals. Top-level `(export S "public-name")` asm-NIF declarations
provide link roots and external C symbol aliases (Arkham's x64 emitter now
produces them from Leng `exportc` on procs and mutable globals). If any are
present, only those definitions are published. Repeated `--export:NAME` flags
override the metadata and publish internal names instead; without markers or
flags the legacy default is export-all. Reachable private helpers and private
init/fini hooks remain in the image. Unknown symbols and duplicate metadata
are rejected. For a DSO, export declarations in **linked** foreign asm-NIF
modules are discovered as well. The linker scans each loaded module's metadata
once (including binary NIF, whose tag/pool ids are remapped to the main module),
without eagerly generating its bodies; exports may pull in further modules, so
discovery runs to a fixed point. This does not
search every foreign file on disk: a module must be referenced by the main
module or by another discovered export. Local RIP-relative references to globals are patched after layout. Literal global
initializers are written to the RW image; global symbol-address initializers
use `R_AMD64_RELATIVE` relocations so they remain correct under ASLR. The
`dlopen` test checks an exported scalar, an initialized pointer to that scalar,
and a function reading the scalar before and after mutation. External function
calls use an indirect `call [rip+GOT]`, with one `R_AMD64_GLOB_DAT` relocation
per imported symbol and `DT_NEEDED` entries for its libraries; the fixture calls
libc's `strlen` from within the DSO. This is **eager** binding (no PLT/lazy
resolution). For imports without an explicit library, the default is
`libc.so.6` on Linux x64 and `libc.so.1` on illumos x64; explicitly name other
libraries in `(extproc ...)`. The writer still rejects address-bearing
read-only constants and TLS. Optional `--init-proc:NAME` and
`--fini-proc:NAME` select defined `void(void)` procedures for one-entry
`DT_INIT_ARRAY`/`DT_FINI_ARRAY` tables. `R_AMD64_RELATIVE` fixes each function
pointer under ASLR. The smoke test verifies that the initializer changes an
exported global before `dlopen` returns, and the finalizer writes `fini!`
during `dlclose`. These flags are an image-level stopgap: module-level
initialization ordering, multiple constructors/destructors, and automatic
Nimony global initialization still need a proper asm-NIF representation.
The writer is not yet a complete general-purpose DSO: imported data, TLS,
address-bearing read-only constants, symbol-version dependencies, ABI-level
visibility/interposition rules, and full C ABI coverage are outstanding.
`--shared` on another architecture fails explicitly; Linux static executable
generation is unchanged.

Verification on illumos:

```sh
nim c src/nifasm/nifasm.nim
nim c -r --out:/tmp/tdynamicelf tests/tdynamicelf.nim
sh tests/test_dynamic_elf.sh # chooses the host's Linux or illumos fixture
nim c src/arkham/arkham.nim
sh tests/test_export_metadata.sh # Leng exportc -> asm-NIF -> DSO alias
sh tests/test_dynamic_modules.sh # linked foreign exports + transitive discovery
src/nifasm/nifasm --shared -o:/tmp/liblinux.so.1 tests/linux_shared.nif
elfdump -e -d /tmp/liblinux.so.1
```

The Linux image has been inspected on illumos, **not runtime-tested on Linux**;
add the C `dlopen` fixture to Linux CI before claiming that gate. See
[illumos.md](illumos.md) for the illumos ABI probes and remaining port work.
