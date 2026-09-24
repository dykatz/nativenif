# ELF64 dynamic-linking primitives shared by the future illumos executable and
# DSO writers. These describe ON-DISK records, not host linker output. No
# platform-specific linker is needed to build the hash or relocation tables.
import elf

type
  Elf64_Dyn* = object
    d_tag*: int64
    d_val*: uint64       # also used for pointer-valued entries

  Elf64_Rela* = object
    r_offset*: uint64
    r_info*: uint64
    r_addend*: int64

const
  ET_DYN* = 3.Elf64_Half
  PT_DYNAMIC* = 2.Elf64_Word
  PT_INTERP* = 3.Elf64_Word
  PT_TLS* = 7.Elf64_Word
  SHT_DYNAMIC* = 6.Elf64_Word
  SHT_DYNSYM* = 11.Elf64_Word
  SHT_RELA* = 4.Elf64_Word
  SHT_HASH* = 5.Elf64_Word
  STT_OBJECT* = 1'u8
  STT_TLS* = 6'u8

  DT_NULL* = 0'i64
  DT_NEEDED* = 1'i64
  DT_PLTRELSZ* = 2'i64
  DT_PLTGOT* = 3'i64
  DT_HASH* = 4'i64
  DT_STRTAB* = 5'i64
  DT_SYMTAB* = 6'i64
  DT_RELA* = 7'i64
  DT_RELASZ* = 8'i64
  DT_RELAENT* = 9'i64
  DT_STRSZ* = 10'i64
  DT_SYMENT* = 11'i64
  DT_SONAME* = 14'i64
  DT_JMPREL* = 23'i64
  DT_PLTREL* = 20'i64
  DT_INIT_ARRAY* = 25'i64
  DT_FINI_ARRAY* = 26'i64
  DT_INIT_ARRAYSZ* = 27'i64
  DT_FINI_ARRAYSZ* = 28'i64

  R_AMD64_64* = 1'u32
  R_AMD64_GLOB_DAT* = 6'u32
  R_AMD64_JUMP_SLOT* = 7'u32
  R_AMD64_RELATIVE* = 8'u32
  R_AMD64_DTPMOD64* = 16'u32
  R_AMD64_DTPOFF64* = 17'u32

static:
  doAssert sizeof(Elf64_Dyn) == 16
  doAssert sizeof(Elf64_Rela) == 24
  doAssert sizeof(Elf64_Sym) == 24

proc relaInfo*(symbol, kind: uint32): uint64 {.inline.} =
  ## ELF64_R_INFO(symbol, kind). RELATIVE relocations use symbol 0.
  (uint64(symbol) shl 32) or uint64(kind)

proc elfHash*(name: string): uint32 =
  ## SysV ELF hash, used by DT_HASH on illumos (not GNU .gnu.hash).
  var h = 0'u32
  for c in name:
    h = (h shl 4) + uint32(ord(c))
    let high = h and 0xf0000000'u32
    if high != 0:
      h = h xor (high shr 24)
    h = h and not high
  result = h

proc sysvHash*(names: openArray[string]; bucketCount: int): seq[uint32] =
  ## Build DT_HASH words in ELF order: nbucket, nchain, buckets[], chains[].
  ## names[i] corresponds to dynsym[i], including the null symbol at index 0.
  ## Empty names are not inserted into a bucket. Collisions retain dynsym order.
  if bucketCount <= 0 or names.len == 0 or names[0].len != 0:
    raise newException(ValueError, "DT_HASH requires positive buckets and dynsym[0] null")
  result = newSeq[uint32](2 + bucketCount + names.len)
  result[0] = uint32(bucketCount)
  result[1] = uint32(names.len)
  for i in 1 ..< names.len:
    if names[i].len == 0: continue
    let bucket = int(elfHash(names[i]) mod uint32(bucketCount))
    let head = 2 + bucket
    if result[head] == 0:
      result[head] = uint32(i)
    else:
      var cur = int(result[head])
      while result[2 + bucketCount + cur] != 0:
        cur = int(result[2 + bucketCount + cur])
      result[2 + bucketCount + cur] = uint32(i)

proc hashLookup*(words: openArray[uint32]; names: openArray[string]; name: string): int =
  ## Reference lookup for tests; the system loader reads the same table.
  if words.len < 2 or words[0] == 0 or words.len != 2 + int(words[0]) + int(words[1]) or
      names.len != int(words[1]):
    raise newException(ValueError, "invalid DT_HASH table")
  let nbucket = int(words[0])
  var i = int(words[2 + int(elfHash(name) mod uint32(nbucket))])
  while i != 0:
    if i >= names.len: raise newException(ValueError, "invalid DT_HASH chain")
    if names[i] == name: return i
    i = int(words[2 + nbucket + i])
  result = -1
