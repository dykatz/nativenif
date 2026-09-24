# Dynamic ELF64 shared objects: local code and writable data, no imports yet.
# The OS-specific ELF identity and segment alignment come from the target
# profile; symbol/hash/layout construction is common to Linux and illumos.
# Unsupported relocation/storage classes are rejected, never emitted as a
# library which only happens to load at one address or corrupts libc's TLS.
import std / [streams, os, tables, algorithm]
import ../core / [context, relocs, sem, buffers]
import elf, dynamicelf

type DynamicElfProfile* = object
  osAbi*: byte
  abiVersion*: byte
  pageSize*: int

const
  LinuxElf* = DynamicElfProfile(osAbi: 0, abiVersion: 0, pageSize: 4096)
  IllumosElf* = DynamicElfProfile(osAbi: 6, abiVersion: 1, pageSize: 4096)

proc alignTo(x, a: int): int = (x + a - 1) and not (a - 1)

proc put[T](f: Stream; v: T) =
  var copy = v
  f.writeData(addr copy, sizeof(T))

proc putBytes(f: Stream; bytes: openArray[byte]) =
  if bytes.len > 0: f.writeData(unsafeAddr bytes[0], bytes.len)

proc padTo(f: Stream; pos: int) =
  while f.getPosition() < pos: f.write 0'u8

proc writeDynamicElfShared*(a: var GenContext; outfile, soname: string;
                            profile: DynamicElfProfile) =
  if profile.pageSize < 4096 or (profile.pageSize and (profile.pageSize - 1)) != 0:
    raise newException(ValueError, "dynamic ELF: page size must be a power of two >= 4096")
  if a.arch notin {Arch.X64, Arch.IllumosX64}:
    raise newException(ValueError, "dynamic ELF: x86-64 only")
  if soname.len == 0 or ('\0' in soname):
    raise newException(ValueError, "dynamic ELF shared: invalid SONAME")
  if a.extProcs.len != 0 or a.imports.len != 0:
    raise newException(ValueError, "dynamic ELF shared: external imports not implemented yet")
  if a.rodataSymInits.len != 0 or a.tlsOffset != 0:
    raise newException(ValueError, "dynamic ELF shared: read-only address constants and TLS not implemented yet")
  # Code-to-global references are RIP-relative and survive arbitrary load bias.
  # Branch passes change code offsets; remap their external patch sites too.
  let threaded = threadJumps(a.buf)
  for k in 0 ..< a.gvarSites.len:
    a.gvarSites[k] = (threaded[a.gvarSites[k][0]], a.gvarSites[k][1])
  let inverted = invertCondJumps(a.buf)
  for k in 0 ..< a.gvarSites.len:
    a.gvarSites[k] = (inverted[a.gvarSites[k][0]], a.gvarSites[k][1])
  finalize(a.buf)
  var labels = initTable[int, int]()
  for l in a.buf.labels: labels[int(l.id)] = l.position
  var exports: seq[(string, Symbol)] = @[]
  for id, sym in a.rootScope.syms:
    if (sym.kind == skProc and labels.hasKey(sym.offset)) or
       (sym.kind == skGvar and sym.offset >= 0 and sym != a.tlsBlockSym):
      exports.add (a.nameOf(id), sym)
  exports.sort(proc(x, y: (string, Symbol)): int = cmp(x[0], y[0]))
  const hdrSize = 64 + 56 * 3   # RX LOAD, RW LOAD, DYNAMIC
  let codeOff = hdrSize
  let codeEnd = codeOff + a.buf.data.len
  var strings: seq[byte] = @[0'u8]
  var names: seq[string] = @[""]
  var symbols: seq[Elf64_Sym] = @[default(Elf64_Sym)]
  for (name, sym) in exports:
    let off = strings.len
    for ch in name: strings.add byte(ch)
    strings.add 0'u8
    names.add name
    if sym.kind == skProc:
      symbols.add Elf64_Sym(st_name: uint32(off),
        st_info: (STB_GLOBAL shl 4) or STT_FUNC, st_shndx: 1,
        st_value: uint64(codeOff + labels[sym.offset]))
    else:
      symbols.add Elf64_Sym(st_name: uint32(off),
        st_info: (STB_GLOBAL shl 4) or STT_OBJECT, st_shndx: 2,
        st_size: uint64(asmSizeOf(sym.typ)))
  let sonameOff = strings.len
  for ch in soname: strings.add byte(ch)
  strings.add 0'u8
  let hash = sysvHash(names, max(1, names.len))
  let symOff = alignTo(codeEnd, 8)
  let strOff = symOff + symbols.len * sizeof(Elf64_Sym)
  let hashOff = alignTo(strOff + strings.len, 8)
  let relaOff = alignTo(hashOff + hash.len * 4, 8)
  let readEnd = relaOff + a.bssSymInits.len * sizeof(Elf64_Rela)
  let dynOff = alignTo(readEnd, profile.pageSize)
  var dyn: seq[Elf64_Dyn] = @[
    Elf64_Dyn(d_tag: DT_SONAME, d_val: uint64(sonameOff)),
    Elf64_Dyn(d_tag: DT_HASH, d_val: uint64(hashOff)),
    Elf64_Dyn(d_tag: DT_STRTAB, d_val: uint64(strOff)),
    Elf64_Dyn(d_tag: DT_STRSZ, d_val: uint64(strings.len)),
    Elf64_Dyn(d_tag: DT_SYMTAB, d_val: uint64(symOff)),
    Elf64_Dyn(d_tag: DT_SYMENT, d_val: uint64(sizeof(Elf64_Sym)))]
  if a.bssSymInits.len > 0:
    dyn.add Elf64_Dyn(d_tag: DT_RELA, d_val: uint64(relaOff))
    dyn.add Elf64_Dyn(d_tag: DT_RELASZ, d_val: uint64(a.bssSymInits.len * sizeof(Elf64_Rela)))
    dyn.add Elf64_Dyn(d_tag: DT_RELAENT, d_val: uint64(sizeof(Elf64_Rela)))
  dyn.add Elf64_Dyn(d_tag: DT_NULL)
  let dynSize = dyn.len * sizeof(Elf64_Dyn)
  var dataAlign = 16
  for _, sym in a.rootScope.syms:
    if sym.kind == skGvar and sym.offset >= 0 and sym != a.tlsBlockSym:
      dataAlign = max(dataAlign, asmAlignOf(sym.typ))
  if (dataAlign and (dataAlign - 1)) != 0 or dataAlign > profile.pageSize:
    raise newException(ValueError, "dynamic ELF shared: unsupported global alignment")
  let dataOff = alignTo(dynSize, dataAlign)
  let dataAddr = dynOff + dataOff
  var data = newSeq[byte](a.bssOffset)
  for it in a.bssInits:
    if it.off < 0 or it.size < 0 or it.off + int64(it.size) > int64(data.len):
      raise newException(ValueError, "dynamic ELF shared: initializer outside writable data")
    for i in 0 ..< it.size:
      data[int(it.off) + i] = byte((it.val shr (8 * i)) and 0xff)
  for i, entry in exports:
    if entry[1].kind == skGvar:
      symbols[i + 1].st_value = uint64(dataAddr + entry[1].size)
  var relas: seq[Elf64_Rela] = @[]
  for it in a.bssSymInits:
    if it.size != 8 or it.off < 0 or it.off + 8 > int64(data.len):
      raise newException(ValueError, "dynamic ELF shared: invalid address initializer")
    var target: int
    case it.sym.kind
    of skProc, skRodata:
      if not labels.hasKey(it.sym.offset):
        raise newException(ValueError, "dynamic ELF shared: unresolved address initializer")
      target = codeOff + labels[it.sym.offset]
    of skGvar: target = dataAddr + it.sym.size
    else: raise newException(ValueError, "dynamic ELF shared: unsupported address initializer")
    relas.add Elf64_Rela(r_offset: uint64(dataAddr) + uint64(it.off),
      r_info: relaInfo(0, R_AMD64_RELATIVE), r_addend: int64(target))
  for (pos, sym) in a.gvarSites:
    if sym.kind != skGvar or sym.offset < 0 or pos < 0 or pos + 7 > a.buf.data.len:
      raise newException(ValueError, "dynamic ELF shared: unresolved global address")
    let delta = int64(dataAddr + sym.size) - int64(codeOff + pos + 7)
    if delta < int64(low(int32)) or delta > int64(high(int32)):
      raise newException(ValueError, "dynamic ELF shared: global out of RIP-relative range")
    let disp = uint32(int32(delta))
    for i in 0 ..< 4: a.buf.data[pos + 3 + i] = byte((disp shr (8 * i)) and 0xff)
  var hdr = initHeader(0, EM_X86_64)
  hdr.e_type = ET_DYN
  hdr.e_ident[7] = profile.osAbi
  hdr.e_ident[8] = profile.abiVersion
  hdr.e_phnum = 3
  var rx = initPhdr(0, 0, uint64(readEnd), uint64(readEnd), PF_R or PF_X)
  let rwSize = dataOff + data.len
  var rw = initPhdr(uint64(dynOff), uint64(dynOff), uint64(rwSize),
                    uint64(rwSize), PF_R or PF_W)
  rx.p_align = uint64(profile.pageSize)
  rw.p_align = uint64(profile.pageSize)
  var dynamic = initPhdr(uint64(dynOff), uint64(dynOff), uint64(dynSize),
                         uint64(dynSize), PF_R or PF_W)
  dynamic.p_type = PT_DYNAMIC
  dynamic.p_align = 8
  var f = newFileStream(outfile, fmWrite)
  if f == nil: raise newException(IOError, "cannot write " & outfile)
  defer: f.close()
  f.put hdr
  f.put rx
  f.put rw
  f.put dynamic
  if a.buf.data.len > 0:
    f.writeData(a.buf.data.rawData, a.buf.data.len)
  f.padTo symOff
  for sym in symbols: f.put sym
  f.putBytes(strings)
  f.padTo hashOff
  for w in hash: f.put w
  f.padTo relaOff
  for rel in relas: f.put rel
  f.padTo dynOff
  for d in dyn: f.put d
  f.padTo dynOff + dataOff
  f.putBytes(data)
