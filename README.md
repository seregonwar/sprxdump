# 🧩 sprxdump
[![Github All Releases](https://img.shields.io/github/downloads/seregonwar/sprxdump/total.svg)]()
[![Repository views](https://hits.sh/github.com/seregonwar/sprxdump.svg?label=views)](https://hits.sh/github.com/seregonwar/sprxdump/)

PS5 payload that extracts the **decrypted** in-memory image of a loaded SPRX/SELF module from a
live process, with a VA↔offset index that Ghidra and IDA can load directly.

Read-only. No ptrace, no copyin, no kernel writes.

## Why it exists

On the console a module exists twice. The `.sprx` on disk is encrypted and signed; the copy in
memory is the decrypted, relocated image the CPU actually runs. Analysing the file needs keys and
a SELF parser. Analysing the live image needs neither — it is plain x86-64 with its imports
already resolved.

`sprxdump` takes the second road: it asks the kernel where the module is mapped and copies it out.

## Features

- `list` — every process with name, pid, uid, authid and resident size, plus a vmmap summary
- `mod` — one module, decrypted, with its `.idx`
- `dump` — the whole address space of a process, with its `.idx`
- module base resolved through the dynamic-library handle, not by guessing
- string fingerprint only as fallback, with candidates printed and a base that can be forced
- every range records its own errno, so a partial dump is still trustworthy
- `cc_prefix` and `first_prologue` printed for each module, so the extraction can be checked
  instead of taken on faith

## Requirements

- a jailbroken console with a payload loader that runs the ELF as `euid 0` — elfldr or equivalent
- firmware 9.40 tested

It does **not** run from an unprivileged app or game sandbox. From that context the process
queries and the cross-process copy are denied, and the jail does not expose the targets at all.
No additional kernel exploit is involved: the privilege is inherited from the loader, not obtained
by the payload.

## Usage

```
list                          all processes
list 67                       one process
mod 67 libSceSysmodule        extract a module by name
mod 67 0x833b74000            extract a module by base
dump 67                       full process snapshot
help                          command summary
```

Arguments can be passed through the loader's argument mechanism, or placed in a config file that
the payload reads when it is sent raw — loaders differ, so both paths are supported.

## Output

Each dump produces a binary image plus an index. The index is one line per range:

```
start_va  end_va  prot  type  bytes  errno  file_offset
```

That is enough to rebuild the address space in a disassembler: every range lands at its real
virtual address, and ranges that could not be read are marked with the errno rather than silently
missing.

Modules are written as separate images, one per loaded module, so they open cleanly in Ghidra
without manual segmentation.

## What was measured

On firmware 9.40:

- `list` — 86 processes, 12 373 ranges, 0.22 s
- `mod 67 libSceSysmodule` — 180 224 bytes in 4 segments, 18 ms, no failed reads
- `dump 67` — 13.4 MB in 0.74 s, 74 ranges, zero failures

The extracted module is byte-identical to an independent manual dump of the same process, and the
first bytes were compared against live memory.

## Limits

- 53 of 86 processes are kernel threads: the kernel refuses their vmmap even at `euid 0`
- the same module in two processes shares its code but not its data — dump per process
- no relocation, no symbol reconstruction, no ELF rebuild: the output is an image, not a binary
- no ELF header exists at the start of in-memory images on 9.40, so magic-based detection is
  useless there; the handle query is what makes the extraction exact

## Build

```
pwsh -File build.ps1
```

The build script reads the payload SDK location from the environment, so no machine-specific path
is baked into the repository.

## Please note

The payload only reads. It does not patch, does not attach a debugger and does not alter the
target process. If a range cannot be read, it is reported and skipped — never guessed.
