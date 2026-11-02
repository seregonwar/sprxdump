# sprxdump — read-only process/module dumper for PS5 (elfldr payload)

Single ELF, no UI. Headline feature: extract the **decrypted** in-memory image of a loaded
SPRX/SELF module from a live PS5 process, with a VA↔file-offset index that Ghidra/IDA can use
directly.

FW tested: 9.40 (`0x09400008`), elfldr on `:9021`, payload runs `euid 0` (`uid 1`,
authid `0x480000001000000e`).

> **Requirement, stated plainly.** This is *not* a tool that runs on a stock console, and it does
> **not** run from an unprivileged app / game sandbox (SWRR, Luac0re, webkit): from that context
> `KERN_PROC_VMMAP` on another process and `mdbg_copyout` are denied, and the jail does not even
> expose the target paths. It needs an **existing** payload loader that gives it `euid 0` (elfldr,
> or any equivalent). It requires **no additional kernel exploit of its own** — the privilege is
> inherited, not obtained.

## Why decrypted extraction matters

On the console a module exists twice: the `.sprx`/`.self` on disk is encrypted and signed, and
the copy in memory is the decrypted, relocated image the CPU actually executes. Static RE of the
file needs keys and a SELF parser; the live image needs neither — it is plain x86-64 with imports
resolved. Inside the running process it also contains runtime-relocated pointers, so it is the only
faithful source for pointer-bearing data segments and for code that was patched at load time.

Verified: the same module dumped from two processes has **byte-identical code** (`0x00000–0xc000`)
and differs only in the data/relocation range (4246 bytes, first diff at `0x14001`). Dump per
process for data; code is stable.

## Build

```powershell
pwsh -File build.ps1            # -> build\sprxdump.elf
```

SDK default `D:\source\repos\Github\_sdk-044\ps5-payload-sdk` (`-Sdk` to override); the SDK's
`win\` dir must be on `PATH` for `prospero-lld.exe`, build.ps1 does that.

## Deploy and run

`elfldr` has no argv on the raw socket path (`argc == 1`), so both modes are supported:

```bash
# args: elfldr URI protocol (single ?args= string, split on commas/spaces by the payload)
python tools/deploy.py build/sprxdump.elf /data/sprxdump.elf list
python tools/deploy.py build/sprxdump.elf /data/sprxdump.elf mod 67 libSceSysmodule

# no args: commands are read from /data/sprxdump.cfg (created on first run if missing)
python tools/deploy.py build/sprxdump.elf x
```

`tools/deploy.py` uploads over FTP (`:2120`, anonymous) and then asks elfldr to load
`file:<remote>?args=...`. A plain `send_payload.py`-style raw stream also works; it just always
takes the cfg path. First run without cfg writes:

```text
list
mod SceSpZeroConf libSceSysmodule
```

Edit `/data/sprxdump.cfg` over FTP and re-send to change the auto behaviour.

## Command surface

| command | action |
|---|---|
| `list` | process table: `pid ppid uid authid rss_kb vsize_kb ranges comm tdname` |
| `list <pid\|name>` | table + that process's vmmap (every range: start/end/size/prot/type/path) + module-image candidates (`base`, `size`, `segs`, prologue count, first 16 bytes) |
| `mod <pid\|name> <module>` | dump the decrypted module image to `/data/sprxdump/<module>.bin` + `.idx` |
| `mod <pid\|name> <module> 0x<base>` | same, with an explicit image base (when name lookup is unavailable/ambiguous) |
| `mod <pid\|name> 0x<base>` | dump by base only (no name) |
| `dump <pid\|name>` | full snapshot of all readable+executable ranges + `.<idx>` |
| `help` | usage |

Name resolution is case-insensitive: exact `comm`/`tdname` first, then a unique substring; an
ambiguous name prints the candidates instead of guessing. `0x…` is accepted anywhere a pid is.

## How a module is located

1. `kernel_dynlib_handle(pid, "libSceSysmodule.sprx", &h)` → `kernel_dynlib_mapbase_addr`,
   `entry`, `init`, `fini`. Exact, kernel-side, read-only. **This is the primary path**; plain
   `libSceSysmodule` is rejected by the API, so `.sprx/.prx/.elf` variants are tried.
2. The image is the contiguous run of ranges of the same vmmap type that starts at that base and
   begins with an executable range (`cluster_at()`). BSS is a different type and is not swallowed.
3. Sanity check: `entry/init/fini` must fall inside the run, else a warning is printed.
4. Fallback when the kernel walk refuses (other firmware): string-fingerprint search over the
   module-image candidates for `name` / `name.sprx`. This is deliberately noisy — on 9.40 the
   literal `libSceSysmodule` also lives in an unrelated 128 KiB rodata range of pid 67 — so
   candidates are always printed and an explicit `0x<base>` overrides the pick.

No ELF header is present at the start of these in-memory images: a scan of 74 ranges in pid 67
and 2202 in pid 58 found **0** ELF magics. "ELF magic at the mapping start" is therefore not a
usable locator on 9.40; the dynlib walk is.

## Output format

`/data/sprxdump/report.txt` — full transcript of the run (process table, vmmap, per-segment
sizes, confirmation bytes, timings, FNV-1a 64 of the dump).

`<module>.idx` / `<proc>_<pid>.idx`:

```text
# sprxdump libSceSysmodule pid=67 image_base=0x833b74000
# va->file: off = file_off + (va - start)
# start end prot type bytes err file_off path
0x0000000833b74000 0x0000000833b80000 0x4 9 49152 0 0x0 -
...
# bytes_written=180224 fnv1a64=0x9c5b4d164022352a
```

* one line per range: `start_va end_va prot type bytes errno file_offset path`
* `errno` is per range (`0` = complete, otherwise the failing `mdbg_copyout`/`write` errno)
* `bytes` is what was actually written; a short `bytes` with non-zero `errno` marks a hole
* `off = file_off + (va - start)` maps any VA to its byte position
* module images are contiguous from `image_base`, so for `mod` output `off == va - image_base`

Load in Ghidra: *File → Import → Raw Binary*, language x86-64, base address = `image_base`.
IDA: *Load as → Binary file*, processor `metapc`, `-b` offset 0 with image base = `image_base`.
Then every address in the dump matches the live console addresses seen in the report.

## What was verified on the console (192.168.1.20, FW 9.40)

* `list` → 86 processes (`vmmap_ok=33`, `vmmap_denied=53` kernel threads/objects), 12,373 ranges,
  9,056 bytes of output, 0.22 s.
* `list 67` → 82 ranges, 21,807,104 bytes mapped, 13,418,496 dumpable, 12 exec-only ranges,
  12 module-image candidates, 15,407 bytes, 0.30 s.
* `mod 67 libSceSysmodule` → 4 segments `0x833b74000–0x833ba0000`, **180,224 bytes**, 4/4 read,
  0 errno, 18 ms; `cc_prefix=0x10`, pseudo-prologue `55 48 89 e5` at **+0x10**; file[0..64) ==
  live bytes: YES. SHA-256 `A389FEBD…A374C8`, byte-identical to the earlier independent
  `RedisBoot/dump/sysmod.bin`.
  *Note*: the `+0x80` prologue offset did not reproduce. The 0xCC padding is real (16 bytes on
  9.40/pids 67 and 59, for this module); byte 0x80 is `f7 48 89 de`. The payload prints
  `cc_prefix` and `first_prologue` per module so any image can be checked instead of assumed.
* Same module in SceShellUI (pid 59) is at `0x803e60000`, also 180,224 bytes; code identical,
  data differs (`first_diff=0x14001`) — see above.
* `dump 67` → 74 ranges, 13,418,496 bytes, 0 failed, 0.74 s (17.3 MiB/s); the module's 180,224
  bytes inside that file at the idx-predicted offset `0x768000` are byte-identical to the
  standalone extraction.
* `mod 67 libSceNonexistent` → exact fallback behaviour: 12 candidates listed, no match, explicit
  base suggested, exit code 1.
* cfg path: uploaded `list 67` + `mod 67 libSceSysmodule`, raw send (no argv) ran both; with the
  cfg deleted the payload recreated the default one and auto-ran `list` + `mod SceSpZeroConf
  libSceSysmodule`.

## Why `.text` is not skipped

PS5 maps code as `PROT_EXEC` **only** (`0x4`, no `PROT_READ`). A "readable only" filter silently
drops every code segment — the dump then contains data but no code. `sprxdump` accepts
`KVME_PROT_READ | KVME_PROT_EXEC` everywhere and marks exec-only ranges in `list` output.

## Limitations

* **Read-only by construction**: `sysctl(KERN_PROC_VMMAP)` + `mdbg_copyout` +
  `kernel_dynlib_*` queries. No ptrace (would stop the target), no `mdbg_copyin`, no kernel
  writes, no patches, no kills. Nothing is ever written into another process.
* **Needs privilege**: reading another process requires euid 0 (or the target's authid). On 9.40
  elfldr payloads run euid 0 and 33/86 processes were readable; the rest are kernel threads and
  kernel-only objects whose vmmap the kernel refuses. A payload injected into an unprivileged
  process can enumerate but not dump.
* Ranges are bounded by vmmap, so unreadable holes are recorded (errno per range) and skipped, not
  zero-filled.
* Hard caps: 1 GiB per snapshot, 64 MiB per module, 32 MiB per image cluster; exceeding them stops
  the write with `ENOSPC` in the idx instead of failing silently.
* Segments are dumped as-is: no relocation resolution, no symbol/export reconstruction, no ELF
  rebuild, no section split. You get the decrypted bytes plus the VA map.
* Module names come from the kernel dynlib list, so a module must be loaded in that process; the
  string fallback can pick a wrong image when a name also appears in another module's rodata.
* Interface stability: `KVME_TYPE` 9 is the PS5 module-image type but is not in the public
  `sys/user.h`, and `kernel_dynlib_mapbase_addr()`'s handle semantics are firmware-specific. Both
  are isolated in one function each (`cluster_at`, `kernel_module`).

## Files

```text
sprxdump/
  src/sprxdump.c        single-file payload (read-only dumper)
  build.ps1             clang/ps5-payload-sdk build -> build/sprxdump.elf
  tools/deploy.py       FTP upload + elfldr URI run (raw stream when no args)
  probe/probe*.c        throwaway fact-finders used to pin down the ABI (not shipped)
  examples/             .idx files produced by a real run (format reference)
```
