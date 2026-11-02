/* sprxdump.c - read-only process/module dumper for PS5 (elfldr payload)
 *
 * Headline feature: extract the DECRYPTED in-memory image of a loaded
 * SPRX/SELF module from a live process, plus a VA<->file-offset index that a
 * disassembler can use directly.
 *
 * Mechanism (read-only, no ptrace, no copyin, no target writes, no patches):
 *   - process table:   sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PROC)
 *   - address space:   sysctl(CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid)
 *   - memory reads:    mdbg_copyout()   (libkernel cross-process copyout)
 *   - module lookup:   kernel_dynlib_handle()/mapbase/entry/init/fini
 *                      (kernel-side dynlib walk; read-only query)
 *
 * IMPORTANT: on PS5 the code segment is mapped PROT_EXEC only (0x4, no READ).
 * A "readable only" filter silently drops every .text range; ranges are
 * therefore accepted when (prot & (READ|EXEC)).
 *
 * Commands (argv, comma/space separated, or /data/sprxdump.cfg):
 *   list [pid|name]                 process table; with a target, its vmmap
 *   mod  <pid|name> <module|0xVA>   dump decrypted module image + .idx
 *   dump <pid|name>                 full readable+exec snapshot + .idx
 *
 * Output: /data/sprxdump/report.txt, /data/sprxdump/<x>.bin, <x>.idx
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>
#include <ps5/payload.h>

#define OUTDIR        "/data/sprxdump"
#define REPORT_PATH   OUTDIR "/report.txt"
#define CFG_PATH      "/data/sprxdump.cfg"

#define CHUNK         (32 * 1024)
#define DUMP_CAP      (1024ULL * 1024 * 1024)   /* full dump hard cap        */
#define MOD_CAP       (64ULL * 1024 * 1024)     /* single module hard cap    */
#define CLUSTER_CAP   (32ULL * 1024 * 1024)     /* one module image max      */
#define FP_SCAN_CAP   (8ULL * 1024 * 1024)      /* fingerprint scan per image*/
#define MAX_SEG       64
#define MAX_RANGES    8192
#define MAX_CLUSTERS  256
#define MAX_TOK       12

/* PS5 reports module image segments as type 9, which is not in the public
 * KVME_TYPE_* list of sys/user.h. Kept symbolic so a future SDK can override. */
#define KVME_TYPE_PS5_MODULE 9

typedef struct rng {
  uint64_t start, end;
  int      prot, type, resid;
  char     path[128];
} rng_t;

typedef struct pinfo {
  pid_t    pid, ppid;
  uid_t    uid;
  uint64_t authid;
  long     rss_kb, vsize_kb;
  char     comm[32], tdname[32];
} pinfo_t;

typedef struct seg {
  uint64_t start, end;
  int      prot, type;
  uint64_t off;      /* file offset where this segment was written */
  uint64_t bytes;    /* bytes actually written                    */
  int      err;      /* errno of the first failing chunk, 0 = ok  */
} seg_t;

typedef struct dres {
  uint64_t written, fnv;
  int      segs, segs_ok, segs_failed, write_errno, first_errno;
} dres_t;

static FILE  *g_rep;

/* ------------------------------------------------------------------ utils */

static void
logf(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  fflush(stdout);
  if(g_rep) {
    va_start(ap, fmt);
    vfprintf(g_rep, fmt, ap);
    va_end(ap);
    fflush(g_rep);
  }
}

static void
hexline(const uint8_t *b, size_t n, char *out, size_t outsz) {
  size_t o = 0;

  out[0] = 0;
  for(size_t i = 0; i < n && o + 3 < outsz; i++) {
    o += (size_t)snprintf(out + o, outsz - o, "%02x", b[i]);
  }
}

static int
read_mem(pid_t pid, uint64_t va, void *buf, size_t len) {
  /* Bounds are the caller's job: only ranges reported by KERN_PROC_VMMAP are
   * ever passed here, and len is clamped to the range end before the call. */
  if(len == 0) {
    return 0;
  }
  if(va == 0 || va + len < va) {
    errno = EFAULT;
    return -1;
  }
  errno = 0;
  if(mdbg_copyout(pid, (intptr_t)va, buf, len) != 0) {
    if(!errno) {
      errno = EIO;
    }
    return -1;
  }
  return 0;
}

static void
mkdir_p(const char *path) {
  if(mkdir(path, 0777) < 0 && errno != EEXIST) {
    logf("mkdir(%s) errno=%d (%s)\n", path, errno, strerror(errno));
  }
}

static void
sanitize(char *dst, size_t cap, const char *src) {
  size_t o = 0;

  for(size_t i = 0; src[i] && o + 1 < cap; i++) {
    unsigned char c = (unsigned char)src[i];

    if((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
       (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
      dst[o++] = (char)c;
    } else {
      dst[o++] = '_';
    }
  }
  dst[o] = 0;
  if(!o) {
    snprintf(dst, cap, "unnamed");
  }
}

static void
strip_suffix(char *s) {
  static const char *suf[] = {".sprx", ".prx", ".elf", ".self", NULL};

  for(int i = 0; suf[i]; i++) {
    size_t l = strlen(s), k = strlen(suf[i]);
    if(l > k && !strcasecmp(s + l - k, suf[i])) {
      s[l - k] = 0;
      return;
    }
  }
}

/* ---------------------------------------------------------- process table */

static uint8_t *
proc_table(size_t *out_sz) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
  size_t sz = 0;
  uint8_t *buf;

  if(sysctl(mib, 4, NULL, &sz, NULL, 0) < 0) {
    return NULL;
  }
  if(sz == 0 || !(buf = malloc(sz))) {
    return NULL;
  }
  if(sysctl(mib, 4, buf, &sz, NULL, 0) < 0) {
    free(buf);
    return NULL;
  }
  *out_sz = sz;
  return buf;
}

static void
safe_name(char *dst, size_t cap, const char *src, size_t srccap) {
  size_t i;

  for(i = 0; i < srccap && i + 1 < cap && src[i]; i++) {
    unsigned char c = (unsigned char)src[i];
    dst[i] = (c >= 32 && c < 127) ? (char)c : '.';
  }
  dst[i] = 0;
}

static int
collect_procs(pinfo_t **out, int *out_n) {
  uint8_t *buf;
  size_t size = 0;
  pinfo_t *v;
  int n = 0, cap = 0;

  if(!(buf = proc_table(&size))) {
    return -1;
  }
  if(!(v = calloc(size / 32 + 16, sizeof(*v)))) {
    free(buf);
    return -1;
  }
  cap = (int)(size / 32 + 16);

  for(uint8_t *p = buf; p < buf + size;) {
    struct kinfo_proc *ki = (struct kinfo_proc *)p;
    int ss = ki->ki_structsize;

    if(ss <= 0 || p + ss > buf + size) {
      break;
    }
    p += ss;
    if(ki->ki_pid <= 0 || n >= cap) {
      continue;
    }
    v[n].pid = ki->ki_pid;
    v[n].ppid = ki->ki_ppid;
    v[n].uid = ki->ki_uid;
    v[n].rss_kb = (long)ki->ki_rssize * (long)getpagesize() / 1024;
    v[n].vsize_kb = (long)((uint64_t)ki->ki_size / 1024);
    v[n].authid = kernel_get_ucred_authid(ki->ki_pid);
    safe_name(v[n].comm, sizeof(v[n].comm), ki->ki_comm, sizeof(ki->ki_comm));
    safe_name(v[n].tdname, sizeof(v[n].tdname), ki->ki_tdname,
              sizeof(ki->ki_tdname));
    n++;
  }
  free(buf);
  *out = v;
  *out_n = n;
  return 0;
}

static int
name_matches(const char *hay, const char *needle) {
  /* case-insensitive exact or substring match */
  size_t nh = strlen(hay), nn = strlen(needle);

  if(nn == 0 || nn > nh) {
    return 0;
  }
  for(size_t i = 0; i + nn <= nh; i++) {
    size_t k = 0;
    while(k < nn && tolower((unsigned char)hay[i + k]) ==
                    tolower((unsigned char)needle[k])) {
      k++;
    }
    if(k == nn) {
      return 1;
    }
  }
  return 0;
}

/* Resolve "<pid>" or "<name>" to a pid. Returns 0 on success, -1 if nothing
 * matched, -2 if the name was ambiguous (candidates are printed). */
static int
resolve_pid(const char *spec, pid_t *out_pid, char *out_name, size_t namecap,
            const pinfo_t *procs, int nprocs) {
  char *end = NULL;
  long v;

  errno = 0;
  v = strtol(spec, &end, 10);
  if(end && *end == 0 && errno == 0 && v > 0) {
    for(int i = 0; i < nprocs; i++) {
      if(procs[i].pid == (pid_t)v) {
        *out_pid = procs[i].pid;
        snprintf(out_name, namecap, "%s", procs[i].comm[0] ? procs[i].comm
                                                           : "unnamed");
        return 0;
      }
    }
    /* Not in the table (kernel thread or freshly forked): keep the number,
     * vmmap will tell whether it exists. */
    *out_pid = (pid_t)v;
    snprintf(out_name, namecap, "pid%d", (int)v);
    return 0;
  }

  {
    int exact = -1, sub = -1, nmatch = 0, last = -1;

    for(int i = 0; i < nprocs; i++) {
      if(!strcasecmp(procs[i].comm, spec) || !strcasecmp(procs[i].tdname, spec)) {
        if(exact < 0) exact = i;
        nmatch++;
        last = i;
        continue;
      }
      if(name_matches(procs[i].comm, spec) || name_matches(procs[i].tdname, spec)) {
        if(sub < 0) sub = i;
        nmatch++;
        last = i;
      }
    }
    if(exact >= 0) {
      *out_pid = procs[exact].pid;
      snprintf(out_name, namecap, "%s", procs[exact].comm);
      return 0;
    }
    if(nmatch == 1 && sub >= 0) {
      *out_pid = procs[sub].pid;
      snprintf(out_name, namecap, "%s", procs[sub].comm);
      return 0;
    }
    if(nmatch == 0) {
      logf("no process matches \"%s\"\n", spec);
      return -1;
    }
    logf("\"%s\" is ambiguous (%d matches):\n", spec, nmatch);
    for(int i = 0; i < nprocs; i++) {
      if(!strcasecmp(procs[i].comm, spec) || !strcasecmp(procs[i].tdname, spec) ||
         name_matches(procs[i].comm, spec) || name_matches(procs[i].tdname, spec)) {
        logf("   %-20s pid=%d uid=%d\n", procs[i].comm, (int)procs[i].pid,
             (int)procs[i].uid);
      }
    }
    (void)last;
    return -2;
  }
}

/* --------------------------------------------------------------- vmmap */

static int
rng_is_candidate(const rng_t *r) {
  /* The whole point: EXEC alone is enough. A READ-only filter would drop
   * every code segment on PS5. */
  if(!(r->prot & (KVME_PROT_READ | KVME_PROT_EXEC))) {
    return 0;
  }
  if(r->end <= r->start || r->start < 0x10000) {
    return 0;
  }
  if(r->type == KVME_TYPE_DEVICE || r->type == KVME_TYPE_MGTDEVICE) {
    return 0;
  }
  if(!strncmp(r->path, "/dev/", 5)) {
    return 0;
  }
  return 1;
}

static int
vmmap_get(pid_t pid, rng_t **out, int *out_n, int *out_err) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, (int)pid};
  size_t vsz = 0;
  uint8_t *vm;
  rng_t *r;
  int n = 0;

  *out = NULL;
  *out_n = 0;
  *out_err = 0;
  errno = 0;
  if(sysctl(mib, 4, NULL, &vsz, NULL, 0) < 0) {
    *out_err = errno ? errno : EIO;
    return -1;
  }
  if(vsz == 0 || !(vm = malloc(vsz))) {
    *out_err = errno ? errno : ENOMEM;
    return -1;
  }
  if(sysctl(mib, 4, vm, &vsz, NULL, 0) < 0) {
    *out_err = errno ? errno : EIO;
    free(vm);
    return -1;
  }
  if(!(r = calloc(vsz / 16 + 32, sizeof(*r)))) {
    *out_err = ENOMEM;
    free(vm);
    return -1;
  }
  for(uint8_t *p = vm; p < vm + vsz && n < MAX_RANGES;) {
    struct kinfo_vmentry *ve = (struct kinfo_vmentry *)p;
    int ss = ve->kve_structsize;

    if(ss <= 0 || p + ss > vm + vsz) {
      break;
    }
    p += ss;
    if(ve->kve_end <= ve->kve_start) {
      continue;
    }
    r[n].start = ve->kve_start;
    r[n].end = ve->kve_end;
    r[n].prot = ve->kve_protection;
    r[n].type = ve->kve_type;
    r[n].resid = ve->kve_resident;
    snprintf(r[n].path, sizeof(r[n].path), "%s", ve->kve_path);
    n++;
  }
  free(vm);
  *out = r;
  *out_n = n;
  return 0;
}

/* A module image is a run of contiguous ranges of the same vmmap type that
 * starts with an executable one. On 9.40 the loaded image of libSceSysmodule
 * in pid 67 is exactly [text RX][rodata R][rodata R][data RW] = 0x2C000
 * bytes (180224) and the anonymous .bss that follows is a different type, so
 * it is not swallowed. */
static int
cluster_at(const rng_t *r, int n, int i, seg_t *out, int max, int out_idx[]) {
  int k = 0;
  uint64_t expect = r[i].start;

  if(!(r[i].prot & KVME_PROT_EXEC) || !rng_is_candidate(&r[i])) {
    return 0;
  }
  /* never part of a file-backed module image */
  if(r[i].type == KVME_TYPE_PHYS || r[i].type == KVME_TYPE_SWAP ||
     r[i].type == KVME_TYPE_DEAD) {
    return 0;
  }
  for(int j = i; j < n && k < max; j++) {
    if(r[j].start != expect) {
      break;
    }
    if(!rng_is_candidate(&r[j]) || r[j].type != r[i].type) {
      break;
    }
    if(r[j].end - r[j].start > CLUSTER_CAP ||
       (r[j].end - r[j].start) + (expect - r[i].start) > CLUSTER_CAP) {
      break;
    }
    out[k].start = r[j].start;
    out[k].end = r[j].end;
    out[k].prot = r[j].prot;
    out[k].type = r[j].type;
    out[k].off = 0;
    out[k].bytes = 0;
    out[k].err = 0;
    if(out_idx) {
      out_idx[k] = j;
    }
    k++;
    expect = r[j].end;
  }
  return k;
}

static int
count_prologues(pid_t pid, uint64_t start, uint64_t end, uint64_t cap) {
  uint8_t *buf;
  uint64_t a = start, stop = end;
  int n = 0;

  if(stop > a + cap) {
    stop = a + cap;
  }
  if(!(buf = malloc(CHUNK))) {
    return 0;
  }
  while(a + 4 <= stop) {
    size_t len = (size_t)((stop - a) < CHUNK ? (stop - a) : CHUNK);

    if(read_mem(pid, a, buf, len) != 0) {
      break;
    }
    for(size_t i = 0; i + 4 <= len; i++) {
      if(buf[i] == 0x55 && buf[i + 1] == 0x48 && buf[i + 2] == 0x89 &&
         buf[i + 3] == 0xe5) {
        n++;
      }
    }
    if(len == 0) {
      break;
    }
    a += len;
  }
  free(buf);
  return n;
}

/* -------------------------------------------------------------- dumping */

static void
write_idx(const char *idxpath, const char *label, pid_t pid, uint64_t base,
          const seg_t *seg, int nseg, const dres_t *res) {
  FILE *f = fopen(idxpath, "w");

  if(!f) {
    logf("idx open %s failed errno=%d (%s)\n", idxpath, errno, strerror(errno));
    return;
  }
  fprintf(f, "# sprxdump %s pid=%d image_base=0x%llx\n", label, (int)pid,
          (unsigned long long)base);
  fprintf(f, "# va->file: off = file_off + (va - start)\n");
  fprintf(f, "# start end prot type bytes err file_off path\n");
  for(int i = 0; i < nseg; i++) {
    fprintf(f, "0x%016llx 0x%016llx 0x%x %d %llu %d 0x%llx %s\n",
            (unsigned long long)seg[i].start,
            (unsigned long long)seg[i].end, (unsigned)seg[i].prot,
            seg[i].type, (unsigned long long)seg[i].bytes, seg[i].err,
            (unsigned long long)seg[i].off, "-");
  }
  fprintf(f, "# bytes_written=%llu fnv1a64=0x%016llx\n",
          (unsigned long long)res->written, (unsigned long long)res->fnv);
  fclose(f);
}

static void
dump_segments(pid_t pid, seg_t *seg, int nseg, const char *binpath,
              const char *idxpath, const char *label, uint64_t base,
              uint64_t budget, dres_t *res) {
  uint8_t *buf;
  FILE *f;
  uint64_t fnv = 0xcbf29ce484222325ULL;

  memset(res, 0, sizeof(*res));
  res->segs = nseg;

  if(!(buf = malloc(CHUNK))) {
    res->write_errno = ENOMEM;
    logf("%s: malloc errno=%d\n", label, errno);
    return;
  }
  if(!(f = fopen(binpath, "wb"))) {
    res->write_errno = errno;
    logf("%s: fopen(%s) errno=%d (%s)\n", label, binpath, errno,
         strerror(errno));
    free(buf);
    return;
  }

  for(int s = 0; s < nseg; s++) {
    seg[s].off = res->written;
    seg[s].bytes = 0;
    seg[s].err = 0;

    for(uint64_t a = seg[s].start; a < seg[s].end;) {
      size_t len = (size_t)((seg[s].end - a) < CHUNK ? (seg[s].end - a) : CHUNK);

      if(res->written + len > budget) {
        seg[s].err = ENOSPC;
        res->write_errno = ENOSPC;
        break;
      }
      if(read_mem(pid, a, buf, len) != 0) {
        seg[s].err = errno ? errno : EIO;
        if(!res->first_errno) {
          res->first_errno = seg[s].err;
        }
        res->segs_failed++;
        break;                 /* skip the rest of this range, keep going */
      }
      if(fwrite(buf, 1, len, f) != len) {
        seg[s].err = errno ? errno : EIO;
        res->write_errno = seg[s].err;
        break;
      }
      for(size_t i = 0; i < len; i++) {
        fnv = (fnv ^ buf[i]) * 0x100000001b3ULL;
      }
      seg[s].bytes += len;
      res->written += len;
      a += len;
    }
    if(seg[s].bytes == seg[s].end - seg[s].start) {
      res->segs_ok++;
    }
  }
  fclose(f);
  free(buf);
  res->fnv = fnv;
  write_idx(idxpath, label, pid, base, seg, nseg, res);
}

/* ------------------------------------------------------ module resolving */

static int
kernel_module(pid_t pid, const char *name, intptr_t *out_base,
              intptr_t *out_entry, intptr_t *out_init, intptr_t *out_fini) {
  char try_name[192];
  uint32_t h = 0;
  static const char *ext[] = {"", ".sprx", ".prx", ".elf", NULL};

  for(int i = 0; ext[i]; i++) {
    snprintf(try_name, sizeof(try_name), "%s%s", name, ext[i]);
    if(strlen(try_name) >= sizeof(try_name)) {
      continue;
    }
    h = 0;
    errno = 0;
    if(kernel_dynlib_handle(pid, try_name, &h) == 0) {
      intptr_t b = kernel_dynlib_mapbase_addr(pid, h);
      if(b) {
        *out_base = b;
        *out_entry = kernel_dynlib_entry_addr(pid, h);
        *out_init = kernel_dynlib_init_addr(pid, h);
        *out_fini = kernel_dynlib_fini_addr(pid, h);
        return 0;
      }
    }
  }
  return -1;
}

/* Fingerprint fallback (used only when the kernel dynlib walk refuses, e.g.
 * another firmware). Looks for the module name in each module-image cluster.
 * On 9.40 this is deliberately secondary: the literal "libSceSysmodule" also
 * appears in an unrelated 128 KiB rodata range of pid 67, so a raw name match
 * alone identifies the WRONG image. Candidates are therefore always listed
 * and an explicit base (mod <pid> 0x<base>) is accepted. */
static int
fingerprint_module(pid_t pid, const rng_t *r, int nr, const char *name,
                   uint64_t want_base, uint64_t *out_base, int *out_ambig) {
  seg_t seg[MAX_SEG];
  int ncl = 0, ties = 0, best = -1, best_hits = -1;
  uint8_t *buf;
  char n1[160], n2[168];
  size_t l1, l2;

  *out_ambig = 0;
  snprintf(n1, sizeof(n1), "%s", name);
  snprintf(n2, sizeof(n2), "%s.sprx", name);
  l1 = strlen(n1);
  l2 = strlen(n2);

  if(!(buf = malloc(CHUNK))) {
    return -1;
  }
  logf("fingerprint search for \"%s\" in pid %d\n", name, (int)pid);

  for(int i = 0; i < nr; i++) {
    int nseg = cluster_at(r, nr, i, seg, MAX_SEG, NULL);

    if(nseg <= 0 || !(seg[0].prot & KVME_PROT_EXEC)) {
      continue;
    }
    uint64_t base = seg[0].start, total = seg[nseg - 1].end - base;
    uint64_t limit = total > FP_SCAN_CAP ? FP_SCAN_CAP : total;
    int hits = 0;

    ncl++;
    for(uint64_t a = base; a < base + limit;) {
      size_t len = (size_t)((base + limit - a) < CHUNK ? (base + limit - a) : CHUNK);
      size_t step, valid;

      if(read_mem(pid, a, buf, len) != 0) {
        break;
      }
      step = (len == CHUNK && a + len < base + limit) ? (CHUNK - 127) : len;
      valid = (len == CHUNK && a + len < base + limit) ? step : len;
      for(size_t k = 0; k < valid; k++) {
        if(buf[k] != (uint8_t)n1[0]) {
          continue;
        }
        if(k + l2 <= len && !memcmp(buf + k, n2, l2)) {
          hits += 2;
        } else if(k + l1 <= len && !memcmp(buf + k, n1, l1)) {
          hits++;
        }
      }
      if(len < CHUNK) {
        break;
      }
      a += step;
    }

    logf("  cand base=0x%09llx size=%llu segs=%d namehits=%d%s\n",
         (unsigned long long)base, (unsigned long long)total, nseg, hits,
         (want_base && base == want_base) ? " <- requested" : "");

    if(want_base) {
      if(base == want_base) {
        best = i;
        best_hits = hits;
        break;
      }
      continue;
    }
    if(hits > best_hits) {
      best_hits = hits;
      best = i;
      ties = 0;
    } else if(hits == best_hits && hits > 0) {
      ties++;
    }
  }
  free(buf);

  if(best < 0 || best_hits <= 0) {
    logf("  no module image contains \"%s\" (%d image clusters seen)\n", name,
         ncl);
    logf("  pick a base by hand: mod %d 0x<base>   (bases: see \"list %d\")\n",
         (int)pid, (int)pid);
    return -1;
  }
  if(ties) {
    *out_ambig = ties + 1;
    logf("  warning: %d image(s) score the same; using 0x%09llx, pass an "
         "explicit base to override\n", ties + 1,
         (unsigned long long)r[best].start);
  }
  *out_base = r[best].start;
  return 0;
}

/* ------------------------------------------------------------- commands */

static void
cmd_list(pid_t self, const char *spec, const pinfo_t *procs, int nprocs) {
  logf("-- processes (pid ppid uid authid rss_kb vsize_kb ranges comm) --\n");
  logf("%5s %5s %3s %18s %8s %9s %6s %-20s %s\n", "pid", "ppid", "uid",
       "authid", "rss_kb", "vsize_kb", "ranges", "comm", "tdname");

  int listed = 0, noprocs = 0;
  uint64_t total_ranges = 0;

  for(int i = 0; i < nprocs; i++) {
    rng_t *r = NULL;
    int nr = 0, err = 0;
    char rtxt[16];

    if(vmmap_get(procs[i].pid, &r, &nr, &err) == 0) {
      snprintf(rtxt, sizeof(rtxt), "%d", nr);
      total_ranges += (uint64_t)nr;
      free(r);
    } else {
      snprintf(rtxt, sizeof(rtxt), "-");
      noprocs++;
    }
    logf("%5d %5d %3d 0x%016llx %8ld %9ld %6s %-20s %s\n",
         (int)procs[i].pid, (int)procs[i].ppid, (int)procs[i].uid,
         (unsigned long long)procs[i].authid, procs[i].rss_kb,
         procs[i].vsize_kb, rtxt, procs[i].comm, procs[i].tdname);
    listed++;
  }
  logf("processes=%d vmmap_ok=%d vmmap_denied=%d total_ranges=%llu self=%d\n",
       listed, listed - noprocs, noprocs, (unsigned long long)total_ranges,
       (int)self);

  if(!spec || !*spec) {
    logf("tip: \"list <pid|name>\" prints that process's vmmap summary and "
         "module images\n");
    return;
  }

  {
    pid_t pid = 0;
    char pname[64];
    rng_t *r = NULL;
    int nr = 0, err = 0;

    if(resolve_pid(spec, &pid, pname, sizeof(pname), procs, nprocs) != 0) {
      return;
    }
    if(pid == self) {
      logf("refusing to dump myself (pid %d)\n", (int)self);
      return;
    }
    logf("\n-- vmmap pid=%d (%s) --\n", (int)pid, pname);
    if(vmmap_get(pid, &r, &nr, &err) != 0) {
      logf("vmmap failed errno=%d (%s)\n", err, strerror(err));
      return;
    }

    uint64_t tot = 0, readable = 0, exec_only = 0;
    int excluded = 0;

    for(int i = 0; i < nr; i++) {
      tot += r[i].end - r[i].start;
      if(!rng_is_candidate(&r[i])) {
        excluded++;
      } else {
        readable += r[i].end - r[i].start;
        if((r[i].prot & KVME_PROT_EXEC) && !(r[i].prot & KVME_PROT_READ)) {
          exec_only++;
        }
      }
    }
    logf("ranges=%d mapped=%llu bytes dumpable=%llu bytes exec_only=%llu "
         "excluded=%d\n", nr, (unsigned long long)tot,
         (unsigned long long)readable, (unsigned long long)exec_only, excluded);

    logf("  %-3s %-10s %-10s %8s %-4s %-4s %s\n", "idx", "start", "end",
         "size", "prot", "type", "path");
    for(int i = 0; i < nr; i++) {
      char p[5];
      snprintf(p, sizeof(p), "%c%c%c%c",
               (r[i].prot & KVME_PROT_READ) ? 'r' : '-',
               (r[i].prot & KVME_PROT_WRITE) ? 'w' : '-',
               (r[i].prot & KVME_PROT_EXEC) ? 'x' : '-',
               ((r[i].prot & KVME_PROT_EXEC) && !(r[i].prot & KVME_PROT_READ))
                   ? '!' : ' ');
      logf("  [%-3d] 0x%09llx 0x%09llx %8llu 0x%x %-4d %s%s\n", i,
           (unsigned long long)r[i].start, (unsigned long long)r[i].end,
           (unsigned long long)(r[i].end - r[i].start), (unsigned)r[i].prot,
           r[i].type, r[i].path[0] ? r[i].path : "-",
           ((r[i].prot & KVME_PROT_EXEC) && !(r[i].prot & KVME_PROT_READ))
               ? "  (exec-only .text, read via mdbg)" : "");
    }

    logf("\n-- module image candidates (contiguous ranges from an exec base) --\n");
    int nmod = 0;
    for(int i = 0; i < nr; i++) {
      seg_t s[MAX_SEG];
      int ns = cluster_at(r, nr, i, s, MAX_SEG, NULL);

      if(ns <= 0) {
        continue;
      }
      nmod++;
      uint64_t base = s[0].start, end = s[ns - 1].end;
      uint8_t head[16];
      char hex[64];
      int got;

      memset(head, 0, sizeof(head));
      got = read_mem(pid, base, head, sizeof(head)) == 0;
      if(got) {
        hexline(head, sizeof(head), hex, sizeof(hex));
      } else {
        snprintf(hex, sizeof(hex), "(read failed errno=%d)", errno);
      }
      logf("  image base=0x%09llx end=0x%09llx size=%llu segs=%d "
           "prologues=%d head=%s\n", (unsigned long long)base,
           (unsigned long long)end, (unsigned long long)(end - base), ns,
           count_prologues(pid, s[0].start, s[0].end, 1ULL << 20), hex);
      i += ns - 1;
    }
    logf("module_images=%d\n", nmod);
    logf("hint: \"mod %d <libName>\" dumps one of them decrypted\n", (int)pid);
    free(r);
  }
}

static int
cmd_mod(pid_t self, const char *pspec, const char *modspec, const char *base_spec,
        const pinfo_t *procs, int nprocs) {
  pid_t pid = 0;
  char pname[64];
  rng_t *r = NULL;
  int nr = 0, err = 0;
  seg_t seg[MAX_SEG];
  int nseg = 0;
  uint64_t base = 0, want_base = 0;
  intptr_t kbase = 0, kentry = 0, kinit = 0, kfini = 0;
  int have_kernel = 0;
  char modname[128], filebase[128], binpath[192], idxpath[192];

  if(!modspec || !*modspec) {
    logf("usage: mod <pid|name> <module-name|0xBASE> [0xBASE]\n");
    return -1;
  }
  if(resolve_pid(pspec, &pid, pname, sizeof(pname), procs, nprocs) != 0) {
    return -1;
  }
  if(pid == self) {
    logf("refusing to dump myself (pid %d)\n", (int)self);
    return -1;
  }

  snprintf(modname, sizeof(modname), "%s", modspec);
  if(base_spec && *base_spec) {
    want_base = strtoull(base_spec, NULL, 0);
  }
  if(!strncasecmp(modspec, "0x", 2)) {
    want_base = strtoull(modspec, NULL, 0);
    snprintf(modname, sizeof(modname), "mod_%09llx",
             (unsigned long long)want_base);
  }

  logf("\n-- mod pid=%d (%s) module=%s --\n", (int)pid, pname, modname);

  if(vmmap_get(pid, &r, &nr, &err) != 0) {
    logf("vmmap failed errno=%d (%s)\n", err, strerror(err));
    return -1;
  }

  if(!want_base) {
    if(kernel_module(pid, modname, &kbase, &kentry, &kinit, &kfini) == 0) {
      base = (uint64_t)kbase;
      have_kernel = 1;
      logf("kernel dynlib: base=0x%09llx entry=0x%09llx init=0x%09llx "
           "fini=0x%09llx\n", (unsigned long long)kbase,
           (unsigned long long)kentry, (unsigned long long)kinit,
           (unsigned long long)kfini);
    } else {
      int ambig = 0;
      logf("kernel dynlib lookup failed for \"%s\" (errno=%d); "
           "falling back to name fingerprint\n", modname, errno);
      if(fingerprint_module(pid, r, nr, modname, 0, &base, &ambig) != 0) {
        logf("module not found. Loaded modules can be listed with "
             "\"list %d\" (module image candidates), or pass the base VA: "
             "mod %d 0x<base>\n", (int)pid, (int)pid);
        free(r);
        return -1;
      }
      logf("fingerprint pick: base=0x%09llx (verify the entry stub)\n",
           (unsigned long long)base);
    }
  } else {
    base = want_base;
    if(kernel_module(pid, modname, &kbase, &kentry, &kinit, &kfini) == 0 &&
       (uint64_t)kbase == base) {
      have_kernel = 1;
      logf("kernel dynlib: base=0x%09llx entry=0x%09llx init=0x%09llx "
           "fini=0x%09llx\n", (unsigned long long)kbase,
           (unsigned long long)kentry, (unsigned long long)kinit,
           (unsigned long long)kfini);
    } else {
      logf("explicit base 0x%09llx requested\n", (unsigned long long)base);
    }
  }

  /* locate the range that starts exactly at the module base */
  int at = -1;
  for(int i = 0; i < nr; i++) {
    if(r[i].start == base) {
      at = i;
      break;
    }
  }
  if(at < 0) {
    logf("base 0x%09llx is not the start of a mapped range (moved/unloaded?)\n",
         (unsigned long long)base);
    free(r);
    return -1;
  }

  nseg = cluster_at(r, nr, at, seg, MAX_SEG, NULL);
  if(nseg <= 0) {
    /* Single-range fallback: at least dump the requested range. */
    seg[0].start = r[at].start;
    seg[0].end = r[at].end;
    seg[0].prot = r[at].prot;
    seg[0].type = r[at].type;
    seg[0].off = seg[0].bytes = 0;
    seg[0].err = 0;
    nseg = 1;
    logf("warning: no contiguous image run at this base, dumping one range\n");
  }

  uint64_t total = seg[nseg - 1].end - seg[0].start;
  if(total > MOD_CAP) {
    logf("refusing: image is %llu bytes (> %llu cap)\n",
         (unsigned long long)total, (unsigned long long)MOD_CAP);
    free(r);
    return -1;
  }

  logf("segments=%d span=0x%09llx-0x%09llx size=%llu\n", nseg,
       (unsigned long long)seg[0].start,
       (unsigned long long)seg[nseg - 1].end, (unsigned long long)total);
  for(int i = 0; i < nseg; i++) {
    logf("  seg[%d] 0x%09llx-0x%09llx prot=0x%x type=%d size=%llu%s\n", i,
         (unsigned long long)seg[i].start, (unsigned long long)seg[i].end,
         (unsigned)seg[i].prot, seg[i].type,
         (unsigned long long)(seg[i].end - seg[i].start),
         ((seg[i].prot & KVME_PROT_EXEC) && !(seg[i].prot & KVME_PROT_READ))
             ? "  (exec-only)" : "");
  }

  if(have_kernel) {
    uint64_t lo = seg[0].start, hi = seg[nseg - 1].end;
    int e_in = (uint64_t)kentry >= lo && (uint64_t)kentry < hi;
    int i_in = (uint64_t)kinit >= lo && (uint64_t)kinit < hi;
    int f_in = (uint64_t)kfini >= lo && (uint64_t)kfini < hi;

    logf("kernel sanity: entry_in_image=%s init_in_image=%s fini_in_image=%s\n",
         e_in ? "yes" : "NO", i_in ? "yes" : "NO", f_in ? "yes" : "NO");
    if(!e_in) {
      logf("warning: entry is outside the image, the range cluster may be "
           "truncated\n");
    }
  }

  /* confirmation reads before the write: entry stub, prologue density */
  {
    uint8_t head[0x100];
    int cc = 0, pro = 0, first_pro = -1;

    memset(head, 0, sizeof(head));
    if(read_mem(pid, base, head, sizeof(head)) == 0) {
      while(cc < (int)sizeof(head) && head[cc] == 0xCC) {
        cc++;
      }
      for(int i = 0; i + 4 <= (int)sizeof(head); i++) {
        if(head[i] == 0x55 && head[i + 1] == 0x48 && head[i + 2] == 0x89 &&
           head[i + 3] == 0xe5) {
          pro++;
          if(first_pro < 0) {
            first_pro = i;
          }
        }
      }
      char hex[600];
      hexline(head, 64, hex, sizeof(hex));
      logf("base head cc_prefix=0x%x first_prologue=+0x%x prologues_in_0x100=%d\n",
           cc, first_pro < 0 ? 0 : first_pro, pro);
      logf("base bytes: %s\n", hex);

      /* Some firmware keeps the decrypted ELF header at the image base; 9.40
       * does not (0/74 and 0/2202 ranges scanned). Report it when present. */
      if(head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F') {
        uint64_t phoff = 0, shoff = 0;
        uint16_t phentsize = 0, phnum = 0, shentsize = 0, shnum = 0;

        memcpy(&phoff, head + 0x20, 8);
        memcpy(&shoff, head + 0x28, 8);
        memcpy(&phentsize, head + 0x36, 2);
        memcpy(&phnum, head + 0x38, 2);
        memcpy(&shentsize, head + 0x3a, 2);
        memcpy(&shnum, head + 0x3c, 2);
        logf("elf: header at base e_phoff=0x%llx phnum=%u (entsize %u) "
             "e_shoff=0x%llx shnum=%u (entsize %u)\n",
             (unsigned long long)phoff, (unsigned)phnum, (unsigned)phentsize,
             (unsigned long long)shoff, (unsigned)shnum, (unsigned)shentsize);
      } else {
        logf("elf: no ELF header at base (image is mapped decrypted without "
             "one; fingerprint/dynlib locators only)\n");
      }
    } else {
      logf("base read failed errno=%d (%s)\n", errno, strerror(errno));
    }
    if(have_kernel && kentry && (uint64_t)kentry >= base &&
       (uint64_t)kentry < seg[nseg - 1].end) {
      uint8_t e[0x20];
      memset(e, 0, sizeof(e));
      if(read_mem(pid, (uint64_t)kentry, e, sizeof(e)) == 0) {
        char hex[80];
        hexline(e, sizeof(e), hex, sizeof(hex));
        logf("entry bytes @0x%09llx: %s\n", (unsigned long long)kentry, hex);
      }
    }
  }

  snprintf(filebase, sizeof(filebase), "%s", modname);
  strip_suffix(filebase);
  {
    char safe[128];
    sanitize(safe, sizeof(safe), filebase);
    snprintf(binpath, sizeof(binpath), OUTDIR "/%s.bin", safe);
    snprintf(idxpath, sizeof(idxpath), OUTDIR "/%s.idx", safe);
  }

  {
    dres_t res;
    struct timeval t0, t1;

    gettimeofday(&t0, NULL);
    dump_segments(pid, seg, nseg, binpath, idxpath, modname, base, MOD_CAP, &res);
    gettimeofday(&t1, NULL);

    double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                (t1.tv_usec - t0.tv_usec) / 1000.0;
    logf("module dump: %s bytes=%llu segs=%d/%d failed=%d errno=%d fnv1a64=0x%016llx "
         "in %.0f ms\n", binpath, (unsigned long long)res.written,
         res.segs_ok, res.segs, res.segs_failed, res.first_errno,
         (unsigned long long)res.fnv, ms);
    logf("index: %s\n", idxpath);

    if(res.written == 0) {
      logf("error: nothing written (first errno=%d %s)\n", res.first_errno,
           strerror(res.first_errno));
      free(r);
      return -1;
    }

    /* read-back proof: file content == live bytes at base */
    {
      FILE *f = fopen(binpath, "rb");
      uint8_t live[64], fromfile[64];
      memset(live, 0, sizeof(live));
      memset(fromfile, 0, sizeof(fromfile));
      int live_ok = read_mem(pid, base, live, sizeof(live)) == 0;
      int file_ok = 0;

      if(f) {
        file_ok = fread(fromfile, 1, sizeof(fromfile), f) == sizeof(fromfile);
        fclose(f);
      }
      if(live_ok && file_ok) {
        char hex[600];
        hexline(fromfile, 64, hex, sizeof(hex));
        logf("file head: %s\n", hex);
        logf("confirmation: file[0..64) == live[base..base+64): %s\n",
             memcmp(live, fromfile, 64) == 0 ? "YES" : "NO");
      } else {
        logf("confirmation unavailable (live=%d file=%d)\n", live_ok, file_ok);
      }
    }

    if(res.segs_failed) {
      logf("note: %d range(s) could not be read; their errno is in the idx\n",
           res.segs_failed);
    }
  }

  free(r);
  return 0;
}

static int
cmd_dump(pid_t self, const char *pspec, const pinfo_t *procs, int nprocs) {
  pid_t pid = 0;
  char pname[64];
  rng_t *r = NULL;
  int nr = 0, err = 0;
  seg_t *seg;
  int nseg = 0;
  char filebase[128], binpath[192], idxpath[192];

  if(!pspec || !*pspec) {
    logf("usage: dump <pid|name>\n");
    return -1;
  }
  if(resolve_pid(pspec, &pid, pname, sizeof(pname), procs, nprocs) != 0) {
    return -1;
  }
  if(pid == self) {
    logf("refusing to dump myself (pid %d)\n", (int)self);
    return -1;
  }

  logf("\n-- dump pid=%d (%s) --\n", (int)pid, pname);
  if(vmmap_get(pid, &r, &nr, &err) != 0) {
    logf("vmmap failed errno=%d (%s)\n", err, strerror(err));
    return -1;
  }
  if(!(seg = calloc((size_t)nr + 1, sizeof(*seg)))) {
    free(r);
    return -1;
  }
  for(int i = 0; i < nr; i++) {
    if(!rng_is_candidate(&r[i])) {
      continue;
    }
    seg[nseg].start = r[i].start;
    seg[nseg].end = r[i].end;
    seg[nseg].prot = r[i].prot;
    seg[nseg].type = r[i].type;
    seg[nseg].off = seg[nseg].bytes = 0;
    seg[nseg].err = 0;
    nseg++;
  }
  if(nseg == 0) {
    logf("no dumpable ranges (all excluded)\n");
    free(seg);
    free(r);
    return -1;
  }

  snprintf(filebase, sizeof(filebase), "%s_%d", pname, (int)pid);
  {
    char safe[128];
    sanitize(safe, sizeof(safe), filebase);
    snprintf(binpath, sizeof(binpath), OUTDIR "/%s.bin", safe);
    snprintf(idxpath, sizeof(idxpath), OUTDIR "/%s.idx", safe);
  }

  {
    dres_t res;
    struct timeval t0, t1;
    uint64_t want = 0;

    for(int i = 0; i < nseg; i++) {
      want += seg[i].end - seg[i].start;
    }
    logf("ranges=%d planned=%llu bytes (cap %llu)\n", nseg,
         (unsigned long long)want, (unsigned long long)DUMP_CAP);

    gettimeofday(&t0, NULL);
    dump_segments(pid, seg, nseg, binpath, idxpath, pname, seg[0].start,
                  DUMP_CAP, &res);
    gettimeofday(&t1, NULL);

    double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1e6;
    logf("dump: %s bytes_written=%llu planned=%llu ranges_ok=%d failed=%d "
         "errno=%d fnv1a64=0x%016llx in %.2f s (%.1f MiB/s)\n", binpath,
         (unsigned long long)res.written,
         (unsigned long long)want, res.segs_ok, res.segs_failed,
         res.first_errno, (unsigned long long)res.fnv, secs,
         secs > 0 ? (double)res.written / (1024.0 * 1024.0) / secs : 0.0);
    logf("index: %s\n", idxpath);

    if(res.write_errno) {
      logf("write error errno=%d (%s): dump truncated\n", res.write_errno,
           strerror(res.write_errno));
    }
    if(res.segs_failed) {
      logf("note: %d range(s) unreadable (errno per range in the idx)\n",
           res.segs_failed);
    }
    if(!res.written) {
      logf("error: nothing written (first errno=%d %s)\n", res.first_errno,
           strerror(res.first_errno));
      free(seg);
      free(r);
      return -1;
    }
    logf("va->file mapping for this snapshot:\n");
    for(int i = 0; i < nseg && i < 6; i++) {
      logf("  va 0x%09llx-0x%09llx -> file[0x%llx,0x%llx)\n",
           (unsigned long long)seg[i].start, (unsigned long long)seg[i].end,
           (unsigned long long)seg[i].off,
           (unsigned long long)(seg[i].off + seg[i].bytes));
    }
    if(nseg > 6) {
      logf("  ... %d more ranges, see %s\n", nseg - 6, idxpath);
    }
  }

  free(seg);
  free(r);
  return 0;
}

/* ------------------------------------------------------------- argv/cfg */

static int
tokenize(const char *line, char *buf, size_t bufsz, char *tok[], int maxtok) {
  int nt = 0, in = 0;
  size_t o = 0;

  for(size_t i = 0; line[i]; i++) {
    char c = line[i];

    if(c == '#') {
      break;                       /* comment to end of line */
    }
    if(c == ',' || isspace((unsigned char)c)) {
      if(in) {
        if(o + 1 < bufsz) {
          buf[o++] = 0;
        }
        nt++;
        in = 0;
      }
      continue;
    }
    if(!in && nt < maxtok) {
      tok[nt] = buf + o;
      in = 1;
    }
    if(o + 1 < bufsz) {
      buf[o++] = c;
    }
  }
  if(in && nt < maxtok) {
    if(o + 1 < bufsz) {
      buf[o++] = 0;
    }
    nt++;
  }
  if(o < bufsz) {
    buf[o] = 0;
  }
  return nt > maxtok ? maxtok : nt;
}

static int
run_command(int argc, char **argv, pid_t self, const pinfo_t *procs,
            int nprocs) {
  const char *cmd = argv[0];
  int rc = 0;

  if(!strcasecmp(cmd, "list") || !strcasecmp(cmd, "ps")) {
    cmd_list(self, argc > 1 ? argv[1] : NULL, procs, nprocs);
  } else if(!strcasecmp(cmd, "mod") || !strcasecmp(cmd, "module")) {
    if(argc < 3) {
      logf("usage: mod <pid|name> <module-name|0xBASE> [0xBASE]\n");
      return -1;
    }
    rc = cmd_mod(self, argv[1], argv[2], argc > 3 ? argv[3] : NULL, procs,
                 nprocs);
  } else if(!strcasecmp(cmd, "dump")) {
    if(argc < 2) {
      logf("usage: dump <pid|name>\n");
      return -1;
    }
    rc = cmd_dump(self, argv[1], procs, nprocs);
  } else if(!strcasecmp(cmd, "help") || !strcasecmp(cmd, "--help") ||
            !strcasecmp(cmd, "-h")) {
    logf("sprxdump <command> [args]\n"
         "  list [pid|name]                process table (+ vmmap + module "
         "images for one target)\n"
         "  mod  <pid|name> <module|0xVA>  dump decrypted module image to "
         OUTDIR "/<module>.bin (+ .idx)\n"
         "  dump <pid|name>                full readable+exec snapshot (+ .idx)\n"
         "  help\n"
         "commands can also come from " CFG_PATH "\n");
  } else {
    logf("unknown command \"%s\" (try \"help\")\n", cmd);
    rc = -1;
  }
  return rc;
}

static void
write_default_cfg(const char *why) {
  FILE *f = fopen(CFG_PATH, "w");

  if(!f) {
    logf("could not create %s errno=%d (%s)\n", CFG_PATH, errno,
         strerror(errno));
    return;
  }
  fprintf(f, "# sprxdump.cfg - commands run when the payload is sent without "
             "argv.\n");
  fprintf(f, "# One command per line, '#' starts a comment, args are separated "
             "by spaces or commas.\n");
  fprintf(f, "#   list [pid|name]\n");
  fprintf(f, "#   mod  <pid|name> <module-name|0xBASE>\n");
  fprintf(f, "#   dump <pid|name>\n");
  fprintf(f, "# This file was created automatically (%s). Edit it over FTP "
             "(port 2120)\n", why);
  fprintf(f, "# and send the ELF again; argv always wins over this file.\n");
  fprintf(f, "\nlist\n");
  fprintf(f, "mod SceSpZeroConf libSceSysmodule\n");
  fclose(f);
  logf("created default %s (edit it and re-send the payload to change the "
       "auto behaviour)\n", CFG_PATH);
}

int
main(int argc, char **argv) {
  pinfo_t *procs = NULL;
  int nprocs = 0;
  pid_t self = getpid();
  char line[512];
  struct timeval t0, t1;
  int checked_cfg = 0;
  int failures = 0, cmds = 0;

  gettimeofday(&t0, NULL);
  mkdir_p(OUTDIR);
  mkdir_p("/data");
  g_rep = fopen(REPORT_PATH, "w");

  logf("== sprxdump - read-only PS5 process/module dumper ==\n");
  logf("payload pid=%d uid=%d euid=%d fw=0x%08x authid=0x%016llx page=%d\n",
       (int)self, (int)getuid(), (int)geteuid(),
       (unsigned)kernel_get_fw_version(),
       (unsigned long long)kernel_get_ucred_authid(self), getpagesize());
  logf("read-only: sysctl(KERN_PROC_VMMAP) + mdbg_copyout, no ptrace, no "
       "copyin, no target writes\n");
  logf("exec-only .text (prot=0x4) is accepted: a READ-only filter would drop "
       "all code\n");

  if(collect_procs(&procs, &nprocs) != 0) {
    logf("process enumeration failed errno=%d (%s)\n", errno, strerror(errno));
    if(g_rep) fclose(g_rep);
    return 1;
  }
  logf("process table: %d entries\n", nprocs);

  /* argv first; elfldr delivers "?args=a,b,c" as ONE argv entry, so every
   * argv entry is tokenized on commas/whitespace. */
  if(argc > 1) {
    char joined[512];
    size_t o = 0;
    joined[0] = 0;
    for(int i = 1; i < argc && o + 1 < sizeof(joined); i++) {
      o += (size_t)snprintf(joined + o, sizeof(joined) - o, "%s%s",
                            o ? " " : "", argv[i]);
    }
    {
      char buf[512];
      char *tok[MAX_TOK];
      int nt = tokenize(joined, buf, sizeof(buf), tok, MAX_TOK);

      logf("argv: %d entrie(s) -> %d token(s)\n", argc - 1, nt);
      if(nt > 0) {
        cmds++;
        if(run_command(nt, tok, self, procs, nprocs) != 0) {
          failures++;
        }
      }
    }
  } else {
    /* No argv (raw ELF send): drive the run from the config file. */
    FILE *cfg = fopen(CFG_PATH, "r");

    checked_cfg = 1;
    if(!cfg) {
      write_default_cfg("file was missing");
      cfg = fopen(CFG_PATH, "r");
    } else {
      logf("no argv, using %s\n", CFG_PATH);
    }
    if(cfg) {
      while(fgets(line, sizeof(line), cfg)) {
        char buf[512];
        char *tok[MAX_TOK];
        int nt;
        size_t nl = strcspn(line, "\r\n");

        line[nl] = 0;
        nt = tokenize(line, buf, sizeof(buf), tok, MAX_TOK);
        if(nt <= 0) {
          continue;
        }
        logf("cfg> %s\n", line);
        cmds++;
        if(run_command(nt, tok, self, procs, nprocs) != 0) {
          failures++;
        }
      }
      fclose(cfg);
    }
    if(cmds == 0) {
      logf("config file had no command; running built-in default\n");
      cmds++;
      {
        char buf[512];
        char *tok[MAX_TOK];
        int nt = tokenize("list", buf, sizeof(buf), tok, MAX_TOK);
        run_command(nt, tok, self, procs, nprocs);
      }
    }
  }

  gettimeofday(&t1, NULL);
  {
    double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1e6;
    logf("\n== done: %d command(s), %d failure(s), %.2f s ==\n", cmds,
         failures, secs);
  }
  logf("report: %s\n", REPORT_PATH);
  logf("output: %s/*.bin + *.idx (%s)\n", OUTDIR,
       checked_cfg ? "cfg-driven run" : "argv run");

  if(g_rep) {
    fclose(g_rep);
    g_rep = NULL;
  }
  free(procs);
  return failures ? 1 : 0;
}
