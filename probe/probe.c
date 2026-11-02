/* probe.c - one-shot fact finder for sprxdump (throwaway, not shipped)
 *
 * Answers, in one console round trip:
 *   1. does elfldr hand us argv? (argc/argv as seen by main)
 *   2. what does pid 67's module cluster look like in vmmap (prot/type/path)
 *   3. is there ELF magic at any range start in pid 67 / 58?
 *   4. where does "libSceSysmodule" live and which range holds it?
 *   5. first bytes at the start of the cluster (0xCC padding check)
 */
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#define CHUNK (32 * 1024)

static void
logf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
  fflush(stdout);
}

static void
hex(const uint8_t *b, size_t n) {
  for(size_t i = 0; i < n; i++) logf("%02x", b[i]);
}

typedef struct rng {
  uint64_t start, end;
  int prot, type, resid;
  char path[128];
} rng_t;

static int
vmmap(pid_t pid, rng_t **out, int *out_n) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, (int)pid};
  size_t vsz = 0;
  uint8_t *vm;
  rng_t *r;
  int n = 0;

  if(sysctl(mib, 4, NULL, &vsz, NULL, 0) < 0) return -1;
  if(!(vm = malloc(vsz))) return -1;
  if(sysctl(mib, 4, vm, &vsz, NULL, 0) < 0) { free(vm); return -1; }
  if(!(r = calloc(vsz / 16 + 8, sizeof(*r)))) { free(vm); return -1; }

  for(uint8_t *p = vm; p < vm + vsz;) {
    struct kinfo_vmentry *ve = (struct kinfo_vmentry *)p;
    int ss = ve->kve_structsize;
    if(ss <= 0 || p + ss > vm + vsz) break;
    p += ss;
    if(ve->kve_end <= ve->kve_start) continue;
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

static int
scan_name(pid_t pid, const rng_t *r, int nr, const char *needle, int maxhits) {
  size_t nl = strlen(needle);
  uint8_t *buf = malloc(CHUNK);
  int hits = 0;

  if(!buf) return 0;
  for(int k = 0; k < nr && hits < maxhits; k++) {
    if(!(r[k].prot & (KVME_PROT_READ | KVME_PROT_EXEC))) continue;
    if(r[k].start < 0x10000) continue;
    if(r[k].type == KVME_TYPE_DEVICE || r[k].type == KVME_TYPE_MGTDEVICE) continue;
    if(!strncmp(r[k].path, "/dev/", 5)) continue;
    uint64_t cap = r[k].end - r[k].start;
    if(cap > (128ULL << 20)) cap = 128ULL << 20;
    for(uint64_t a = r[k].start; a < r[k].start + cap;) {
      size_t len = (size_t)((r[k].start + cap - a) < CHUNK ? (r[k].start + cap - a) : CHUNK);
      size_t step, valid;
      if(mdbg_copyout(pid, (intptr_t)a, buf, len) != 0) break;
      step = (len == CHUNK && a + len < r[k].start + cap) ? (CHUNK - (nl - 1)) : len;
      valid = (len == CHUNK && a + len < r[k].start + cap) ? step : len;
      for(size_t i = 0; i < valid; i++) {
        if(buf[i] != (uint8_t)needle[0]) continue;
        if(i + nl > len) continue;
        if(!memcmp(buf + i, needle, nl)) {
          logf("HIT %s va=0x%09llx range=[%d] 0x%09llx-0x%09llx prot=%x type=%d\n",
               needle, (unsigned long long)(a + i), k,
               (unsigned long long)r[k].start, (unsigned long long)r[k].end,
               r[k].prot, r[k].type);
          if(++hits >= maxhits) { free(buf); return hits; }
        }
      }
      if(len < CHUNK) break;
      a += step;
    }
  }
  free(buf);
  return hits;
}

int
main(int argc, char **argv) {
  rng_t *r = NULL;
  int nr = 0;
  pid_t me = getpid();

  logf("PROBE start pid=%d uid=%d euid=%d fw=0x%08x authid=0x%016llx\n",
       (int)me, (int)getuid(), (int)geteuid(),
       (unsigned)kernel_get_fw_version(),
       (unsigned long long)kernel_get_ucred_authid(me));
  logf("ARGC %d\n", argc);
  for(int i = 0; i < argc; i++) logf("ARGV[%d] \"%s\"\n", i, argv[i] ? argv[i] : "(null)");

  /* 1. vmmap window around the known libSceSysmodule cluster in pid 67 */
  if(vmmap(67, &r, &nr) == 0) {
    uint64_t lo = 0x833b00000ULL, hi = 0x833bc0000ULL;
    logf("VM67 total=%d window 0x%llx-0x%llx\n", nr,
         (unsigned long long)lo, (unsigned long long)hi);
    for(int k = 0; k < nr; k++) {
      uint8_t b[16];
      int rd = 0;
      if(r[k].end < lo || r[k].start > hi) continue;
      memset(b, 0, sizeof(b));
      rd = mdbg_copyout(67, (intptr_t)r[k].start, b, sizeof(b)) == 0;
      logf("  [%d] 0x%09llx-0x%09llx prot=%x type=%d resid=%d rd=%d head=",
           k, (unsigned long long)r[k].start, (unsigned long long)r[k].end,
           r[k].prot, r[k].type, r[k].resid, rd);
      if(rd) hex(b, 16);
      logf(" path=%s\n", r[k].path[0] ? r[k].path : "-");
    }

    /* 2. ELF magic at range starts across the whole process */
    int nmagic = 0, nread = 0;
    for(int k = 0; k < nr; k++) {
      uint32_t m = 0;
      if(r[k].start < 0x10000 || r[k].end <= r[k].start) continue;
      if(!(r[k].prot & (KVME_PROT_READ | KVME_PROT_EXEC))) continue;
      if(r[k].type == KVME_TYPE_DEVICE || r[k].type == KVME_TYPE_MGTDEVICE) continue;
      nread++;
      if(mdbg_copyout(67, (intptr_t)r[k].start, &m, 4) != 0) continue;
      if(m == 0x464c457f) {
        uint8_t h[64];
        nmagic++;
        if(nmagic <= 8 && mdbg_copyout(67, (intptr_t)r[k].start, h, sizeof(h)) == 0) {
          logf("ELF67 [%d] 0x%09llx-0x%09llx prot=%x type=%d head=",
               k, (unsigned long long)r[k].start, (unsigned long long)r[k].end,
               r[k].prot, r[k].type);
          hex(h, 24);
          logf("\n");
        }
      }
    }
    logf("ELF67 ranges_read=%d magic=%d\n", nread, nmagic);

    /* 3. module name fingerprint */
    logf("SCAN67 libSceSysmodule\n");
    scan_name(67, r, nr, "libSceSysmodule", 6);
    free(r);
    r = NULL;
  } else {
    logf("vmmap(67) failed errno=%d\n", errno);
  }

  /* 4. same ELF-magic census for SceShellCore (big process, sanity only) */
  {
    rng_t *s = NULL;
    int ns = 0;
    if(vmmap(58, &s, &ns) == 0) {
      int nmagic = 0;
      for(int k = 0; k < ns; k++) {
        uint32_t m = 0;
        if(s[k].start < 0x10000 || s[k].end <= s[k].start) continue;
        if(!(s[k].prot & (KVME_PROT_READ | KVME_PROT_EXEC))) continue;
        if(s[k].type == KVME_TYPE_DEVICE || s[k].type == KVME_TYPE_MGTDEVICE) continue;
        if(mdbg_copyout(58, (intptr_t)s[k].start, &m, 4) != 0) continue;
        if(m == 0x464c457f) nmagic++;
      }
      logf("ELF58 ranges=%d magic=%d\n", ns, nmagic);
      free(s);
    } else {
      logf("vmmap(58) failed errno=%d\n", errno);
    }
  }

  logf("PROBE done\n");
  return 0;
}
