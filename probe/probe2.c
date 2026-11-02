/* probe2.c - second fact finder (throwaway): kernel dynlib resolution + cluster shape */
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

static void logf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
  fflush(stdout);
}

typedef struct { uint64_t start, end; int prot, type, resid; char path[128]; } rng_t;

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
count_needle(pid_t pid, uint64_t start, uint64_t end, const char *needle) {
  size_t nl = strlen(needle);
  uint8_t *buf;
  int hits = 0;

  if(!(buf = malloc(CHUNK))) return 0;
  for(uint64_t a = start; a < end;) {
    size_t len = (size_t)((end - a) < CHUNK ? (end - a) : CHUNK);
    size_t step, valid;
    if(mdbg_copyout(pid, (intptr_t)a, buf, len) != 0) break;
    step = (len == CHUNK && a + len < end) ? (CHUNK - (nl - 1)) : len;
    valid = (len == CHUNK && a + len < end) ? step : len;
    for(size_t i = 0; i < valid; i++) {
      if(buf[i] != (uint8_t)needle[0] || i + nl > len) continue;
      if(!memcmp(buf + i, needle, nl)) hits++;
    }
    if(len < CHUNK) break;
    a += step;
  }
  free(buf);
  return hits;
}

static int
count_prologues(pid_t pid, uint64_t start, uint64_t end) {
  uint8_t *buf;
  int n = 0;
  if(!(buf = malloc(CHUNK))) return 0;
  for(uint64_t a = start; a + 4 <= end;) {
    size_t len = (size_t)((end - a) < CHUNK ? (end - a) : CHUNK);
    if(mdbg_copyout(pid, (intptr_t)a, buf, len) != 0) break;
    for(size_t i = 0; i + 4 <= len; i++) {
      if(buf[i] == 0x55 && buf[i+1] == 0x48 && buf[i+2] == 0x89 && buf[i+3] == 0xe5) n++;
    }
    a += len;
  }
  free(buf);
  return n;
}

static void
try_handle(pid_t pid, const char *name) {
  uint32_t h = 0xdeadbeef;
  int rc = kernel_dynlib_handle(pid, name, &h);
  logf("HANDLE(%d,\"%s\") rc=%d errno=%d h=0x%x", (int)pid, name, rc, errno, h);
  if(rc == 0) {
    logf(" base=0x%09lx entry=0x%09lx init=0x%09lx fini=0x%09lx",
         (unsigned long)kernel_dynlib_mapbase_addr(pid, h),
         (unsigned long)kernel_dynlib_entry_addr(pid, h),
         (unsigned long)kernel_dynlib_init_addr(pid, h),
         (unsigned long)kernel_dynlib_fini_addr(pid, h));
  }
  logf("\n");
}

int
main(int argc, char **argv) {
  rng_t *r = NULL;
  int nr = 0;

  logf("PROBE2 start pid=%d euid=%d\n", (int)getpid(), (int)geteuid());
  logf("ARGC %d\n", argc);
  for(int i = 0; i < argc; i++) logf("ARGV[%d] \"%s\"\n", i, argv[i] ? argv[i] : "(null)");

  try_handle(67, "libSceSysmodule");
  try_handle(67, "libSceSysmodule.sprx");
  try_handle(67, "SceSysmodule");
  try_handle(67, "libSceNpUtility");
  try_handle(67, "libSceLibcInternal");
  try_handle(58, "libSceShellCore");

  logf("-- mapbase by index, pid 67 --\n");
  for(uint32_t i = 0; i < 10; i++) {
    logf("  idx=%u base=0x%09lx entry=0x%09lx init=0x%09lx\n", i,
         (unsigned long)kernel_dynlib_mapbase_addr(67, i),
         (unsigned long)kernel_dynlib_entry_addr(67, i),
         (unsigned long)kernel_dynlib_init_addr(67, i));
  }

  if(vmmap(67, &r, &nr) == 0) {
    logf("-- all ranges pid 67 (n=%d) --\n", nr);
    for(int k = 0; k < nr; k++) {
      logf("  [%d] 0x%09llx-0x%09llx prot=%x type=%d resid=%-3d sz=%-7llu %s\n",
           k, (unsigned long long)r[k].start, (unsigned long long)r[k].end,
           r[k].prot, r[k].type, r[k].resid,
           (unsigned long long)(r[k].end - r[k].start),
           r[k].path[0] ? r[k].path : "-");
    }

    uint64_t s = 0x833b74000ULL, e = 0x833ba0000ULL;
    logf("-- cluster fingerprint 0x%llx-0x%llx --\n",
         (unsigned long long)s, (unsigned long long)e);
    logf("  prologues=%d\n", count_prologues(67, s, e));
    logf("  \"libSceSysmodule\"       = %d\n", count_needle(67, s, e, "libSceSysmodule"));
    logf("  \"SceSysmodule\"          = %d\n", count_needle(67, s, e, "SceSysmodule"));
    logf("  \"sceSysmodule\"          = %d\n", count_needle(67, s, e, "sceSysmodule"));
    logf("  \"sprx\"                  = %d\n", count_needle(67, s, e, "sprx"));
    logf("  \"/system/common/lib\"    = %d\n", count_needle(67, s, e, "/system/common/lib"));
    free(r);
  } else {
    logf("vmmap(67) failed errno=%d\n", errno);
  }

  logf("PROBE2 done\n");
  return 0;
}
