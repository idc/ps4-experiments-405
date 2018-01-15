#include <assert.h>

#include "ps4.h"

uint64_t __readmsr(unsigned long __register)
{
  unsigned long __edx;
  unsigned long __eax;
  __asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
  return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

#define X86_CR0_WP (1 << 16)

static inline __attribute__((always_inline)) uint64_t readCr0(void)
{
  uint64_t cr0;
  __asm__ volatile ("movq %0, %%cr0" : "=r" (cr0) : : "memory");
  return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0)
{
  __asm__ volatile("movq %%cr0, %0" : : "r" (cr0) : "memory");
}

int call_fuse_loader(void* td, void* args)
{
  uint8_t* kernel_base = (uint8_t*)(__readmsr(0xC0000082) - 0x30EB30);

  uint64_t cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);
  // skip devkit/testkit/dipsw check in fuse_loader
  kernel_base[0x47928E] = 0xEB;
  kernel_base[0x47928F] = 0x1B;
  // skip sceSblACMgrIsSyscoreProcess check in fuse_vfsop_mount
  kernel_base[0x477C9D] = 0xEB;
  kernel_base[0x477C9E] = 0x04;
  // skip sceSblACMgrIsMinisyscore/unknown check in fuse_vfsop_unmount
  kernel_base[0x478421] = 0xEB;
  kernel_base[0x478422] = 0x04;
  // skip sceSblACMgrIsSystemUcred check in fuse_vfsop_statfs
  kernel_base[0x4787B2] = 0xEB;
  kernel_base[0x4787B3] = 0x04;
  writeCr0(cr0);

  // initialize FUSEFS module
  int (*fuse_loader)(void* m, int op, void* arg);
  *((void**)&fuse_loader) = &kernel_base[0x479260];
  return fuse_loader(NULL, 0, NULL);
}

int _main(void)
{
  initKernel();
  int result = kexec(&call_fuse_loader, NULL);
  return !result ? 0 : errno;
}
