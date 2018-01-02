#include "ps4.h"

#include <assert.h>

#define DEBUG_SOCKET
#include "defines.h"

void hexdump(void* input, int length, int relative)
{
  uint8_t* buffer = (uint8_t*)input;
  int i;

  for (i = 0; i < length; i++)
  {
    if ((i % 16) == 0)
    {
      printfsocket("%llx :", !relative ? (uint64_t)&buffer[i] : (uint64_t)i);
    }

    printfsocket(" %02x", buffer[i]);

    if (i > 0 && (i % 16) == 15)
    {
      printfsocket("\n");
    }
  }

  if ((i % 16) != 0)
  {
    printfsocket("\n");
  }

  //printfsocket("\n");
}

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

int install_patches()
{
  uint64_t cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);

  uint8_t* kernel_base = (uint8_t*)(__readmsr(0xC0000082) - 0x30EB30);

  // change path ID for /hostapp/
  *(uint32_t*)(kernel_base + 0x36077A + 1) = 6;

  // allow any process to open /dev/authmgr
  *(uint8_t*)(kernel_base + 0x612EB0) = 0x31;
  *(uint8_t*)(kernel_base + 0x612EB1) = 0xC0;
  *(uint8_t*)(kernel_base + 0x612EB2) = 0xC3;

  // allow any process to sceSblAuthMgrDeleteEEkc
  *(uint8_t*)(kernel_base + 0x612F23) = 0x90;
  *(uint8_t*)(kernel_base + 0x612F24) = 0x90;
  *(uint8_t*)(kernel_base + 0x612F25) = 0x90;
  *(uint8_t*)(kernel_base + 0x612F26) = 0x90;
  *(uint8_t*)(kernel_base + 0x612F27) = 0x90;
  *(uint8_t*)(kernel_base + 0x612F28) = 0x90;

  // allow any process to sceSblAuthMgrAddEEkc3
  *(uint8_t*)(kernel_base + 0x612F7F) = 0x90;
  *(uint8_t*)(kernel_base + 0x612F80) = 0x90;
  *(uint8_t*)(kernel_base + 0x612F81) = 0x90;
  *(uint8_t*)(kernel_base + 0x612F82) = 0x90;
  *(uint8_t*)(kernel_base + 0x612F83) = 0x90;
  *(uint8_t*)(kernel_base + 0x612F84) = 0x90;

  // allow any process to open /dev/npdrm
  *(uint8_t*)(kernel_base + 0x6204F0) = 0x31;
  *(uint8_t*)(kernel_base + 0x6204F1) = 0xC0;
  *(uint8_t*)(kernel_base + 0x6204F2) = 0xC3;

  // allow any process to close /dev/npdrm
  *(uint8_t*)(kernel_base + 0x620510) = 0x31;
  *(uint8_t*)(kernel_base + 0x620511) = 0xC0;
  *(uint8_t*)(kernel_base + 0x620512) = 0xC3;

  // allow any process to ioctl /dev/npdrm
  *(uint8_t*)(kernel_base + 0x62056D) = 0x90;
  *(uint8_t*)(kernel_base + 0x62056E) = 0x90;
  *(uint8_t*)(kernel_base + 0x62056F) = 0x90;
  *(uint8_t*)(kernel_base + 0x620570) = 0x90;
  *(uint8_t*)(kernel_base + 0x620571) = 0x90;
  *(uint8_t*)(kernel_base + 0x620572) = 0x90;

  writeCr0(cr0);
  return 0;
}

typedef struct _LaunchAppParam
{
  uint32_t size;
  int32_t user_id;
  int32_t app_attr;
  int32_t enable_crash_report;
  uint64_t check_flag;
}
LaunchAppParam;
int (*sceSystemServiceLaunchApp)(const char* titleId, const char* argv[], LaunchAppParam* param);

int read_rif(const char* path, void* buffer)
{
  FILE* handle = fopen(path, "rb");
  if (handle == NULL)
  {
    return -1;
  }
  fseek(handle, 0x400, SEEK_SET);
  fread(buffer, 1, 0x400, handle);
  fclose(handle);
  return 0;
}

typedef struct _rif_info
{
  uint32_t version;
  uint32_t unknown_4; // &rif[0x6]
  uint64_t psn_account_id;
  uint64_t start_timestamp;
  uint64_t end_timestamp;
  uint64_t unknown_20;
  uint32_t type;
  uint32_t unknown_2C; // &rif[0x54]
  uint32_t sku_flag;
  uint32_t unknown_34;
  uint64_t unknown_38;
  uint64_t unknown_40;
  char content_id[48];
  uint8_t secret_key_iv[16];
}
rif_info;

typedef struct _rif_secret
{
  uint8_t content_key_seed[16];
  uint8_t self_key_seed[16];
  uint8_t entitlement_key[16];
}
rif_secret;

int npdrm_decompose_rif(rif_secret* secret, rif_info* info, void* rif)
{
  int fd = open("/dev/npdrm", O_RDWR, 0);
  if (fd < 0)
  {
    return 0x800F0A13;
  }
  struct
  {
    void* secret;
    void* info;
    void* rif;
    int error;
  }
  args;
  memset(&args, 0, sizeof(args));
  args.secret = secret;
  args.info = info;
  args.rif = rif;
  int result = ioctl(fd, 0xC0204E0E, &args);
  close(fd);
  return result ? 0x800F0A05 : args.error;
}

int sceSblAuthMgrAddEEkc3(const char* content_id, void* keys, int field_2C, int a4)
{
  if (!content_id || !keys)
  {
    return 0x800F0B16;
  }
  int fd = open("/dev/authmgr", O_RDWR, 0);
  if (fd < 0)
  {
    return 0x800F0B13;
  }
  struct
  {
    char content_id[36];
    uint8_t keys[32];
    int field_44;
    int field_48;
    int error;
  }
  args;
  memcpy(args.content_id, content_id, sizeof(args.content_id));
  memcpy(args.keys, keys, sizeof(args.keys));
  args.field_44 = field_2C;
  args.field_48 = a4;
  int result = ioctl(fd, 0xC0504104, &args);
  close(fd);
  return result ? 0x800F0B05 : args.error;
}

int sceSblAuthMgrDeleteEEkc(const char* content_id)
{
  if (!content_id)
  {
    return 0x800F0B16;
  }
  int fd = open("/dev/authmgr", O_RDWR, 0);
  if (fd < 0)
  {
    return 0x800F0B13;
  }
  struct
  {
    char content_id[36];
    uint8_t unknown[32];
    int error;
  }
  args;
  memcpy(args.content_id, content_id, sizeof(args.content_id));
  int result = ioctl(fd, 0xC0484102, &args);
  close(fd);
  return result ? 0x800F0B05 : args.error;
}

uint8_t rif[0x400];

void do_launch()
{
  int result;

  kexec(&install_patches, NULL);

  int systemServiceHandle;
  if (loadModule("libSceSystemService.sprx", &systemServiceHandle))
  {
    printfsocket("Failed to load: %d\n", errno);
    return;
  }

  if (getFunctionAddressByName(systemServiceHandle, "sceSystemServiceLaunchApp", &sceSystemServiceLaunchApp))
  {
    printfsocket("Failed to get sceSystemServiceLaunchApp: %d\n", errno);
    return;
  }

  read_rif("/user/license/freeIP9100-CUSA00001_00.rif", rif);

  rif_secret rif_secret;
  rif_info rif_info;
  memset(&rif_secret, 0xCC, sizeof(rif_secret));
  memset(&rif_info, 0xCC, sizeof(rif_info));
  result = npdrm_decompose_rif(&rif_secret, &rif_info, rif);
  printfsocket("npdrm_parse_rif = %x\n", result);
  if (result)
  {
    return;
  }

  hexdump(&rif_secret, sizeof(rif_secret), 1);
  //hexdump(&rif_info, sizeof(rif_info), 1);

  struct
  {
    uint8_t content_key_seed[16];
    uint8_t self_key_seed[16];
  }
  keys;
  memcpy(keys.content_key_seed, rif_secret.content_key_seed, 16);
  memcpy(keys.self_key_seed, rif_secret.self_key_seed, 16);

  // just in case, delete any possible existing EEkc
  sceSblAuthMgrDeleteEEkc(rif_info.content_id);

  // activate RIF keys
  result = sceSblAuthMgrAddEEkc3(rif_info.content_id, &keys, 1, 0);
  printfsocket("sceSblAuthMgrAddEEkc3 = %x\n", result);
  if (result && result != 0x800f0b11)
  {
    return;
  }

  const char* argv[] =
  {
    "/hostapp/app/eboot.bin",
    NULL,
  };

  LaunchAppParam param;
  param.size = sizeof(LaunchAppParam);
  param.user_id = -1;
  param.app_attr = 0;
  param.enable_crash_report = 0;
  param.check_flag = 0;
  result = sceSystemServiceLaunchApp("NPXS29999", argv, &param);
  if (result)
  {
    printfsocket("Launch result: %x\n", result);
  }

  // Launch result: 80aa001a :-(
}
