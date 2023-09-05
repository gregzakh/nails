/*
 * Detecting if the current process is running under a debugger.
 */
#include <intrin.h>
#include <cstdio>
#include <cstdint>

const auto DEBUGGED = 0xABABABAB;
#ifdef _M_X64
  const auto Environment = 0x80;
  const auto EnvironmentSize = 0x3F0;
#else
  const auto Environment = 0x48;
  const auto EnvironmentSize = 0x290;
#endif

bool CheckHeapBlockTail(void) {
  void *env = nullptr;
  size_t sz{};
  // RTL_USER_PROCESS_PARAMETERS
#ifdef _M_X64
  env = *(void **)((uint8_t *)__readgsqword(0x60) + 0x20);
#else
  env = *(void **)((uint8_t *)__readfsdword(0x30) + 0x10);
#endif
  // RTL_USER_PROCESS_PARAMETERS->EnvironmentSize
  sz = *(size_t *)((uint8_t *)env + EnvironmentSize);
  // RTL_USER_PROCESS_PARAMETERS->Environment
  env = *(void **)((uint8_t *)env + Environment);
  // skip Environment block (with null terminator) and get value
  return DEBUGGED == *(uint32_t *)((uint8_t *)env + sz + sizeof(wchar_t));
}

int main(void) {
  printf("Process is debugged: %s\n", CheckHeapBlockTail() ? "true" : "false");
  return 0;
}
