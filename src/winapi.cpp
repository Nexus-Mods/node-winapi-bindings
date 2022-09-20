#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <comdef.h>
#endif
#include <napi.h>
#include "fs.h"
#include "ini.h"
#include "tasks.h"
#include "shell.h"
#include "convenience.h"
#include "registry.h"
#include "processes.h"
#include "permissions.h"
#include "system.h"
#ifdef _WIN32
#pragma comment(lib, "Version.lib")
#endif

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  #ifdef _WIN32 // initialize the COM library
  HRESULT hr = ::CoInitialize(nullptr);
  napi_add_env_cleanup_hook(env, [](void*) {
    ::CoUninitialize();
  }, nullptr);
  #endif
  Registry::Init(env, exports);
  Tasks::Init(env, exports);
  WinShell::Init(env, exports);
  Processes::Init(env, exports);
  INI::Init(env, exports);
  FS::Init(env, exports);
  Convenience::Init(env, exports);
  Permissions::Init(env, exports);
  System::Init(env, exports);

  return exports;
}

NODE_API_MODULE(winapi, Init)
