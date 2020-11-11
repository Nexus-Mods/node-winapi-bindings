#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <comdef.h>
#include <napi.h>
#include "fs.h"
#include "ini.h"
#include "tasks.h"
#include "shell.h"
#include "convenience.h"
#include "registry.h"
#include "processes.h"

#pragma comment(lib, "Version.lib")

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  HRESULT hr = ::CoInitialize(nullptr);
  napi_add_env_cleanup_hook(env, [](void*) {
    ::CoUninitialize();
  }, nullptr);

  Registry::Init(env, exports);
  Tasks::Init(env, exports);
  WinShell::Init(env, exports);
  Processes::Init(env, exports);
  INI::Init(env, exports);
  FS::Init(env, exports);
  Convenience::Init(env, exports);

  return exports;
}

NODE_API_MODULE(winapi, Init)
