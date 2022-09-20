#pragma once

#include <napi.h>
#ifdef _WIN32
#include <windows.h>
#endif

namespace FS {
  void Init(Napi::Env env, Napi::Object exports);
}

#ifdef _WIN32
DWORD mapPermissions(const Napi::Array& input);
#endif
