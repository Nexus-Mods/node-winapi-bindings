#pragma once

#include <napi.h>
#include <windows.h>

namespace FS {
  void Init(Napi::Env env, Napi::Object exports);
}

DWORD mapPermissions(const Napi::Array& input);
