#pragma once

#include <napi.h>

namespace Kernel32 {
  void Init(Napi::Env env, Napi::Object exports);
}