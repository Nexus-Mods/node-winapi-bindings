#pragma once

#include <napi.h>

namespace Registry {
  void Init(Napi::Env env, Napi::Object exports);
}