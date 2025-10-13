#include "kernel32.h"
#include "util.h"
#include "scopeguard.hpp"
#include "fs.h"
#include <windows.h>
#include <tlhelp32.h>
#include <UserEnv.h>
#include <AclAPI.h>
#include <future>
#include <unordered_map>

const char* MachineToString(USHORT m)
{
  switch (m) {
    case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
    case IMAGE_FILE_MACHINE_AMD64: return "x64";
    case IMAGE_FILE_MACHINE_I386:  return "x86";
    case IMAGE_FILE_MACHINE_ARM:   return "ARM";
    case 0:                        return "Unknown"; // per docs, 0 if the function fails to retrieve
    default:                       return "Unknown";
  }
}

using IsWow64Process2_t = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);

Napi::Value GetNativeArchWrap(const Napi::CallbackInfo& info) {
  try {
    if (info.Length() != 0) {
      throw std::exception("Expected 0 parameters");
    }

    Napi::Env env = info.Env();

    USHORT processMachine = 0;
    USHORT nativeMachine  = 0;
    bool usedFallback = false;

    HMODULE hKernel32 = ::GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
      auto pIsWow64Process2 = reinterpret_cast<IsWow64Process2_t>(
          ::GetProcAddress(hKernel32, "IsWow64Process2"));

      if (pIsWow64Process2) {
        if (!pIsWow64Process2(::GetCurrentProcess(), &processMachine, &nativeMachine)) {
          // If the call fails, fall back below.
          processMachine = 0;
          nativeMachine = 0;
        }
      }
    }

    if (nativeMachine == 0) {
      // Fallback to GetNativeSystemInfo (older Windows that lacks IsWow64Process2)
      SYSTEM_INFO si{};
      ::GetNativeSystemInfo(&si);
      usedFallback = true;

      // Convert SYSTEM_INFO arch -> our return fields
      // We can’t fill processMachine (emulation) without IsWow64Process2,
      // so leave it 0/"Unknown".
      switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_ARM64: nativeMachine = IMAGE_FILE_MACHINE_ARM64; break;
        case PROCESSOR_ARCHITECTURE_AMD64: nativeMachine = IMAGE_FILE_MACHINE_AMD64; break;
        case PROCESSOR_ARCHITECTURE_ARM:   nativeMachine = IMAGE_FILE_MACHINE_ARM; break;
        case PROCESSOR_ARCHITECTURE_INTEL: nativeMachine = IMAGE_FILE_MACHINE_I386; break;
        default: nativeMachine = 0; break;
      }
    }

    Napi::Object out = Napi::Object::New(env);
    out.Set("nativeMachineCode", Napi::Number::New(env, nativeMachine));
    out.Set("nativeArch", Napi::String::New(env, MachineToString(nativeMachine)));
    out.Set("usedFallback", Napi::Boolean::New(env, usedFallback));
    return out;
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

namespace Kernel32 {
  void Init(Napi::Env env, Napi::Object exports) {
    exports.Set("GetNativeArch", Napi::Function::New(env, GetNativeArchWrap));
  }
}
