#include <napi.h>
#include "scopeguard.hpp"
#include "string_cast.h"
#include "util.h"
#ifdef _WIN32
#include <windows.h>
#pragma comment( lib, "advapi32.lib" )
#endif


Napi::Value InitiateSystemShutdownWrap(const Napi::CallbackInfo &info)
{
  try {
    if (info.Length() != 4) {
      throw Napi::Error::New(info.Env(), "Expected four parameters (message, timeout, askToClose, reboot)");
    }

    #ifdef _WIN32
    std::string msg = info[0].ToString().Utf8Value();
    int timeout = info[1].ToNumber();
    bool askToClose = info[2].ToBoolean();
    bool reboot = info[3].ToBoolean();
    HANDLE processToken;

    if (!::OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken)) {
      throw WinApiException(::GetLastError(), "OpenProcessToken");
    }

    TOKEN_PRIVILEGES privileges;
    LookupPrivilegeValue(nullptr, SE_SHUTDOWN_NAME, &privileges.Privileges[0].Luid);

    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ::AdjustTokenPrivileges(processToken, false, &privileges, 0, (PTOKEN_PRIVILEGES)nullptr, 0);

    // AdjustTokenPrivileges may return "true" even if not all privileges were applied
    if (GetLastError() != ERROR_SUCCESS) {
      throw WinApiException(::GetLastError(), "AdjustTokenPrivileges");
    }

    ScopeGuard restorePrivileges([&] () {
      privileges.Privileges[0].Attributes = 0;
      ::AdjustTokenPrivileges(processToken, false, &privileges, 0, (PTOKEN_PRIVILEGES)nullptr, 0);
    });

    std::wstring msg16 = toWC(msg.c_str(), CodePage::UTF8, msg.length());
    if (!::InitiateSystemShutdown(nullptr, &msg16[0], timeout, askToClose, reboot)) {
      if (::GetLastError() == ERROR_SHUTDOWN_IS_SCHEDULED) {
        return Napi::Boolean::New(info.Env(), false);
      }
      throw WinApiException(::GetLastError(), "InitiateSystemShutdown");
    }

    return Napi::Boolean::New(info.Env(), true);
    #else
    return info.Env().Undefined();
    #endif
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value AbortSystemShutdownWrap(const Napi::CallbackInfo &info)
{
  try {
    #ifdef _WIN32
    HANDLE processToken;

    BOOL fResult;

    if (!::OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken)) {
      throw WinApiException(::GetLastError(), "OpenProcessToken");
    }

    TOKEN_PRIVILEGES privileges;
    LookupPrivilegeValue(nullptr, SE_SHUTDOWN_NAME, &privileges.Privileges[0].Luid);

    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ::AdjustTokenPrivileges(processToken, false, &privileges, 0, (PTOKEN_PRIVILEGES)nullptr, 0);

    // AdjustTokenPrivileges may return "true" even if not all privileges were applied
    if (GetLastError() != ERROR_SUCCESS) {
      throw WinApiException(::GetLastError(), "AdjustTokenPrivileges");
    }

    ScopeGuard restorePrivileges([&] () {
      privileges.Privileges[0].Attributes = 0;
      ::AdjustTokenPrivileges(processToken, false, &privileges, 0, (PTOKEN_PRIVILEGES)nullptr, 0);
    });

    if (!::AbortSystemShutdown(nullptr)) {
      if (::GetLastError() == ERROR_NO_SHUTDOWN_IN_PROGRESS) {
        return Napi::Boolean::New(info.Env(), false);
      }
      throw WinApiException(::GetLastError(), "AbortSystemShutdown");
    }
    return Napi::Boolean::New(info.Env(), true);
    #else
    return Napi::Boolean::New(info.Env(), false);
    #endif
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

namespace System {
  void Init(Napi::Env env, Napi::Object exports) {
    exports.Set("InitiateSystemShutdown", Napi::Function::New(env, InitiateSystemShutdownWrap));
    exports.Set("AbortSystemShutdown", Napi::Function::New(env, AbortSystemShutdownWrap));
  }
}
