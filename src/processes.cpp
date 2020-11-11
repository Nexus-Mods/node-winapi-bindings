#include "processes.h"
#include "util.h"
#include "scopeguard.hpp"
#include <windows.h>
#include <tlhelp32.h>

typedef struct {
  DWORD pid;
  HWND hwnd;
} WINDOWPROCESSINFO;

Napi::Object convert(const Napi::Env &env, const TOKEN_ELEVATION &input) {
  Napi::Object result = Napi::Object::New(env);

  result.Set("isElevated", input.TokenIsElevated);

  return result;
}

template <typename StructT> Napi::Object convertToken(const Napi::Env &env, HANDLE process,  TOKEN_INFORMATION_CLASS tokenClass) {
  StructT token;
  DWORD size;
  if (!GetTokenInformation(process, tokenClass, &token, sizeof(StructT), &size)) {
    throw ::GetLastError();
  }

  return convert(env, token);
}

Napi::Value GetModuleListWrap(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();
  auto convertME = [&env](const MODULEENTRY32W &mod) -> Napi::Object {
    Napi::Object item = Napi::Object::New(env);
    item.Set("baseAddr", Napi::Number::New(env, reinterpret_cast<uint64_t>(mod.modBaseAddr)));
    item.Set("baseSize", Napi::Number::New(env, mod.modBaseSize));
    item.Set("module", toMB(mod.szModule, CodePage::UTF8, wcslen(mod.szExePath)));
    item.Set("exePath", toMB(mod.szExePath, CodePage::UTF8, wcslen(mod.szExePath)));
    return item;
  };

  try {
    if (info.Length() != 1) {
      throw std::exception("Expected 1 parameter (process id)");
    }

    Napi::Array modules = Napi::Array::New(info.Env());

    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, info[0].ToNumber().Uint32Value());
    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);
    int idx = 0;
    bool more = ::Module32FirstW(snap, &me32);
    while (more) {
      modules.Set(idx++, convertME(me32));
      more = ::Module32NextW(snap, &me32);
    }

    return modules;
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetProcessToken(const Napi::CallbackInfo &info) {
  try {
    if ((info.Length() < 1) || (info.Length() > 2)) {
      throw std::exception("Expected 1 or 2 parameter(s) (type, pid?)");
    }

    std::string tokenType = info[0].ToString().Utf8Value();

    HANDLE processHandle;
    if (info[1].IsUndefined()) {
      processHandle = ::GetCurrentProcess();
    }
    else {
      processHandle = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, info[1].ToNumber().Uint32Value());
    }

    ScopeGuard onExit([&]() { ::CloseHandle(processHandle); });

    HANDLE token;
    if (!::OpenProcessToken(processHandle, TOKEN_QUERY, &token)) {
      return ThrowWinApiException(info.Env(), ::GetLastError(), "OpenProcessToken");
    }

    try {
      if (tokenType == "elevation") {
        return convertToken<TOKEN_ELEVATION>(info.Env(), token, TokenElevation);
      }
      else {
        throw std::runtime_error(std::string("Unsupported token type \"" + tokenType + "\""));
      }
    }
    catch (DWORD code) {
      throw WinApiException(code, "GetTokenInformation");
    }
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetProcessListWrap(const Napi::CallbackInfo &info) {
  Napi::Env env = info.Env();

  auto convertPE = [&env](const PROCESSENTRY32W &process) -> Napi::Object {
    Napi::Object item = Napi::Object::New(env);
    item.Set("numThreads", Napi::Number::New(env, process.cntThreads));
    item.Set("processID", Napi::Number::New(env, process.th32ProcessID));
    item.Set("parentProcessID", Napi::Number::New(env, process.th32ParentProcessID));
    item.Set("priClassBase", Napi::Number::New(env, process.pcPriClassBase));
    item.Set("exeFile", toMB(process.szExeFile, CodePage::UTF8, wcslen(process.szExeFile)));
    return item;
  };

  try {
    Napi::Array result = Napi::Array::New(env);
    int idx = 0;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    ScopeGuard onExit([&]() { ::CloseHandle(snap); });
    PROCESSENTRY32W pe32;

    if (snap != INVALID_HANDLE_VALUE) {
      pe32.dwSize = sizeof(PROCESSENTRY32W);
      bool more = ::Process32FirstW(snap, &pe32);
      while (more) {
        result.Set(idx++, convertPE(pe32));
        more = ::Process32NextW(snap, &pe32);
      }
    }

    return result;
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetProcessWindowListWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw std::exception("Expected 1 parameter (the process id)");
    }

    DWORD pid = info[0].ToNumber().Uint32Value();

    Napi::Array res = Napi::Array::New(info.Env());
    uint32_t resIdx = 0;

    HWND windowIter = nullptr;
    while (true) {
      // FindWindowEx, in contrast to EnumWindows, also lists metro-style windows.
      // Unfortunately FindWindowEx is not technically safe since the window list can change asynchronously but
      // even the windows-published ProcessExplorer uses it this way so - pffft.
      windowIter = FindWindowEx(nullptr, windowIter, nullptr, nullptr);
      if (windowIter == nullptr) {
        break;
      }
      // ignore all non-top-level windows
      if (GetWindow(windowIter, GW_OWNER) != 0) {
        continue;
      }

      // ignore windows of other processes
      DWORD windowProcess = 0;
      GetWindowThreadProcessId(windowIter, &windowProcess);
      if (windowProcess != pid) {
        continue;
      }

      WINDOWINFO winInfo;
      GetWindowInfo(windowIter, &winInfo);

      uint64_t winId = reinterpret_cast<uint64_t>(windowIter);
      if (((winInfo.dwStyle & WS_CAPTION) != 0) && ((winInfo.dwStyle & WS_CHILD) == 0)) {
        res.Set(resIdx++, Napi::Number::New(info.Env(), winId));
      }
    }

    return res;
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value SetForegroundWinWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw std::exception("Expected 1 parameter (window id)");
    }

    uint64_t winId = info[0].ToNumber().Uint32Value();

    HWND hwnd = reinterpret_cast<HWND>(winId);

    if (::IsIconic(hwnd)) {
      ::ShowWindow(hwnd, 9);
    }

    return Napi::Boolean::New(info.Env(), ::SetForegroundWindow(hwnd));
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value SetProcessPreferredUILanguagesWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw std::exception("Expected 1 parameter (the list of language codes, in the format \"en-US\")");
    }

    Napi::Array languages = info[0].As<Napi::Array>();

    std::vector<wchar_t> buffer;
    size_t offset = 0;

    ULONG count = languages.Length();

    for (ULONG i = 0; i < count; ++i) {
      const std::wstring langU16 = toWC(languages.Get(i));
      buffer.resize(offset + langU16.length() + 2);
      wcsncpy(&buffer[offset], langU16.c_str(), langU16.length() + 1);
      offset += langU16.length() + 1;
    }

    buffer[offset] = '\0';

    if (!SetProcessPreferredUILanguages(MUI_LANGUAGE_NAME, &buffer[0], &count)) {
      throw WinApiException(::GetLastError(), "SetProcessPreferredUILanguages");
    }

    return info.Env().Undefined();
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetPreferredLanguage(const Napi::CallbackInfo &info,
                          BOOL (*func)(DWORD, PULONG, PZZWSTR, PULONG),
                          const char *funcName) {
  try {
    ULONG numLanguages = 0;
    std::vector<wchar_t> buffer;
    ULONG bufferSize = 0;
    if (!func(MUI_LANGUAGE_NAME, &numLanguages, nullptr, &bufferSize)) {
      throw WinApiException(::GetLastError(), funcName);
    }

    buffer.resize(bufferSize);

    if (!func(MUI_LANGUAGE_NAME, &numLanguages, &buffer[0], &bufferSize)) {
      throw WinApiException(::GetLastError(), funcName);
    }

    Napi::Object result = Napi::Object::New(info.Env());

    wchar_t *buf = &buffer[0];

    for (ULONG i = 0; i < numLanguages; ++i) {
      size_t len = wcslen(buf);
      result.Set(i, Napi::String::New(info.Env(), toMB(buf, CodePage::UTF8, len).c_str()));
      buf += len + 1;
    }

    return result;
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetUserPreferredUILanguagesWrap(const Napi::CallbackInfo &info) {
  return GetPreferredLanguage(info, &GetUserPreferredUILanguages, "GetUserPreferredUILanguages");
}

Napi::Value GetSystemPreferredUILanguagesWrap(const Napi::CallbackInfo &info) {
  return GetPreferredLanguage(info, &GetSystemPreferredUILanguages, "GetSystemPreferredUILanguages");
}

Napi::Value GetProcessPreferredUILanguagesWrap(const Napi::CallbackInfo &info) {
  return GetPreferredLanguage(info, &GetProcessPreferredUILanguages, "GetProcessPreferredUILanguages");
}

namespace Processes {
  void Init(Napi::Env env, Napi::Object exports) {
    exports.Set("GetProcessList", Napi::Function::New(env, GetProcessListWrap));
    exports.Set("GetModuleList", Napi::Function::New(env, GetModuleListWrap));
    exports.Set("GetProcessToken", Napi::Function::New(env, GetProcessToken));

    exports.Set("GetProcessWindowList", Napi::Function::New(env, GetProcessWindowListWrap));
    exports.Set("SetForegroundWindow", Napi::Function::New(env, SetForegroundWinWrap));

    exports.Set("GetUserPreferredUILanguages", Napi::Function::New(env, GetUserPreferredUILanguagesWrap));
    exports.Set("GetSystemPreferredUILanguages", Napi::Function::New(env, GetSystemPreferredUILanguagesWrap));
    exports.Set("GetProcessPreferredUILanguages", Napi::Function::New(env, GetProcessPreferredUILanguagesWrap));
    exports.Set("SetProcessPreferredUILanguages", Napi::Function::New(env, SetProcessPreferredUILanguagesWrap));
  }
}
