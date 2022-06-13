#include "processes.h"
#include "util.h"
#include "scopeguard.hpp"
#include "fs.h"
#include <windows.h>
#include <tlhelp32.h>
#include <UserEnv.h>
#include <AclAPI.h>
#include <future>

#pragma comment(lib, "UserEnv.lib")

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
      throw std::exception("Expected 1 parameter (process id)");
    }

    DWORD pid = info[0].ToNumber().Uint32Value();

    Napi::Array res = Napi::Array::New(info.Env());
    uint32_t resIdx = 0;

    HWND windowIter = nullptr;
    while (true) {
      // FindWindowEx, in contrast to EnumWindows, also lists metro-style windows.
      // Unfortunately FindWindowEx is not technically safe since the window list can change asynchronously but
      // even the published-by-microsoft ProcessExplorer uses it this way so - pffft.
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

Napi::Value CreateAppContainer(const Napi::CallbackInfo &info) {
  std::wstring containerName = toWC(info[0]);
  std::wstring displayName = toWC(info[1]);
  std::wstring description = toWC(info[2]);
  PSID sid;
  HRESULT res = ::CreateAppContainerProfile(containerName.c_str(), displayName.c_str(), description.c_str(), nullptr, 0, &sid);
  if (FAILED(res)) {
    if (HRESULT_CODE(res) == ERROR_ALREADY_EXISTS) {
      return info.Env().Undefined();
    }
    return ThrowHResultException(info.Env(), res, "CreateAppContainerProfile");
  }

  return info.Env().Undefined();
}

Napi::Value DeleteAppContainer(const Napi::CallbackInfo& info) {
  std::wstring containerName = toWC(info[0]);
  HRESULT res = ::DeleteAppContainerProfile(containerName.c_str());
  if (FAILED(res)) {
    return ThrowHResultException(info.Env(), res, "DeleteAppContainerProfile");
  }
  return info.Env().Undefined();
}

Napi::Value RunInContainer(const Napi::CallbackInfo& info) {
  std::wstring containerName = toWC(info[0]);
  std::wstring processPath = toWC(info[1]);
  std::wstring cwdPath = toWC(info[2]);

  PSID sid;
  HRESULT res = ::DeriveAppContainerSidFromAppContainerName(containerName.c_str(), &sid);
  if (FAILED(res)) {
    return ThrowHResultException(info.Env(), res, "DeriveAppContainerSidFromAppContainerName");
  }

  STARTUPINFOEX si = { sizeof(si) };
  PROCESS_INFORMATION pi;
  SECURITY_CAPABILITIES sc = { 0 };
  sc.AppContainerSid = sid;

  try {
    SIZE_T size = 0;
    // pre-flight to determine required size
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);

    std::vector<BYTE> buffer;
    buffer.resize(size);
    si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());

    checkedBool(::InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size),
      "InitializeProcThreadAttributeList", containerName.c_str());

    checkedBool(::UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), nullptr, nullptr),
      "UpdateProcThreadAttribute", containerName.c_str());

    checkedBool(::CreateProcessW(nullptr, processPath.data(), nullptr, nullptr, FALSE, EXTENDED_STARTUPINFO_PRESENT, nullptr, cwdPath.c_str(), (LPSTARTUPINFO)&si, &pi),
      "CreateProcessW", processPath.c_str());

    return info.Env().Undefined();
  }
  catch (const std::exception& e) {
    return Rethrow(info.Env(), e);
  }
}

void GrantPermission(PSID sid, HANDLE handle, LPCWSTR name, SE_OBJECT_TYPE type, DWORD accessPermissions)
{
  EXPLICIT_ACCESS_W explicitAccess;
  explicitAccess.Trustee.ptstrName = (PWSTR)sid;
  explicitAccess.grfAccessMode = GRANT_ACCESS;
  explicitAccess.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
  explicitAccess.grfAccessPermissions = accessPermissions;

  explicitAccess.Trustee.pMultipleTrustee = nullptr;
  explicitAccess.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
  // explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
  explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;

  PACL oldACL;
  checked(GetSecurityInfo(handle, type, DACL_SECURITY_INFORMATION, nullptr, nullptr, &oldACL, nullptr, nullptr), "GetSecurityInfo", name);

  PACL newACL;
  checked(SetEntriesInAclW(1, &explicitAccess, oldACL, &newACL), "SetEntriesInAclW", name);

  checked(SetSecurityInfo(handle, type, DACL_SECURITY_INFORMATION, nullptr, nullptr, newACL, nullptr), "SetSecurityInfo", name);
}

void GrantPermissionNamed(PSID sid, LPWSTR name, SE_OBJECT_TYPE type, DWORD accessPermissions)
{
  EXPLICIT_ACCESS_W explicitAccess;
  explicitAccess.Trustee.ptstrName = (PWSTR)sid;
  explicitAccess.grfAccessMode = GRANT_ACCESS;
  explicitAccess.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
  explicitAccess.grfAccessPermissions = accessPermissions;

  explicitAccess.Trustee.pMultipleTrustee = nullptr;
  explicitAccess.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
  // explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
  explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;

  PACL oldACL;
  checked(GetNamedSecurityInfoW(name, type, DACL_SECURITY_INFORMATION, nullptr, nullptr, &oldACL, nullptr, nullptr), "GetNamedSecurityInfoW", name);

  PACL newACL;
  checked(SetEntriesInAclW(1, &explicitAccess, oldACL, &newACL), "SetEntriesInAclW", name);

  checked(SetNamedSecurityInfoW(name, type, DACL_SECURITY_INFORMATION, nullptr, nullptr, newACL, nullptr), "SetNamedSecurityInfoW", name);
}

SE_OBJECT_TYPE typeFromName(const std::string& name) {
  static const std::unordered_map<std::string, SE_OBJECT_TYPE> typeNameMap{
    { "file_object", SE_FILE_OBJECT },
    { "service", SE_SERVICE },
    { "printer", SE_PRINTER },
    { "registry_key", SE_REGISTRY_KEY },
    { "se_lmshare", SE_LMSHARE },
    { "se_kernel_object", SE_KERNEL_OBJECT },
    { "se_window_object", SE_WINDOW_OBJECT },
    { "se_ds_object", SE_DS_OBJECT },
    { "se_ds_object_all", SE_DS_OBJECT_ALL },
    { "se_provider_defined_object", SE_PROVIDER_DEFINED_OBJECT },
    { "se_wmiguid_object", SE_WMIGUID_OBJECT },
    { "se_registry_wow64_32key", SE_REGISTRY_WOW64_32KEY },
    { "se_registry_wow64_64key", SE_REGISTRY_WOW64_64KEY },

    // custom object type to allow for special handling
    { "named_pipe", SE_KERNEL_OBJECT },
  };

  auto type = typeNameMap.find(name);
  if (type != typeNameMap.end()) {
    return type->second;
  }

  throw std::exception((std::string("invalid type \"") + name + "\"").c_str());
}

Napi::Value GrantAppContainer(const Napi::CallbackInfo& info) {
  std::wstring containerName = toWC(info[0]);
  std::wstring objectName = toWC(info[1]);
  std::string typeName = info[2].ToString();
  Napi::Array permissions = info[3].As<Napi::Array>();


  PSID sid;
  HRESULT res = ::DeriveAppContainerSidFromAppContainerName(containerName.c_str(), &sid);
  if (FAILED(res)) {
    return ThrowHResultException(info.Env(), res, "DeriveAppContainerSidFromAppContainerName");
  }
  
  try {
    SE_OBJECT_TYPE type = typeFromName(typeName);
    // the default approach of granting permission to named objects doesn't work for all kind of objects,
    // we have to implement special handling for some
    if (typeName == "named_pipe")
    {
      HANDLE handle = CreateFileW(objectName.c_str(), WRITE_DAC, 0, nullptr, OPEN_EXISTING, 0, nullptr);
      checkedBool((handle != INVALID_HANDLE_VALUE), "CreateFileW", objectName.c_str());
      GrantPermission(sid, handle, objectName.c_str(), type, mapPermissions(permissions));
    }
    else {
      GrantPermissionNamed(sid, objectName.data(), type, mapPermissions(permissions));
    }
    return info.Env().Undefined();
  }
  catch (const std::exception& e) {
    return Rethrow(info.Env(), e);
  }
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

    exports.Set("CreateAppContainer", Napi::Function::New(env, CreateAppContainer));
    exports.Set("DeleteAppContainer", Napi::Function::New(env, DeleteAppContainer));
    exports.Set("GrantAppContainer", Napi::Function::New(env, GrantAppContainer));
    exports.Set("RunInContainer", Napi::Function::New(env, RunInContainer));
  }
}
