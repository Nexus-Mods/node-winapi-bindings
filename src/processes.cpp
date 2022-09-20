#include "processes.h"
#include "util.h"
#include "scopeguard.hpp"
#include "fs.h"
#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <UserEnv.h>
#include <AclAPI.h>
#endif
#include <future>
#include <unordered_map>
#ifdef _WIN32

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
#endif

Napi::Value GetModuleListWrap(const Napi::CallbackInfo &info) {
  #ifdef _WIN32
  Napi::Env env = info.Env();
  auto convertME = [&env](const MODULEENTRY32W &mod) -> Napi::Object {
    Napi::Object item = Napi::Object::New(env);
    item.Set("baseAddr", Napi::Number::New(env, reinterpret_cast<uint64_t>(mod.modBaseAddr)));
    item.Set("baseSize", Napi::Number::New(env, mod.modBaseSize));
    item.Set("module", toMB(mod.szModule, CodePage::UTF8, wcslen(mod.szExePath)));
    item.Set("exePath", toMB(mod.szExePath, CodePage::UTF8, wcslen(mod.szExePath)));
    return item;
  };
  #endif
  try {
    if (info.Length() != 1) {
      throw Napi::Error::New(info.Env(), "Expected 1 parameter (process id)");
    }
    #ifdef _WIN32
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
    #else
    return info.Env().Undefined();
    #endif
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetProcessToken(const Napi::CallbackInfo &info) {
  try {
    if ((info.Length() < 1) || (info.Length() > 2)) {
      throw Napi::Error::New(info.Env(), "Expected 1 or 2 parameter(s) (type, pid?)");
    }
    #ifdef _WIN32
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
        throw Napi::Error::New(info.Env(), std::string("Unsupported token type \"" + tokenType + "\""));
      }
    }
    catch (DWORD code) {
      throw WinApiException(code, "GetTokenInformation");
    }
    #else
    return info.Env().Undefined();
    #endif
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetProcessListWrap(const Napi::CallbackInfo &info) {
  #ifdef _WIN32
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
  #else
  return info.Env().Undefined();
  #endif
}

Napi::Value GetProcessWindowListWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw Napi::Error::New(info.Env(), "Expected 1 parameter (process id)");
    }
    #ifdef _WIN32
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

      WINDOWINFO winInfo = { 0 };
      GetWindowInfo(windowIter, &winInfo);

      uint64_t winId = reinterpret_cast<uint64_t>(windowIter);
      if (((winInfo.dwStyle & WS_CAPTION) != 0) && ((winInfo.dwStyle & WS_CHILD) == 0)) {
        res.Set(resIdx++, Napi::Number::New(info.Env(), winId));
      }
    }

    return res;
    #else
    return info.Env().Undefined();
    #endif
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value SetForegroundWinWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw Napi::Error::New(info.Env(), "Expected 1 parameter (window id)");
    }
    #ifdef _WIN32
    uint64_t winId = info[0].ToNumber().Uint32Value();

    HWND hwnd = reinterpret_cast<HWND>(winId);

    if (::IsIconic(hwnd)) {
      ::ShowWindow(hwnd, 9);
    }

    return Napi::Boolean::New(info.Env(), ::SetForegroundWindow(hwnd));
    #else
    return info.Env().Undefined();
    #endif
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value SetProcessPreferredUILanguagesWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw Napi::Error::New(info.Env(), "Expected 1 parameter (the list of language codes, in the format \"en-US\")");
    }
    #ifdef _WIN32
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
    #endif
    return info.Env().Undefined();
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}
#ifdef _WIN32
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
#endif

Napi::Value GetUserPreferredUILanguagesWrap(const Napi::CallbackInfo &info) {
  #ifdef _WIN32
  return GetPreferredLanguage(info, &GetUserPreferredUILanguages, "GetUserPreferredUILanguages");
  #else
  return info.Env().Undefined();
  #endif
}

Napi::Value GetSystemPreferredUILanguagesWrap(const Napi::CallbackInfo &info) {
  #ifdef _WIN32
  return GetPreferredLanguage(info, &GetSystemPreferredUILanguages, "GetSystemPreferredUILanguages");
  #else
  return info.Env().Undefined();
  #endif
}

Napi::Value GetProcessPreferredUILanguagesWrap(const Napi::CallbackInfo &info) {
  #ifdef _WIN32
  return GetPreferredLanguage(info, &GetProcessPreferredUILanguages, "GetProcessPreferredUILanguages");
  #else
  return info.Env().Undefined();
  #endif
}

#ifdef _WIN32
typedef USERENVAPI
HRESULT (WINAPI *CreateAppContainerProfileType)(
    _In_ PCWSTR pszAppContainerName,
    _In_ PCWSTR pszDisplayName,
    _In_ PCWSTR pszDescription,
    _In_reads_opt_(dwCapabilityCount) PSID_AND_ATTRIBUTES pCapabilities,
    _In_ DWORD dwCapabilityCount,
    _Outptr_ PSID* ppSidAppContainerSid);

typedef USERENVAPI
HRESULT (WINAPI *DeriveAppContainerSidFromAppContainerNameType)(
    _In_ PCWSTR pszAppContainerName,
    _Outptr_ PSID *ppsidAppContainerSid);

typedef USERENVAPI
HRESULT (WINAPI *DeleteAppContainerProfileType)(
    _In_ PCWSTR pszAppContainerName);

struct UserEnv {
  static UserEnv& instance() {
    static UserEnv sInstance;
    return sInstance;
  }

  CreateAppContainerProfileType CreateAppContainerProfile;
  DeriveAppContainerSidFromAppContainerNameType DeriveAppContainerSidFromAppContainerName;
  DeleteAppContainerProfileType DeleteAppContainerProfile;

  bool valid() const { return m_Valid; }

private:
  bool m_Valid{ false };

  UserEnv()
    : CreateAppContainerProfile(nullptr)
    , DeriveAppContainerSidFromAppContainerName(nullptr)
    , DeleteAppContainerProfile(nullptr)
  {
    HMODULE mod = ::LoadLibraryW(L"UserEnv.dll");
    if (mod == nullptr) {
      return;
    }
    CreateAppContainerProfile = (CreateAppContainerProfileType)::GetProcAddress(mod, "CreateAppContainerProfile");
    DeriveAppContainerSidFromAppContainerName = (DeriveAppContainerSidFromAppContainerNameType)::GetProcAddress(mod, "DeriveAppContainerSidFromAppContainerName");
    DeleteAppContainerProfile = (DeleteAppContainerProfileType)::GetProcAddress(mod, "DeleteAppContainerProfile");

    m_Valid = (CreateAppContainerProfile != nullptr)
           && (DeriveAppContainerSidFromAppContainerName != nullptr)
           && (DeleteAppContainerProfile != nullptr);
  }
};
#endif

Napi::Value SupportsAppContainer(const Napi::CallbackInfo& info) {
  #ifdef _WIN32
  return Napi::Boolean::New(info.Env(), UserEnv::instance().valid());
  #else
  return info.Env().Undefined();
  #endif
}

Napi::Value CreateAppContainer(const Napi::CallbackInfo &info) {
  try {
    #ifdef _WIN32
    if (!UserEnv::instance().valid()) {
      return info.Env().Undefined();
    }

    if (info.Length() != 3) {
      throw Napi::Error::New(info.Env(), "Expected 3 parameters (container name, display name, description)");
    }

    std::wstring containerName = toWC(info[0]);
    std::wstring displayName = toWC(info[1]);
    std::wstring description = toWC(info[2]);

    std::vector<SID_AND_ATTRIBUTES> capabilities;
    for (auto id : { WinCapabilityPicturesLibrarySid }) {
      PSID psid = HeapAlloc(GetProcessHeap(), 0, SECURITY_MAX_SID_SIZE);
      if (psid == nullptr) {
        throw Napi::Error::New(info.Env(), "alloc failed");
      }
      DWORD sidlistsize = SECURITY_MAX_SID_SIZE;
      if (::CreateWellKnownSid(id, NULL, psid, &sidlistsize) != TRUE) {
        HeapFree(GetProcessHeap(), 0, psid);
        continue;
      }
      if (::IsWellKnownSid(psid, id) != TRUE) {
        HeapFree(GetProcessHeap(), 0, psid);
        continue;
      }
      SID_AND_ATTRIBUTES attr;
      attr.Sid = psid;
      attr.Attributes = SE_GROUP_ENABLED;
      capabilities.push_back(attr);
    }

    PSID sid = nullptr;
    HRESULT res = UserEnv::instance().CreateAppContainerProfile(
      containerName.c_str(), displayName.c_str(), description.c_str(), capabilities.data(), capabilities.size(), &sid);
    ScopeGuard onExit([&]() { ::FreeSid(sid); });

    if (FAILED(res)) {
      if (HRESULT_CODE(res) == ERROR_ALREADY_EXISTS) {
        return info.Env().Undefined();
      }
      return ThrowHResultException(info.Env(), res, "CreateAppContainerProfile");
    }
    #endif
    return info.Env().Undefined();
  }
  catch (const std::exception& e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value DeleteAppContainer(const Napi::CallbackInfo& info) {
  try {
    #ifdef _WIN32
    if (!UserEnv::instance().valid()) {
      return info.Env().Undefined();
    }
    #endif
    if (info.Length() != 1) {
      throw Napi::Error::New(info.Env(), "Expected 1 parameter (container name)");
    }
    #ifdef _WIN32
    std::wstring containerName = toWC(info[0]);
    HRESULT res = UserEnv::instance().DeleteAppContainerProfile(containerName.c_str());
    if (FAILED(res)) {
      return ThrowHResultException(info.Env(), res, "DeleteAppContainerProfile");
    }
    #endif
    return info.Env().Undefined();
  }
  catch (const std::exception& e) {
    return Rethrow(info.Env(), e);
  }

}

#ifdef _WIN32
class ProcessMonitor : public Napi::AsyncProgressQueueWorker<char> {
public:
  ProcessMonitor(const Napi::Function &onExit, const Napi::Function &onStdOut, HANDLE proc, HANDLE stdOutHandle)
    : Napi::AsyncProgressQueueWorker<char>(onExit)
    , mOnStdOut(Napi::Persistent(onStdOut))
  {
    mProc = proc;
    mStdOut = stdOutHandle;
  }

  ~ProcessMonitor() {
    ::CloseHandle(mProc);
    ::CloseHandle(mStdOut);
  }

  virtual void OnProgress(const char* data, size_t size) override {
    try {
      std::string copy(data, size);
      mOnStdOut.Call(Receiver().Value(), std::initializer_list<napi_value>{ Napi::String::From(Env(), copy) });
    }
    catch (const std::exception& e) {
      SetError(e.what());
    }
  }

  virtual void Execute(const ExecutionProgress &progress) override {
    static const int BUFSIZE = 4096;
    char buf[BUFSIZE + 1];
    DWORD readBytes = BUFSIZE;
    BOOL res;

    while (true) {
      memset(buf, '\0', BUFSIZE + 1);
      res = ::ReadFile(mStdOut, buf, BUFSIZE, &readBytes, nullptr);
      if (!res || (readBytes == 0)) {
        break;
      }

      buf[readBytes] = '\0';
      // fixing windows line breaks
      if ((readBytes >= 2) && (buf[readBytes - 2] == '\r')) {
        buf[readBytes - 2] = '\n';
        buf[readBytes - 1] = '\0';
        readBytes -= 1;
      }

      progress.Send(buf, readBytes);
    }
  }

  virtual void OnOK() override {
    DWORD exitCode = 0;
    ::GetExitCodeProcess(mProc, &exitCode);
    Callback().Call(Receiver().Value(), std::initializer_list<napi_value>{ Napi::Number::From(Env(), exitCode) });
  }


private:
  Napi::FunctionReference mOnStdOut;
  HANDLE mProc;
  HANDLE mStdOut;
};
#endif

Napi::Value RunInContainer(const Napi::CallbackInfo& info) {
  try {
    if (info.Length() != 5) {
      throw Napi::Error::New(info.Env(), "Expected 5 parameters (container name, commandline, working directory, onexit callback, stdout callback)");
    }
    #ifdef _WIN32
    std::wstring containerName = toWC(info[0]);
    std::wstring commandLine = toWC(info[1]);
    std::wstring cwdPath = toWC(info[2]);
    Napi::Function onExitCB = info[3].As<Napi::Function>();
    Napi::Function onStdoutCB = info[4].As<Napi::Function>();

    PSID sid = nullptr;
    if (UserEnv::instance().valid()) {
      HRESULT res = UserEnv::instance().DeriveAppContainerSidFromAppContainerName(containerName.c_str(), &sid);
      if (FAILED(res)) {
        return ThrowHResultException(info.Env(), res, "DeriveAppContainerSidFromAppContainerName");
      }
    }
    ScopeGuard onExit([&]() {
      if (sid != nullptr) {
        ::FreeSid(sid);
      }
      });

    STARTUPINFOEX startupInfo = { sizeof(startupInfo) };
    PROCESS_INFORMATION processInfo;
    SECURITY_CAPABILITIES secCap = { 0 };
    secCap.AppContainerSid = sid;

    SIZE_T size = 0;
    // pre-flight to determine required size
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);

    std::vector<BYTE> buffer;
    buffer.resize(size);
    startupInfo.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());

    SECURITY_ATTRIBUTES secAttr;
    ::ZeroMemory(&secAttr, sizeof(secAttr));
    secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    secAttr.bInheritHandle = TRUE;
    secAttr.lpSecurityDescriptor = nullptr;

    HANDLE stdoutR, stdoutW;

    checkedBool(::CreatePipe(&stdoutR, &stdoutW, &secAttr, 0), "CreatePipe", commandLine.c_str());
    checkedBool(::SetHandleInformation(stdoutR, HANDLE_FLAG_INHERIT, 0), "SetHandleInformation", commandLine.c_str());

    startupInfo.StartupInfo.hStdError = stdoutW;
    startupInfo.StartupInfo.hStdOutput = stdoutW;
    startupInfo.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;

    checkedBool(::InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, &size),
      "InitializeProcThreadAttributeList", containerName.c_str());

    if (UserEnv::instance().valid()) {
      checkedBool(::UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &secCap, sizeof(secCap), nullptr, nullptr),
        "UpdateProcThreadAttribute", containerName.c_str());
    }

    DWORD processFlags = CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;

    checkedBool(::CreateProcessW(
      nullptr,
      commandLine.data(),
      nullptr,
      nullptr,
      TRUE,
      processFlags,
      nullptr,
      cwdPath.c_str(),
      (LPSTARTUPINFOW)&startupInfo,
      &processInfo
    ), "CreateProcessW", commandLine.c_str());

    // ::CloseHandle(processInfo.hProcess);
    ::CloseHandle(processInfo.hThread);
    ::CloseHandle(stdoutW);
    stdoutW = nullptr;

    auto worker = new ProcessMonitor(onExitCB, onStdoutCB, processInfo.hProcess, stdoutR);
    worker->Queue();

    return Napi::Number::From(info.Env(), processInfo.dwProcessId);
    #else
    return info.Env().Undefined();
    #endif
  }
  catch (const std::exception& e) {
    return Rethrow(info.Env(), e);
  }
}

#ifdef _WIN32
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
#endif

Napi::Value GrantAppContainer(const Napi::CallbackInfo& info) {
  try {
    if (info.Length() != 4) {
      throw Napi::Error::New(info.Env(), "Expected 4 parameters (container, object, type, permissions)");
    }
    #ifdef _WIN32
    std::wstring containerName = toWC(info[0]);
    std::wstring objectName = toWC(info[1]);
    std::string typeName = info[2].ToString();
    Napi::Array permissions = info[3].As<Napi::Array>();

    if (!UserEnv::instance().valid()) {
      return info.Env().Undefined();
    }

    PSID sid;
    HRESULT res = UserEnv::instance().DeriveAppContainerSidFromAppContainerName(containerName.c_str(), &sid);
    if (FAILED(res)) {
      return ThrowHResultException(info.Env(), res, "DeriveAppContainerSidFromAppContainerName");
    }
    ScopeGuard onExit([&]() { ::FreeSid(sid); });

    SE_OBJECT_TYPE type = typeFromName(typeName);
    // the default approach of granting permission to named objects doesn't work for all kind of objects,
    // we have to implement special handling for some
    if (typeName == "named_pipe")
    {
      HANDLE handle = CreateFileW(objectName.c_str(), WRITE_DAC | READ_CONTROL, 0, nullptr, OPEN_EXISTING, 0, nullptr);
      ScopeGuard onExit([&]() { ::CloseHandle(handle); });
      checkedBool((handle != INVALID_HANDLE_VALUE), "CreateFileW", objectName.c_str());
      GrantPermission(sid, handle, objectName.c_str(), type, mapPermissions(permissions));
    }
    else {
      GrantPermissionNamed(sid, objectName.data(), type, mapPermissions(permissions));
    }
    #endif
    return info.Env().Undefined();
  }
  catch (const std::exception& e) {
    return Rethrow(info.Env(), e);
  }
}

#ifdef _WIN32
DWORD mapIntegrityLevel(const std::string &integrityName) {
  static const std::unordered_map<std::string, DWORD> integrityMap{
    { "untrusted", SECURITY_MANDATORY_UNTRUSTED_RID },
    { "low", SECURITY_MANDATORY_LOW_RID }
  };
  auto iter = integrityMap.find(integrityName);
  if (iter == integrityMap.end()) {
    throw std::exception("invalid integrity level");
  }
  return iter->second;
}
#endif

Napi::Value CreateProcessWithIntegrity(const Napi::CallbackInfo& info) {
  try {
    if (info.Length() != 5) {
      throw Napi::Error::New(info.Env(), "Expected 5 parameters (commandline, working directory, integrity level, onexit callback, stdout callback)");
    }
    #ifdef _WIN32
    std::wstring commandLine = toWC(info[0]);
    std::wstring cwdPath = toWC(info[1]);
    std::string integrityName = info[2].ToString();
    Napi::Function onExitCB = info[3].As<Napi::Function>();
    Napi::Function onStdoutCB = info[4].As<Napi::Function>();

    SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;

    PSID integrityLevel;
    checkedBool(::AllocateAndInitializeSid(
      &authority,
      1,
      mapIntegrityLevel(integrityName),
      0, 0, 0, 0, 0, 0, 0,
      &integrityLevel), "AllocateAndInitializeSid", nullptr);

    HANDLE token, newToken;
    checkedBool(::OpenProcessToken(::GetCurrentProcess(), MAXIMUM_ALLOWED, &token), "OpenProcessToken", nullptr);
    ScopeGuard onExit1([&]() { ::CloseHandle(token); });

    checkedBool(::DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation,
      TokenPrimary, &newToken), "DuplicateTokenEx", nullptr);
    ScopeGuard onExit2([&]() { ::CloseHandle(newToken); });

    TOKEN_MANDATORY_LABEL tml = { 0 };
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = integrityLevel;

    checkedBool(::SetTokenInformation(newToken, TokenIntegrityLevel, &tml,
      sizeof(TOKEN_MANDATORY_LABEL) + ::GetLengthSid(integrityLevel)), "SetTokenInformation", nullptr);

    STARTUPINFOEX startupInfo = { sizeof(startupInfo) };
    /*
    STARTUPINFOW startupInfo;
    ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
    startupInfo.cb = sizeof(STARTUPINFOW);
    */

    PROCESS_INFORMATION processInfo = { 0 };

    SECURITY_ATTRIBUTES secAttr;
    ::ZeroMemory(&secAttr, sizeof(secAttr));
    secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    secAttr.bInheritHandle = TRUE;
    secAttr.lpSecurityDescriptor = nullptr;

    HANDLE stdoutR, stdoutW;

    checkedBool(::CreatePipe(&stdoutR, &stdoutW, &secAttr, 0), "CreatePipe", commandLine.c_str());
    checkedBool(::SetHandleInformation(stdoutR, HANDLE_FLAG_INHERIT, 0), "SetHandleInformation", commandLine.c_str());

    startupInfo.StartupInfo.hStdError = stdoutW;
    startupInfo.StartupInfo.hStdOutput = stdoutW;
    startupInfo.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;

    DWORD processFlags = CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;

    checkedBool(::CreateProcessAsUserW(
      newToken,
      nullptr,
      commandLine.data(),
      nullptr,
      nullptr,
      TRUE,
      processFlags,
      nullptr,
      cwdPath.c_str(),
      (LPSTARTUPINFOW) &startupInfo,
      &processInfo
    ), "CreateProcessAsUser", commandLine.c_str());

    ::CloseHandle(processInfo.hThread);
    ::CloseHandle(stdoutW);
    // ::CloseHandle(processInfo.hProcess);
    stdoutW = nullptr;

    auto worker = new ProcessMonitor(onExitCB, onStdoutCB, processInfo.hProcess, stdoutR);
    worker->Queue();

    return Napi::Number::From(info.Env(), processInfo.dwProcessId);
    #else
    return info.Env().Undefined();
    #endif
  }
  catch (const std::exception &e) {
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

    exports.Set("SupportsAppContainer", Napi::Function::New(env, SupportsAppContainer));
    exports.Set("CreateAppContainer", Napi::Function::New(env, CreateAppContainer));
    exports.Set("DeleteAppContainer", Napi::Function::New(env, DeleteAppContainer));
    exports.Set("GrantAppContainer", Napi::Function::New(env, GrantAppContainer));
    exports.Set("RunInContainer", Napi::Function::New(env, RunInContainer));
    exports.Set("CreateProcessWithIntegrity", Napi::Function::New(env, CreateProcessWithIntegrity));
  }
}
