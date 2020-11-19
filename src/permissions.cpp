#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <Sddl.h>
#include <string>
#include <vector>
#include <functional>
#include <napi.h>

#include "scopeguard.hpp"
#include "string_cast.h"
#include "util.h"

class Access {
public:
  Access(Access &reference)
    : mAccess(reference.mAccess), mSid(reference.mSid)
  {
    reference.mOwner = false;
  }

  Access(ACCESS_MODE mode, const std::string &group, const std::string &permission) {
    mAccess.grfAccessMode = mode;
    mAccess.grfAccessPermissions = translatePermission(permission);
    mAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    mAccess.Trustee = makeTrustee(group);
  }

  Access &operator=(const Access&) = delete;

  ~Access() {
    if (mOwner && (mSid != nullptr)) {
      LocalFree(mSid);
    }
  }

  PEXPLICIT_ACCESSW operator*() {
    return &mAccess;
  }
private:
  WELL_KNOWN_SID_TYPE translateGroup(const std::string &group) {
    if (group == "everyone") {
      return WinAuthenticatedUserSid;
    }
    else if (group == "owner") {
      return WinCreatorOwnerSid;
    }
    else if (group == "group") {
      return WinBuiltinUsersSid;
    }
    else if (group == "guest") {
      return WinBuiltinGuestsSid;
    }
    else if (group == "administrator") {
      return WinBuiltinAdministratorsSid;
    } else {
      return WinNullSid;
    }
  }

  DWORD translatePermission(const std::string &rights) {
    static auto sPermissions = std::vector<std::pair<char, DWORD>>({
        std::make_pair('r', FILE_GENERIC_READ),
        std::make_pair('w', FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
                                FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE | DELETE),
        std::make_pair('x', FILE_GENERIC_READ | FILE_GENERIC_EXECUTE),
    });

    DWORD res = 0;
    for (auto kv : sPermissions) {
      if (rights.find_first_of(kv.first) != std::string::npos) {
        res |= kv.second;
      }
    }
    return res;
  }

  TRUSTEEW makeTrustee(const std::string &group) {
    DWORD sidSize = SECURITY_MAX_SID_SIZE;
    // assume it's a known sid
    WELL_KNOWN_SID_TYPE knownSid = translateGroup(group);
    if (knownSid != WinNullSid) {
      mSid = LocalAlloc(LMEM_FIXED, sidSize);
      if (mSid == nullptr) {
        throw std::runtime_error("allocation error");
      }
      if (!CreateWellKnownSid(knownSid, nullptr, mSid, &sidSize)) {
        throw std::runtime_error(std::string("Failed to create sid from group \"") + group + "\": " + std::to_string(::GetLastError()));
      }
    } else {
      // no known sid, assume it's a stringified sid
      ConvertStringSidToSid(toWC(group.c_str(), CodePage::UTF8, group.size()).c_str(), &mSid);
    }

    TRUSTEEW res;
    res.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    res.pMultipleTrustee = nullptr;
    res.TrusteeForm = TRUSTEE_IS_SID;
    res.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    res.ptstrName = reinterpret_cast<LPWSTR>(mSid);
    return res;
  }
private:
  bool mOwner { true };
  EXPLICIT_ACCESSW mAccess;
  PSID mSid{nullptr};
};


class AccessWrap : public Napi::ObjectWrap<AccessWrap> {
public:
  static void Init(const Napi::Env &env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "Access", {
    });

    Napi::Object access = Napi::Object::New(env);
    access.Set("Grant", Napi::Function::New(env, AccessWrap::Grant));
    access.Set("Deny", Napi::Function::New(env, AccessWrap::Deny));
    access.Set("Revoke", Napi::Function::New(env, AccessWrap::Revoke));
    exports.Set("Access", access);

    constructor().Reset(func);
  }

  static Napi::Value Grant(const Napi::CallbackInfo &info) {
    if (info.Length() != 2) {
      throw Napi::Error::New(info.Env(), "Expected parameters (group, permission)");
    }

    return constructor().New({ Napi::Number::New(info.Env(), GRANT_ACCESS), info[0], info[1] });
  }

  static Napi::Value Deny(const Napi::CallbackInfo &info) {
    if (info.Length() != 2) {
      throw Napi::Error::New(info.Env(), "Expected parameters (group, permission)");
    }

    return constructor().New({ Napi::Number::New(info.Env(), DENY_ACCESS), info[0], info[1] });
  }

  static Napi::Value Revoke(const Napi::CallbackInfo &info) {
    if (info.Length() != 2) {
      throw Napi::Error::New(info.Env(), "Expected parameters (group, permission)");
    }

    return constructor().New({ Napi::Number::New(info.Env(), REVOKE_ACCESS), info[0], info[1] });
  }

  explicit AccessWrap(const Napi::CallbackInfo &info)
    : Napi::ObjectWrap<AccessWrap>(info) {
    m_Value = new Access(static_cast<ACCESS_MODE>(info[0].ToNumber().Int32Value()),
      info[1].ToString().Utf8Value(),
      info[2].ToString().Utf8Value());
  }

  ~AccessWrap() {
    delete m_Value;
  }

  Access *get() const { return m_Value; }

private:

  static inline Napi::FunctionReference &constructor() {
    static Napi::FunctionReference sInstance;
    return sInstance;
  }

  Access *m_Value;
};

std::string stringifyErr(DWORD code, const char *op) {
  std::string res;
  if (code == ERROR_ACCESS_DENIED) {
    res = std::string(op) + ": You don't have permission";
  } else if (code == ERROR_FILE_NOT_FOUND) {
    res = std::string(op) + ": File not found";
  } else if (code == ERROR_INVALID_NAME) {
    res = std::string(op) + ": Invalid name";
  } else {
    res = std::string(op) + " failed: " + std::to_string(code);
  }
  return res;
}

BOOL SetPrivilege(HANDLE token, LPCTSTR privilege, BOOL enable) {
  TOKEN_PRIVILEGES tokenPrivileges;
  LUID luid;

  if (!LookupPrivilegeValue(nullptr, privilege, &luid)) {
    return FALSE;
  }

  tokenPrivileges.PrivilegeCount = 1;
  tokenPrivileges.Privileges[0].Luid = luid;
  tokenPrivileges.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

  if (!AdjustTokenPrivileges(token, false, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
    return FALSE;
  }

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
    return FALSE;
  }

  return TRUE;
}

std::string sidToString(PSID sid) {
  LPWSTR stringSid = nullptr;
  if (!ConvertSidToStringSid(sid, &stringSid)) {
    throw WinApiException(::GetLastError(), "ConvertSidToStringSid");
    return "";
  }
  ScopeGuard onExit([&]() {
    if (stringSid != nullptr) {
      LocalFree(stringSid);
    }
    });

  return toMB(stringSid, CodePage::UTF8, wcslen(stringSid));
}

template<typename T> using deleted_unique_ptr = std::unique_ptr<T, std::function<void(T*)>>;

#define checkedBool(res, name, filePath) { if (!res) { throw WinApiException(::GetLastError(), name, filePath == nullptr ? nullptr : toMB(filePath, CodePage::UTF8, wcslen(filePath)).c_str()); } }
#define checked(res, name, filePath) { if (res != ERROR_SUCCESS) { throw WinApiException(res, name, filePath == nullptr ? nullptr : toMB(filePath, CodePage::UTF8, wcslen(filePath)).c_str()); } }

deleted_unique_ptr<TOKEN_USER> getCurrentUser() {
  HANDLE token;
  checkedBool(OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &token), "OpenProcessToken", nullptr);

  TOKEN_USER *temp = nullptr;
  DWORD required = 0;
  // pre-flight to get required buffer size
  GetTokenInformation(token, TokenUser, (void*)temp, 0, &required);
  deleted_unique_ptr<TOKEN_USER> res((TOKEN_USER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, required), [](TOKEN_USER *user) {
    HeapFree(GetProcessHeap(), 0, (void*)user);
    });

  checkedBool(GetTokenInformation(token, TokenUser, (void*)res.get(), required, &required), "GetTokenInformation", nullptr);
  LPWSTR stringSid = nullptr;
  checkedBool(ConvertSidToStringSid(res->User.Sid, &stringSid), "ConvertSidToStringSid", nullptr);

  return res;
}

void setOwner(std::wstring path, PSID owner) {
  HANDLE token;
  checkedBool(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token), "OpenProcessToken", path.c_str());
  checkedBool(SetPrivilege(token, SE_TAKE_OWNERSHIP_NAME, TRUE), "SetPrivilege", path.c_str());
  checkedBool(SetPrivilege(token, SE_RESTORE_NAME, TRUE), "SetPrivilege", path.c_str());
  checked(SetNamedSecurityInfoW(&path[0], SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, owner, nullptr, nullptr, nullptr), "SetNamedSecurityInfoW", path.c_str());
  checkedBool(SetPrivilege(token, SE_TAKE_OWNERSHIP_NAME, FALSE), "SetPrivilege", path.c_str());
  checkedBool(SetPrivilege(token, SE_RESTORE_NAME, FALSE), "SetPrivilege", path.c_str());
}

void applyImpl(Access &access, const std::string &path) {
  std::wstring wpath = toWC(path.c_str(), CodePage::UTF8, path.size());

  PSID owner;
  PACL oldAcl;
  PSECURITY_DESCRIPTOR secDesc = nullptr;
  DWORD res = GetNamedSecurityInfoW(
    wpath.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    &owner, nullptr, &oldAcl, nullptr, &secDesc);
  if (res != ERROR_SUCCESS) {
    throw WinApiException(res, "GetNamedSecurityInfoW", path.c_str());
  }

  ScopeGuard onExitSD([&] () {
    if (secDesc != nullptr) {
      ::LocalFree(secDesc);
    }
  });

  PACL newAcl = nullptr;

  res = SetEntriesInAclW(1, *access, oldAcl, &newAcl);

  if (res != ERROR_SUCCESS) {
    throw WinApiException(res, "SetEntriesInAclW", path.c_str());
  }

  ScopeGuard onExitACL([&] () {
    if (newAcl != nullptr) {
      LocalFree(newAcl);
    }
  });

  // SetNamedSecurityInfo expects a non-const point to the path, but there is
  // no indication that it may actually get changed, much less that we need
  // to provide a larger buffer than necessary to hold the string
  res = SetNamedSecurityInfoW(&wpath[0], SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION, nullptr, nullptr,
                              newAcl, nullptr);

  if (res == ERROR_ACCESS_DENIED) {
    // if this failed due to permission issues then the file/directory is owned by "a higher power", but
    // as admin we can change the owner - preferrably only temporary
    auto currentUser = getCurrentUser();
    setOwner(wpath, currentUser->User.Sid);
    res = SetNamedSecurityInfoW(&wpath[0], SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION, nullptr, nullptr,
      newAcl, nullptr);
    // restore previous owner of the item
    setOwner(wpath, owner);
  }

  if (res != ERROR_SUCCESS) {
    throw WinApiException(res, "SetNamedSecurityInfoW", path.c_str());
  }
}

std::string getSidImpl() {
  auto user = getCurrentUser();
  return sidToString(user->User.Sid);
}


Napi::Value apply(const Napi::CallbackInfo& info) {
  try {
    if (info.Length() != 2) {
      throw std::runtime_error("Expected parameters (access, path)");
    }

    Napi::Object access = info[0].ToObject();
    std::string path(info[1].ToString());

    applyImpl(*Napi::ObjectWrap<AccessWrap>::Unwrap(access)->get(), path);

    return info.Env().Undefined();
  }
  catch (const std::exception& e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value getSid(const Napi::CallbackInfo &info) {
  try {
    return Napi::String::New(info.Env(), getSidImpl().c_str());
  }
  catch (const std::exception& e) {
    return Rethrow(info.Env(), e);
  }
}

namespace Permissions {
  void Init(Napi::Env env, Napi::Object exports) {
    AccessWrap::Init(env, exports);

    exports.Set("AddFileACE", Napi::Function::New(env, apply));
    exports.Set("GetUserSID", Napi::Function::New(env, getSid));
  }
}


