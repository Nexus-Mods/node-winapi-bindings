#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atlbase.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <Shlobj.h>
#include <taskschd.h>
#include <comdef.h>
#include <wchar.h>
#include <stdio.h>
#include <string>
#include <functional>
#include <unordered_map>
#include <list>
#include <nan.h>
#include <iostream>
#include "string_cast.h"

#pragma comment(lib, "taskschd.lib")


using namespace Nan;
using namespace v8;


static std::wstring strerror(DWORD errorno) {
  wchar_t *errmsg = nullptr;

  LCID lcid;
  GetLocaleInfoEx(L"en-US", LOCALE_RETURN_NUMBER | LOCALE_ILANGUAGE, reinterpret_cast<LPWSTR>(&lcid), sizeof(lcid));

  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
    FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, errorno,
    lcid, (LPWSTR)&errmsg, 0, nullptr);

  if (errmsg) {
    for (int i = (wcslen(errmsg) - 1);
         (i >= 0) && ((errmsg[i] == '\n') || (errmsg[i] == '\r'));
         --i) {
      errmsg[i] = '\0';
    }

    return errmsg;
  }
  else {
    return L"Unknown error";
  }
}

Local<String> operator "" _n(const char *input, size_t) {
  return Nan::New(input).ToLocalChecked();
}

const char *translateCode(DWORD err) {
  switch (err) {
  case ERROR_USER_MAPPED_FILE: return "EBUSY";
  default: return uv_err_name(uv_translate_sys_error(err));
  }
}

void setNodeErrorCode(v8::Local<v8::Object> err, DWORD errCode) {
  Local<Context> context = Nan::GetCurrentContext();
  if (!err->Has(context, "code"_n).ToChecked()) {
    err->Set(context, "code"_n, Nan::New(translateCode(errCode)).ToLocalChecked());
  }
}

inline v8::Local<v8::Value> WinApiException(
  DWORD lastError
  , const char *func = nullptr
  , const char *path = nullptr) {

  Local<Context> context = Nan::GetCurrentContext();

  std::wstring errStr = strerror(lastError);
  std::string err = toMB(errStr.c_str(), CodePage::UTF8, errStr.size()) + " (" + std::to_string(lastError) + ")";
  v8::Local<v8::Value> res = node::WinapiErrnoException(v8::Isolate::GetCurrent(), lastError, func, err.c_str(), path);
  setNodeErrorCode(res->ToObject(context).ToLocalChecked(), lastError);
  return res;
}

inline v8::Local<v8::Value> HResultException(HRESULT hr, const char *func = nullptr, const char *path = nullptr) {
  Local<Context> context = Nan::GetCurrentContext();

  _com_error err(hr);
  LPCWSTR errMsg = err.ErrorMessage();
  std::string errMsgUtf8 = toMB(errMsg, CodePage::UTF8, wcslen(errMsg));

  v8::Local<v8::Value> res = node::WinapiErrnoException(v8::Isolate::GetCurrent(), hr & 0xFFFF, func, errMsgUtf8.c_str(), path);
  setNodeErrorCode(res->ToObject(context).ToLocalChecked(), hr & 0xFFFF);
  return res;
}

std::wstring toWC(const Local<Value> &input) {
  Isolate *isolate = Isolate::GetCurrent();

  if (input->IsNullOrUndefined()) {
    return std::wstring();
  }
  String::Utf8Value temp(isolate, input);
  return toWC(*temp, CodePage::UTF8, temp.length());
}

Local<Value> toV8(const wchar_t *input) {
  return Nan::New<String>(toMB(input, CodePage::UTF8, (std::numeric_limits<size_t>::max)())).ToLocalChecked();
}


DWORD mapAttributes(Isolate *isolate, Local<Array> input) {
  static const std::unordered_map<std::string, DWORD> attributeMap{
    { "archive", FILE_ATTRIBUTE_ARCHIVE },
    { "hidden", FILE_ATTRIBUTE_HIDDEN },
    { "normal", FILE_ATTRIBUTE_NORMAL },
    { "not_content_indexed", FILE_ATTRIBUTE_NOT_CONTENT_INDEXED },
    { "readonly", FILE_ATTRIBUTE_READONLY },
    { "temporary", FILE_ATTRIBUTE_TEMPORARY },
  };

  Local<Context> context = Nan::GetCurrentContext();

  DWORD res = 0;
  for (uint32_t i = 0; i < input->Length(); ++i) {
    v8::String::Utf8Value attr(isolate, input->Get(context, i).ToLocalChecked());

    auto attribute = attributeMap.find(*attr);
    if (attribute != attributeMap.end()) {
      res |= attribute->second;
    }
  }

  return res;
}

NAN_METHOD(SetFileAttributes) {
  Isolate* isolate = Isolate::GetCurrent();
  try {
    if (info.Length() != 2) {
      Nan::ThrowError("Expected two parameters (path, attributes)");
      return;
    }

    String::Utf8Value pathV8(isolate, info[0]);
    std::wstring path = toWC(*pathV8, CodePage::UTF8, pathV8.length());
    Local<Array> attributes = Local<Array>::Cast(info[1]);

    if (!::SetFileAttributesW(path.c_str(), mapAttributes(isolate, attributes))) {
      isolate->ThrowException(WinApiException(::GetLastError(), "SetFileAttributes", *pathV8));
      return;
    }
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

NAN_METHOD(GetDiskFreeSpaceEx) {
  Isolate* isolate = Isolate::GetCurrent();
  Local<Context> context = Nan::GetCurrentContext();

  try {
    if (info.Length() != 1) {
      Nan::ThrowError("Expected one parameter (path)");
      return;
    }

    String::Utf8Value pathV8(isolate, info[0]);
    std::wstring path = toWC(*pathV8, CodePage::UTF8, pathV8.length());

    ULARGE_INTEGER freeBytesAvailableToCaller;
    ULARGE_INTEGER totalNumberOfBytes;
    ULARGE_INTEGER totalNumberOfFreeBytes;

    if (!::GetDiskFreeSpaceExW(path.c_str(),
      &freeBytesAvailableToCaller,
      &totalNumberOfBytes,
      &totalNumberOfFreeBytes)) {
      isolate->ThrowException(WinApiException(::GetLastError(), "GetDiskFreeSpaceEx", *pathV8));
      return;
    }

    Local<Object> result = Nan::New<Object>();
    result->Set(context, "total"_n, Nan::New<Number>(static_cast<double>(totalNumberOfBytes.QuadPart)));
    result->Set(context, "free"_n, Nan::New<Number>(static_cast<double>(totalNumberOfFreeBytes.QuadPart)));
    result->Set(context, "freeToCaller"_n, Nan::New<Number>(static_cast<double>(freeBytesAvailableToCaller.QuadPart)));

    info.GetReturnValue().Set(result);
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

NAN_METHOD(GetVolumePathName) {
  Isolate* isolate = Isolate::GetCurrent();

  try {
    if (info.Length() != 1) {
      Nan::ThrowError("Expected one parameter (path)");
      return;
    }

    std::wstring path = toWC(info[0]);

    wchar_t buffer[MAX_PATH];
    if (!::GetVolumePathNameW(path.c_str(), buffer, MAX_PATH)) {
      isolate->ThrowException(WinApiException(::GetLastError(), "GetDiskFreeSpaceEx", toMB(path.c_str(), CodePage::UTF8, path.length()).c_str()));
      return;
    }

    info.GetReturnValue().Set(Nan::New<String>(toMB(buffer, CodePage::UTF8, (std::numeric_limits<size_t>::max)())).ToLocalChecked());
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}


uint32_t translateExecuteMask(const std::string &name) {
  static std::unordered_map<std::string, uint32_t> map{
    { "noasync", SEE_MASK_NOASYNC },
    { "flag_no_ui", SEE_MASK_FLAG_NO_UI },
    { "unicode", SEE_MASK_UNICODE },
    { "no_console", SEE_MASK_NO_CONSOLE },
    { "waitforinputidle", SEE_MASK_WAITFORINPUTIDLE }
  };

  auto iter = map.find(name);
  if (iter != map.end()) {
    return iter->second;
  }

  return 0;
}

typedef struct {
  DWORD pid;
  HWND hwnd;
} WINDOWPROCESSINFO;

static BOOL CALLBACK getWindowByProcess(HWND hwnd, LPARAM lParam)
{
  WINDOWPROCESSINFO *infoPtr = (WINDOWPROCESSINFO *)lParam;
  DWORD check = 0;
  BOOL br = true;
  GetWindowThreadProcessId(hwnd, &check);
  if (check == infoPtr->pid) {
    infoPtr->hwnd = hwnd;
    return false;
  }
  return true;
}

#include <fstream>

NAN_METHOD(ShellExecuteEx) {
  static const DWORD SW_FOREGROUND = SW_MAX + 1;
  static const std::unordered_map<std::string, DWORD> showFlagMap{
    {"hide", SW_HIDE},
    {"maximize", SW_MAXIMIZE},
    {"minimize", SW_MINIMIZE},
    {"restore", SW_RESTORE},
    {"show", SW_SHOW},
    {"showdefault", SW_SHOWDEFAULT},
    {"showminimized", SW_SHOWMINIMIZED},
    {"showminnoactive", SW_SHOWMINNOACTIVE},
    {"showna", SW_SHOWNA},
    {"shownoactivate", SW_SHOWNOACTIVATE},
    {"shownormal", SW_SHOWNORMAL},
    {"foreground", SW_FOREGROUND}
  };

  Isolate *isolate = Isolate::GetCurrent();
  Local<Context> context = Nan::GetCurrentContext();

  try {
    if (info.Length() != 1) {
      Nan::ThrowError("Expected one parameter (options)");
      return;
    }

    Local<Object> args(info[0]->ToObject(context).ToLocalChecked());
    auto hasArg = [&args, &context](const Local<String> &key) {
      return args->Has(context, key).ToChecked();
    };

    if (!hasArg("file"_n) || !hasArg("show"_n)) {
      Nan::ThrowError("Parameter missing (required: file, show)");
      return;
    }

    // important: has to be a container that doesn't invalidate iterators on insertion (like vector would)
    std::list<std::wstring> buffers;

    auto assignParameter = [isolate, &context, &args, &hasArg, &buffers](LPCWSTR &target, const Local<String> &key) {
      if (hasArg(key)) {
        String::Utf8Value value(isolate, args->Get(context, key).ToLocalChecked());
        buffers.push_back(toWC(*value, CodePage::UTF8, value.length()));
        target = buffers.rbegin()->c_str();
      }
      else {
        target = nullptr;
      }
    };

    SHELLEXECUTEINFOW execInfo;
    ZeroMemory(&execInfo, sizeof(SHELLEXECUTEINFOW));
    execInfo.cbSize = sizeof(SHELLEXECUTEINFO);

    execInfo.fMask = 0;

    if ((hasArg("mask"_n) && args->Get(context, "mask"_n).ToLocalChecked()->IsArray())) {
      Local<Array> mask = Local<Array>::Cast(args->Get(context, "mask"_n).ToLocalChecked());
      for (uint32_t i = 0; i < mask->Length(); ++i) {
        Local<Value> val = mask->Get(context, i).ToLocalChecked();
        if (val->IsString()) {
          execInfo.fMask |= translateExecuteMask(*Utf8String(val->ToString(context).ToLocalChecked()));
        }
        else {
          execInfo.fMask |= val->Uint32Value(context).ToChecked();
        }
      }
    }

    execInfo.hwnd = nullptr;
    execInfo.hInstApp = nullptr;

    assignParameter(execInfo.lpVerb, "verb"_n);
    assignParameter(execInfo.lpFile, "file"_n);
    assignParameter(execInfo.lpDirectory, "directory"_n);
    assignParameter(execInfo.lpParameters, "parameters"_n);

    v8::String::Utf8Value show(isolate, args->Get(context, "show"_n).ToLocalChecked());
    auto iter = showFlagMap.find(*show);
    if (iter == showFlagMap.end()) {
      Nan::ThrowRangeError("Invalid show flag");
      return;
    }
    if (iter->second == SW_FOREGROUND) {
      execInfo.nShow = SW_RESTORE;
      execInfo.fMask |= SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_WAITFORINPUTIDLE;

      // allow _all_ processes to set the foreground window, so that if the ShellExecute is forwarded to
      // a running application, that application can take put itself to the foreground.
      // Maybe it would make more sense to limit this to processes that have a window but for all I know, figuring out
      // which process has a window may be more time consuming than simply doing it for every process
      HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      PROCESSENTRY32W pe32;

      if (snap != INVALID_HANDLE_VALUE) {
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        bool more = ::Process32FirstW(snap, &pe32);
        while (more) {
          AllowSetForegroundWindow(pe32.th32ProcessID);
          more = ::Process32NextW(snap, &pe32);
        }
        ::CloseHandle(snap);
      }
    } else {
      execInfo.nShow = iter->second;
    }

    if (!::ShellExecuteExW(&execInfo)) {
      std::string fileName = toMB(execInfo.lpFile, CodePage::UTF8, wcslen(execInfo.lpFile));
      isolate->ThrowException(WinApiException(::GetLastError(), "ShellExecuteEx", fileName.c_str()));
      return;
    }

    if (iter->second == SW_FOREGROUND) {
      WINDOWPROCESSINFO info;
      info.pid = GetProcessId(execInfo.hProcess);
      info.hwnd = 0;
      // put the process into the foreground _if_ a new process was created
      AllowSetForegroundWindow(info.pid);
      EnumWindows(getWindowByProcess, (LPARAM)&info);
      if (info.hwnd != 0) {
        SetForegroundWindow(info.hwnd);
        SetActiveWindow(info.hwnd);
      }
      CloseHandle(execInfo.hProcess);
    }
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

NAN_METHOD(GetPrivateProfileSection) {
  Isolate* isolate = Isolate::GetCurrent();
  Local<Context> context = Nan::GetCurrentContext();

  try {
    if (info.Length() != 2) {
      Nan::ThrowError("Expected two parameters (section, fileName)");
      return;
    }

    String::Utf8Value appNameV8(isolate, info[0]);
    String::Utf8Value fileNameV8(isolate, info[1]);

    std::wstring appName = toWC(*appNameV8, CodePage::UTF8, appNameV8.length());
    std::wstring fileName = toWC(*fileNameV8, CodePage::UTF8, fileNameV8.length());

    DWORD size = 32 * 1024;
    std::unique_ptr<wchar_t[]> buffer(new wchar_t[size]);

    DWORD charCount = ::GetPrivateProfileSectionW(appName.c_str(), buffer.get(), size, fileName.c_str());

    Local<Object> result = Nan::New<Object>();
    wchar_t *start = buffer.get();
    wchar_t *ptr = start;
    // double check. the list is supposed to end on a double zero termination but to ensure we don't overrun
    // the buffer, also verify we don't exceed the character count
    Local<String> lastKey;
    Local<String> lastValue;
    while ((*ptr != '\0') && ((ptr - start) < charCount)) {
      wchar_t *eqPos = wcschr(ptr, L'=');
      size_t valLength;
      if (eqPos != nullptr) {
        lastKey = Nan::New<String>(toMB(ptr, CodePage::UTF8, eqPos - ptr)).ToLocalChecked();
        valLength = wcslen(eqPos);
        lastValue = Nan::New<String>(toMB(eqPos + 1, CodePage::UTF8, valLength - 1)).ToLocalChecked();
        ptr = eqPos + valLength + 1;
        result->Set(context, lastKey, lastValue);
      }
      else {
        // ignore all lines that contain no equal sign
        ptr += wcslen(ptr) + 1;
      }
    }

    info.GetReturnValue().Set(result);
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

Local<Array> convertMultiSZ(wchar_t *input, DWORD maxLength) {
  Local<Context> context = Nan::GetCurrentContext();
  Local<Array> result = Nan::New<Array>();
  wchar_t *start = input;
  wchar_t *ptr = start;
  int idx = 0;
  // double check. the list is supposed to end on a double zero termination but to ensure we don't overrun
  // the buffer, also verify we don't exceed the character count
  while ((*ptr != '\0') && ((ptr - start) < maxLength)) {
    size_t len = wcslen(ptr);
    result->Set(context, idx++, Nan::New<String>(toMB(ptr, CodePage::UTF8, len)).ToLocalChecked());
    ptr += len + 1;
  }

  return result;
}

NAN_METHOD(GetPrivateProfileSectionNames) {
  Isolate* isolate = Isolate::GetCurrent();

  try {
    if (info.Length() != 1) {
      Nan::ThrowError("Expected one parameter (fileName)");
      return;
    }

    String::Utf8Value fileName(isolate, info[0]);

    DWORD size = 32 * 1024;
    std::unique_ptr<wchar_t[]> buffer(new wchar_t[size]);

    DWORD charCount = ::GetPrivateProfileSectionNamesW(buffer.get(), size,
      toWC(*fileName, CodePage::UTF8, fileName.length()).c_str());

    info.GetReturnValue().Set(convertMultiSZ(buffer.get(), charCount));
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

NAN_METHOD(GetPrivateProfileString) {
  Isolate* isolate = Isolate::GetCurrent();

  try {
    if (info.Length() != 4) {
      Nan::ThrowError("Expected four parameters (section, key, default, fileName)");
      return;
    }

    std::wstring appName = toWC(info[0]);
    std::wstring keyName = toWC(info[1]);
    std::wstring defaultValue = toWC(info[2]);
    std::wstring fileName = toWC(info[3]);

    DWORD size = 32 * 1024;
    std::unique_ptr<wchar_t[]> buffer(new wchar_t[size]);

    bool repeat = true;

    DWORD charCount = 0;

    while (repeat) {
      charCount = ::GetPrivateProfileStringW(
        appName.c_str(), keyName.c_str(), defaultValue.c_str(),
        buffer.get(), size, fileName.c_str());
      if (charCount == 0) {
        DWORD error = ::GetLastError();
        if (error != ERROR_SUCCESS) {
          isolate->ThrowException(WinApiException(::GetLastError(), "GetPrivateProfileString", toMB(fileName.c_str(), CodePage::UTF8, fileName.length()).c_str()));
          return;
        }
      }
      if (charCount < size - 1) {
        repeat = false;
      }
      else {
        size *= 2;
        buffer.reset(new wchar_t[size]);
      }
    }
    info.GetReturnValue().Set(convertMultiSZ(buffer.get(), charCount));
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

NAN_METHOD(WritePrivateProfileString) {
  Isolate* isolate = Isolate::GetCurrent();

  try {
    if (info.Length() != 4) {
      Nan::ThrowError("Expected four parameters (section, key, value, fileName)");
      return;
    }

    String::Utf8Value appNameV8(isolate, info[0]);
    String::Utf8Value keyNameV8(isolate, info[1]);
    String::Utf8Value valueV8(isolate, info[2]);
    String::Utf8Value fileNameV8(isolate, info[3]);

    std::wstring appName = toWC(*appNameV8, CodePage::UTF8, appNameV8.length());
    std::wstring keyName = toWC(*keyNameV8, CodePage::UTF8, keyNameV8.length());
    std::wstring value = info[2]->IsNullOrUndefined() ? L"" : toWC(*valueV8, CodePage::UTF8, valueV8.length());
    std::wstring fileName = toWC(*fileNameV8, CodePage::UTF8, fileNameV8.length());

    BOOL res = ::WritePrivateProfileStringW(appName.c_str(), keyName.c_str(),
      info[2]->IsNullOrUndefined() ? nullptr : value.c_str(), fileName.c_str());

    if (!res) {
      isolate->ThrowException(WinApiException(::GetLastError(), "WritePrivateProfileString", *fileNameV8));
      return;
    }
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

static const std::unordered_map<std::string, HKEY> hkeyMap{
    { "HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT },
    { "HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG },
    { "HKEY_CURRENT_USER", HKEY_CURRENT_USER },
    { "HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE },
    { "HKEY_USERS", HKEY_USERS },
};

NAN_METHOD(WithRegOpen) {
  Isolate* isolate = Isolate::GetCurrent();

  try {
    if (info.Length() != 3) {
      Nan::ThrowError("Expected three parameters (hive, path, callback)");
      return;
    }

    String::Utf8Value hiveV8(isolate, info[0]);
    String::Utf8Value pathV8(isolate, info[1]);
    v8::Local<v8::Function> cb = info[2].As<v8::Function>();

    auto iter = hkeyMap.find(*hiveV8);
    if (iter == hkeyMap.end()) {
      Nan::ThrowError("Invalid hive specified");
      return;
    }
    std::wstring path = toWC(*pathV8, CodePage::UTF8, pathV8.length());

    HKEY key;
    LSTATUS res = ::RegOpenKeyExW(iter->second, path.c_str(), 0, KEY_READ, &key);
    if (res != ERROR_SUCCESS) {
      isolate->ThrowException(WinApiException(res, "WithRegOpen", *pathV8));
      return;
    }

    auto buf = CopyBuffer(reinterpret_cast<char*>(&key), sizeof(HKEY)).ToLocalChecked();
    Local<Value> argv[1] = { buf };
    AsyncResource async("callback");
    v8::Local<v8::Object> target = Nan::New<v8::Object>();
    async.runInAsyncScope(target, cb, 1, argv);

    ::RegCloseKey(key);
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

Local<String> regTypeToString(DWORD type) {
  switch (type) {
    case REG_BINARY: return "REG_BINARY"_n;
    case REG_DWORD: return "REG_DWORD"_n;
    case REG_DWORD_BIG_ENDIAN: return "REG_DWORD_BIG_ENDIAN"_n;
    case REG_EXPAND_SZ: return "REG_EXPAND_SZ"_n;
    case REG_LINK: return "REG_LINK"_n;
    case REG_MULTI_SZ: return "REG_MULTI_SZ"_n;
    case REG_NONE: return "REG_NONE"_n;
    case REG_QWORD: return "REG_QWORD"_n;
    case REG_SZ: return "REG_SZ"_n;
    default: throw std::runtime_error("invalid registry type");
  }
}

uint64_t toTimestamp(FILETIME ft)
{
  LARGE_INTEGER date;
  date.HighPart = ft.dwHighDateTime;
  date.LowPart = ft.dwLowDateTime;

  date.QuadPart -= (11644473600000 * 10000);

  return date.QuadPart / 10000;
}

HKEY decodeKeyParameter(Isolate *isolate, const Local<Value> &input) {
  HKEY key;
  if (input->IsString()) {
    String::Utf8Value hkeyStr(isolate, input);
    auto iter = hkeyMap.find(*hkeyStr);
    if (iter == hkeyMap.end()) {
      throw std::runtime_error("Invalid hive specified");
    }
    key = iter->second;
  }
  else {
    if (!input->IsUint8Array()) {
      throw std::runtime_error("Parameter expected to be a buffer (as generated by WithRegOpen)");
    }

    memcpy(&key, node::Buffer::Data(input), sizeof(HKEY));
  }

  return key;
}

NAN_METHOD(RegSetKeyValue) {
  Local<Context> context = Nan::GetCurrentContext();
  Isolate *isolate = context->GetIsolate();

  try {
    if (info.Length() != 4) {
      Nan::ThrowError("Expected four parameters (key, subkey, name, data)");
      return;
    }

    HKEY key = decodeKeyParameter(isolate, info[0]);

    String::Utf8Value pathV8(isolate, info[1]);
    String::Utf8Value nameV8(isolate, info[2]);

    std::wstring path = toWC(*pathV8, CodePage::UTF8, pathV8.length());
    std::wstring name = toWC(*nameV8, CodePage::UTF8, nameV8.length());

    DWORD type;
    DWORD dataSize = 0;

    LSTATUS res = ::RegGetValueW(key, path.c_str(), name.c_str(), RRF_RT_ANY, &type, nullptr, &dataSize);

    if (res != ERROR_SUCCESS) {
      // have to assume the type based on the input value
      if (info[3]->IsString()) {
        type = REG_SZ;
      }
      else if (info[3]->IsNumber()) {
        type = REG_DWORD;
      }
      else if (info[3]->IsUint8Array()) {
        type = REG_BINARY;
      }
    }

    res = ERROR_INVALID_DATA;
    switch (type) {
      case REG_SZ: {
        String::Utf8Value dataV8(isolate, info[3]);
        std::wstring data = toWC(*dataV8, CodePage::UTF8, dataV8.length());
        res = ::RegSetKeyValueW(key, path.c_str(), name.c_str(), type, data.c_str(), 0);
      } break;
      case REG_DWORD: {
        uint32_t data = info[3]->Uint32Value(context).ToChecked();
        res = ::RegSetKeyValueW(key, path.c_str(), name.c_str(), type, &data, 0);
      } break;
      case REG_BINARY: {
        Local<Array> arr = Local<Array>::Cast(info[3]);
        std::unique_ptr<uint8_t> buffer(new uint8_t[arr->Length()]);
        memcpy(buffer.get(), node::Buffer::Data(info[3]), arr->Length());
        res = ::RegSetKeyValueW(key, path.c_str(), name.c_str(), type, buffer.get(), 0);
      } break;
    }

    if (res != ERROR_SUCCESS) {
      isolate->ThrowException(WinApiException(res, "RegSetKeyValue", *pathV8));
    }
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

NAN_METHOD(RegGetValue) {
  Local<Context> context = Nan::GetCurrentContext();
  Isolate* isolate = context->GetIsolate();

  try {
    if (info.Length() != 3) {
      Nan::ThrowError("Expected three parameters (key, subkey, value)");
      return;
    }

    HKEY key = decodeKeyParameter(isolate, info[0]);

    String::Utf8Value pathV8(isolate, info[1]);
    String::Utf8Value valueV8(isolate, info[2]);

    std::wstring path = toWC(*pathV8, CodePage::UTF8, pathV8.length());
    std::wstring value = toWC(*valueV8, CodePage::UTF8, valueV8.length());

    DWORD type;
    DWORD dataSize = 0;

    LSTATUS res = ::RegGetValueW(key, path.c_str(), value.c_str(), RRF_RT_ANY, &type, nullptr, &dataSize);
    if (res != ERROR_SUCCESS) {
      isolate->ThrowException(WinApiException(res, "RegGetValue", *pathV8));
      return;
    }

    std::shared_ptr<uint8_t[]> buffer(new uint8_t[dataSize]);

    res = ::RegGetValueW(key, path.c_str(), value.c_str(), RRF_RT_ANY, &type, buffer.get(), &dataSize);

    if (res != ERROR_SUCCESS) {
      isolate->ThrowException(WinApiException(res, "RegGetValue", *pathV8));
      return;
    }

    Local<Object> result = Nan::New<Object>();
    result->Set(context, "type"_n, regTypeToString(type));

    switch (type) {
      case REG_BINARY: {
        result->Set(context, "value"_n, CopyBuffer(reinterpret_cast<char*>(buffer.get()), dataSize).ToLocalChecked());
      } break;
      case REG_DWORD: {
        DWORD val = *reinterpret_cast<DWORD*>(buffer.get());
        result->Set(context, "value"_n, Nan::New<Number>(val));
      } break;
      case REG_DWORD_BIG_ENDIAN: {
        union {
          DWORD val;
          char temp[4];
        };
        for (int i = 0; i < 4; ++i) {
          temp[i] = buffer[3 - i];
        }
        result->Set(context, "value"_n, Nan::New<Number>(val));
      } break;
      case REG_MULTI_SZ: {
        result->Set(context, "value"_n, convertMultiSZ(reinterpret_cast<wchar_t*>(buffer.get()), dataSize));
      } break;
      case REG_NONE: { } break;
      case REG_QWORD: {
        result->Set(context, "value"_n, Nan::New<Number>(static_cast<double>(*reinterpret_cast<uint64_t*>(buffer.get()))));
      } break;
      case REG_SZ:
      case REG_EXPAND_SZ:
      case REG_LINK: {
        const wchar_t *buf = reinterpret_cast<wchar_t*>(buffer.get());
        result->Set(context, "value"_n, Nan::New<String>(toMB(buf, CodePage::UTF8, (dataSize / sizeof(wchar_t)) - 1)).ToLocalChecked());
      } break;
    }

    info.GetReturnValue().Set(result);
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

NAN_METHOD(RegEnumKeys) {
  Isolate* isolate = Isolate::GetCurrent();

  try {
    if (info.Length() != 1) {
      Nan::ThrowError("Expected one parameters (key)");
      return;
    }

    if (!info[0]->IsUint8Array()) {
      Nan::ThrowError("Parameter expected to be a buffer (as generated by WithRegOpen)");
      return;
    }

    HKEY key;
    memcpy(&key, node::Buffer::Data(info[0]), sizeof(HKEY));

    DWORD numSubkeys;
    DWORD maxSubkeyLen;
    DWORD maxClassLen;
    LSTATUS res = RegQueryInfoKey(key, nullptr, nullptr, nullptr, &numSubkeys, &maxSubkeyLen, &maxClassLen, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (res != ERROR_SUCCESS) {
      isolate->ThrowException(WinApiException(res, "RegEnumKeys"));
      return;
    }

    Local<Context> context = Nan::GetCurrentContext();

    Local<Array> result = Nan::New<Array>();
    std::shared_ptr<wchar_t[]> keyBuffer(new wchar_t[maxSubkeyLen + 1]);
    std::shared_ptr<wchar_t[]> classBuffer(new wchar_t[maxClassLen + 1]);
    for (DWORD i = 0; i < numSubkeys; ++i) {
      DWORD keyLen = maxSubkeyLen + 1;
      DWORD classLen = maxClassLen + 1;
      FILETIME lastWritten;
      res = ::RegEnumKeyExW(key, i, keyBuffer.get(), &keyLen, nullptr, classBuffer.get(), &classLen, &lastWritten);
      if (res == ERROR_NO_MORE_ITEMS) {
        // https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw#remarks
        // Registry must've been manipulated since we called RegQueryInfoKey
        //  and the total number of subKeys has been reduced. (user uninstalled something ?)
        // Either way, we don't want to lose any information we've already collected and
        //  there's no point in continuing past this point so we break out of the for loop.
        break;
      }
      else if (res != ERROR_SUCCESS) {
        isolate->ThrowException(WinApiException(res, "RegEnumKeys"));
        return;
      }

      Local<Object> item = Nan::New<Object>();
      item->Set(context, "class"_n, Nan::New<String>(toMB(classBuffer.get(), CodePage::UTF8, classLen)).ToLocalChecked());
      item->Set(context, "key"_n, Nan::New<String>(toMB(keyBuffer.get(), CodePage::UTF8, keyLen)).ToLocalChecked());
      item->Set(context, "lastWritten"_n, Nan::New<Number>(static_cast<double>(toTimestamp(lastWritten))));
      result->Set(context, i, item);
    }

    info.GetReturnValue().Set(result);
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

NAN_METHOD(RegEnumValues) {
  Isolate* isolate = Isolate::GetCurrent();

  try {
    if (info.Length() != 1) {
      Nan::ThrowError("Expected one parameters (key)");
      return;
    }

    if (!info[0]->IsUint8Array()) {
      Nan::ThrowError("Parameter expected to be a buffer (as generated by WithRegOpen)");
      return;
    }

    HKEY key;
    memcpy(&key, node::Buffer::Data(info[0]), sizeof(HKEY));

    DWORD numValues;
    DWORD maxKeyLen;
    LSTATUS res = RegQueryInfoKey(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &numValues, &maxKeyLen, nullptr, nullptr, nullptr);
    if (res != ERROR_SUCCESS) {
      isolate->ThrowException(WinApiException(res, "RegEnumValues"));
      return;
    }

    Local<Context> context = Nan::GetCurrentContext();

    Local<Array> result = Nan::New<Array>();
    std::shared_ptr<wchar_t[]> keyBuffer(new wchar_t[maxKeyLen + 1]);
    for (DWORD i = 0; i < numValues; ++i) {
      DWORD keyLen = maxKeyLen + 1;
      DWORD type;
      res = ::RegEnumValueW(key, i, keyBuffer.get(), &keyLen, nullptr, &type, nullptr, nullptr);
      if (res != ERROR_SUCCESS) {
        isolate->ThrowException(WinApiException(res, "RegEnumValues"));
        return;
      }

      Local<Object> item = Nan::New<Object>();
      item->Set(context, "type"_n, regTypeToString(type));
      item->Set(context, "key"_n, Nan::New<String>(toMB(keyBuffer.get(), CodePage::UTF8, keyLen)).ToLocalChecked());
      result->Set(context, i, item);
    }

    info.GetReturnValue().Set(result);
  }
  catch (const std::exception &e) {
    Nan::ThrowError(e.what());
  }
}

static const std::unordered_map<std::string, DWORD> knownFolderFlags {
  { "default", KF_FLAG_DEFAULT },
  { "force_app_data_redirection", KF_FLAG_FORCE_APP_DATA_REDIRECTION },
  { "return_filter_redirection_target", KF_FLAG_RETURN_FILTER_REDIRECTION_TARGET },
  { "force_package_redirection", KF_FLAG_FORCE_PACKAGE_REDIRECTION },
  { "no_package_redirection", KF_FLAG_NO_PACKAGE_REDIRECTION },
  { "force_appcontainer_redirection", KF_FLAG_FORCE_APPCONTAINER_REDIRECTION },
  { "no_appcontainer_redirection", KF_FLAG_NO_APPCONTAINER_REDIRECTION },
  { "create", KF_FLAG_CREATE },
  { "dont_verify", KF_FLAG_DONT_VERIFY },
  { "dont_unexpand", KF_FLAG_DONT_UNEXPAND },
  { "no_alias", KF_FLAG_NO_ALIAS },
  { "init", KF_FLAG_INIT },
  { "default_path", KF_FLAG_DEFAULT_PATH },
  { "not_parent_relative", KF_FLAG_NOT_PARENT_RELATIVE },
  { "simple_idlist", KF_FLAG_SIMPLE_IDLIST },
  { "alias_only", KF_FLAG_ALIAS_ONLY }
};

static const std::unordered_map<std::string, REFKNOWNFOLDERID> knownFolders {
  { "AccountPictures", FOLDERID_AccountPictures },
  { "AddNan::NewPrograms", FOLDERID_AddNewPrograms },
  { "AdminTools", FOLDERID_AdminTools },
  { "AllAppMods", FOLDERID_AllAppMods },
  { "AppCaptures", FOLDERID_AppCaptures },
  { "AppDataDesktop", FOLDERID_AppDataDesktop },
  { "AppDataDocuments", FOLDERID_AppDataDocuments },
  { "AppDataFavorites", FOLDERID_AppDataFavorites },
  { "AppDataProgramData", FOLDERID_AppDataProgramData },
  { "AppUpdates", FOLDERID_AppUpdates },
  { "ApplicationShortcuts", FOLDERID_ApplicationShortcuts },
  { "AppsFolder", FOLDERID_AppsFolder },
  { "CDBurning", FOLDERID_CDBurning },
  { "CameraRoll", FOLDERID_CameraRoll },
  { "CameraRollLibrary", FOLDERID_CameraRollLibrary },
  { "ChangeRemovePrograms", FOLDERID_ChangeRemovePrograms },
  { "CommonAdminTools", FOLDERID_CommonAdminTools },
  { "CommonOEMLinks", FOLDERID_CommonOEMLinks },
  { "CommonPrograms", FOLDERID_CommonPrograms },
  { "CommonStartMenu", FOLDERID_CommonStartMenu },
  { "CommonStartMenuPlaces", FOLDERID_CommonStartMenuPlaces },
  { "CommonStartup", FOLDERID_CommonStartup },
  { "CommonTemplates", FOLDERID_CommonTemplates },
  { "ComputerFolder", FOLDERID_ComputerFolder },
  { "ConflictFolder", FOLDERID_ConflictFolder },
  { "ConnectionsFolder", FOLDERID_ConnectionsFolder },
  { "Contacts", FOLDERID_Contacts },
  { "ControlPanelFolder", FOLDERID_ControlPanelFolder },
  { "Cookies", FOLDERID_Cookies },
  { "CurrentAppMods", FOLDERID_CurrentAppMods },
  { "Desktop", FOLDERID_Desktop },
  { "DevelopmentFiles", FOLDERID_DevelopmentFiles },
  { "Device", FOLDERID_Device },
  { "DeviceMetadataStore", FOLDERID_DeviceMetadataStore },
  { "Documents", FOLDERID_Documents },
  { "DocumentsLibrary", FOLDERID_DocumentsLibrary },
  { "Downloads", FOLDERID_Downloads },
  { "Favorites", FOLDERID_Favorites },
  { "Fonts", FOLDERID_Fonts },
  { "GameTasks", FOLDERID_GameTasks },
  { "Games", FOLDERID_Games },
  { "History", FOLDERID_History },
  { "HomeGroup", FOLDERID_HomeGroup },
  { "HomeGroupCurrentUser", FOLDERID_HomeGroupCurrentUser },
  { "ImplicitAppShortcuts", FOLDERID_ImplicitAppShortcuts },
  { "InternetCache", FOLDERID_InternetCache },
  { "InternetFolder", FOLDERID_InternetFolder },
  { "Libraries", FOLDERID_Libraries },
  { "Links", FOLDERID_Links },
  { "LocalAppData", FOLDERID_LocalAppData },
  { "LocalAppDataLow", FOLDERID_LocalAppDataLow },
  { "LocalDocuments", FOLDERID_LocalDocuments },
  { "LocalDownloads", FOLDERID_LocalDownloads },
  { "LocalMusic", FOLDERID_LocalMusic },
  { "LocalPictures", FOLDERID_LocalPictures },
  { "LocalVideos", FOLDERID_LocalVideos },
  { "LocalizedResourcesDir", FOLDERID_LocalizedResourcesDir },
  { "Music", FOLDERID_Music },
  { "MusicLibrary", FOLDERID_MusicLibrary },
  { "NetHood", FOLDERID_NetHood },
  { "NetworkFolder", FOLDERID_NetworkFolder },
  { "Objects3D", FOLDERID_Objects3D },
  { "OneDrive", FOLDERID_OneDrive },
  { "OriginalImages", FOLDERID_OriginalImages },
  { "PhotoAlbums", FOLDERID_PhotoAlbums },
  { "Pictures", FOLDERID_Pictures },
  { "PicturesLibrary", FOLDERID_PicturesLibrary },
  { "Playlists", FOLDERID_Playlists },
  { "PrintHood", FOLDERID_PrintHood },
  { "PrintersFolder", FOLDERID_PrintersFolder },
  { "Profile", FOLDERID_Profile },
  { "ProgramData", FOLDERID_ProgramData },
  { "ProgramFiles", FOLDERID_ProgramFiles },
  { "ProgramFilesCommon", FOLDERID_ProgramFilesCommon },
  { "ProgramFilesCommonX64", FOLDERID_ProgramFilesCommonX64 },
  { "ProgramFilesCommonX86", FOLDERID_ProgramFilesCommonX86 },
  { "ProgramFilesX64", FOLDERID_ProgramFilesX64 },
  { "ProgramFilesX86", FOLDERID_ProgramFilesX86 },
  { "Programs", FOLDERID_Programs },
  { "Public", FOLDERID_Public },
  { "PublicDesktop", FOLDERID_PublicDesktop },
  { "PublicDocuments", FOLDERID_PublicDocuments },
  { "PublicDownloads", FOLDERID_PublicDownloads },
  { "PublicGameTasks", FOLDERID_PublicGameTasks },
  { "PublicLibraries", FOLDERID_PublicLibraries },
  { "PublicMusic", FOLDERID_PublicMusic },
  { "PublicPictures", FOLDERID_PublicPictures },
  { "PublicRingtones", FOLDERID_PublicRingtones },
  { "PublicUserTiles", FOLDERID_PublicUserTiles },
  { "PublicVideos", FOLDERID_PublicVideos },
  { "QuickLaunch", FOLDERID_QuickLaunch },
  { "Recent", FOLDERID_Recent },
  { "RecordedCalls", FOLDERID_RecordedCalls },
  { "RecordedTVLibrary", FOLDERID_RecordedTVLibrary },
  { "RecycleBinFolder", FOLDERID_RecycleBinFolder },
  { "ResourceDir", FOLDERID_ResourceDir },
  { "RetailDemo", FOLDERID_RetailDemo },
  { "Ringtones", FOLDERID_Ringtones },
  { "RoamedTileImages", FOLDERID_RoamedTileImages },
  { "RoamingAppData", FOLDERID_RoamingAppData },
  { "RoamingTiles", FOLDERID_RoamingTiles },
  { "SEARCH_CSC", FOLDERID_SEARCH_CSC },
  { "SEARCH_MAPI", FOLDERID_SEARCH_MAPI },
  { "SampleMusic", FOLDERID_SampleMusic },
  { "SamplePictures", FOLDERID_SamplePictures },
  { "SamplePlaylists", FOLDERID_SamplePlaylists },
  { "SampleVideos", FOLDERID_SampleVideos },
  { "SavedGames", FOLDERID_SavedGames },
  { "SavedPictures", FOLDERID_SavedPictures },
  { "SavedPicturesLibrary", FOLDERID_SavedPicturesLibrary },
  { "SavedSearches", FOLDERID_SavedSearches },
  { "Screenshots", FOLDERID_Screenshots },
  { "SearchHistory", FOLDERID_SearchHistory },
  { "SearchHome", FOLDERID_SearchHome },
  { "SearchTemplates", FOLDERID_SearchTemplates },
  { "SendTo", FOLDERID_SendTo },
  { "SidebarDefaultParts", FOLDERID_SidebarDefaultParts },
  { "SidebarParts", FOLDERID_SidebarParts },
  { "SkyDrive", FOLDERID_SkyDrive },
  { "SkyDriveCameraRoll", FOLDERID_SkyDriveCameraRoll },
  { "SkyDriveDocuments", FOLDERID_SkyDriveDocuments },
  { "SkyDriveMusic", FOLDERID_SkyDriveMusic },
  { "SkyDrivePictures", FOLDERID_SkyDrivePictures },
  { "StartMenu", FOLDERID_StartMenu },
  { "StartMenuAllPrograms", FOLDERID_StartMenuAllPrograms },
  { "Startup", FOLDERID_Startup },
  { "SyncManagerFolder", FOLDERID_SyncManagerFolder },
  { "SyncResultsFolder", FOLDERID_SyncResultsFolder },
  { "SyncSetupFolder", FOLDERID_SyncSetupFolder },
  { "System", FOLDERID_System },
  { "SystemX86", FOLDERID_SystemX86 },
  { "Templates", FOLDERID_Templates },
  { "UserPinned", FOLDERID_UserPinned },
  { "UserProfiles", FOLDERID_UserProfiles },
  { "UserProgramFiles", FOLDERID_UserProgramFiles },
  { "UserProgramFilesCommon", FOLDERID_UserProgramFilesCommon },
  { "UsersFiles", FOLDERID_UsersFiles },
  { "UsersLibraries", FOLDERID_UsersLibraries },
  { "Videos", FOLDERID_Videos },
  { "VideosLibrary", FOLDERID_VideosLibrary },
  { "Windows", FOLDERID_Windows },
};

NAN_METHOD(SHGetKnownFolderPath) {
  Isolate* isolate = Isolate::GetCurrent();
  Local<Context> context = Nan::GetCurrentContext();

  if ((info.Length() < 1) || (info.Length() > 2)) {
    Nan::ThrowError("Expected 1-2 parameters (folderId, flag)");
    return;
  }

  KNOWNFOLDERID folder;
  DWORD flag = KF_FLAG_DEFAULT;

  {
    String::Utf8Value folderIdV8(isolate, info[0]);
    auto folderId = knownFolders.find(*folderIdV8);

    if (folderId == knownFolders.end()) {
      Nan::ThrowError("Invalid folder id");
      return;
    }
    folder = folderId->second;
  }

  if (info.Length() > 1) {
    if (!info[1]->IsArray()) {
      Nan::ThrowError("Invalid flags, expected to be an array");
      return;
    }
    Local<Array> flagList = Local<Array>::Cast(info[1]);

    for (uint32_t i = 0; i < flagList->Length(); ++i) {
      v8::String::Utf8Value flagV8(isolate, flagList->Get(context, i).ToLocalChecked());

      auto flagIter = knownFolderFlags.find(*flagV8);
      if (flagIter == knownFolderFlags.end()) {
        Nan::ThrowError("Invalid folder flag");
        return;
      }

      if (flagIter != knownFolderFlags.end()) {
        flag |= flagIter->second;
      }
    }
  }

  PWSTR result;

  HRESULT res = SHGetKnownFolderPath(folder, flag, nullptr, &result);

  if (FAILED(res)) {
    isolate->ThrowException(WinApiException(res, "SHGetKnownFolderPath"));
    return;
  }

  info.GetReturnValue().Set(Nan::New<String>(toMB(result, CodePage::UTF8, wcslen(result))).ToLocalChecked());

  CoTaskMemFree(result);
}

NAN_METHOD(GetModuleList) {
  Isolate* isolate = Isolate::GetCurrent();

  Local<Context> context = Nan::GetCurrentContext();
  
  auto convertME = [&context](const MODULEENTRY32W &mod) -> Local<Object> {
    Local<Object> item = Nan::New<Object>();
    item->Set(context, "baseAddr"_n, Nan::New<Number>(reinterpret_cast<uint64_t>(mod.modBaseAddr)));
    item->Set(context, "baseSize"_n, Nan::New<Number>(mod.modBaseSize));
    item->Set(context, "module"_n, toV8(mod.szModule));
    item->Set(context, "exePath"_n, toV8(mod.szExePath));
    return item;
  };

  if (info.Length() != 1) {
    Nan::ThrowError("Expected 1 parameter (process id)");
    return;
  }

  Local<Array> modules = Nan::New<Array>();

  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, info[0]->Uint32Value(context).ToChecked());
  MODULEENTRY32W me32;
  me32.dwSize = sizeof(MODULEENTRY32W);
  int idx = 0;
  bool more = ::Module32FirstW(snap, &me32);
  while (more) {
    modules->Set(context, idx++, convertME(me32));
    more = ::Module32NextW(snap, &me32);
  }

  info.GetReturnValue().Set(modules);
}

NAN_METHOD(GetProcessList) {
  Local<Context> context = Nan::GetCurrentContext();
  
  auto convertPE = [&context](const PROCESSENTRY32W &process) -> Local<Object> {
    Local<Object> item = Nan::New<Object>();
    item->Set(context, "numThreads"_n, Nan::New<Number>(process.cntThreads));
    item->Set(context, "processID"_n, Nan::New<Number>(process.th32ProcessID));
    item->Set(context, "parentProcessID"_n, Nan::New<Number>(process.th32ParentProcessID));
    item->Set(context, "priClassBase"_n, Nan::New<Number>(process.pcPriClassBase));
    item->Set(context, "exeFile"_n, toV8(process.szExeFile));
    return item;
  };

  Local<Array> result = Nan::New<Array>();
  int idx = 0;
  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32W pe32;

  if (snap != INVALID_HANDLE_VALUE) {
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    bool more = ::Process32FirstW(snap, &pe32);
    while (more) {
      result->Set(context, idx++, convertPE(pe32));
      more = ::Process32NextW(snap, &pe32);
    }
    ::CloseHandle(snap);
  }

  info.GetReturnValue().Set(result);
}

NAN_METHOD(GetProcessWindowList) {
  if (info.Length() != 1) {
    Nan::ThrowError("Expected 1 parameter (the process id)");
    return;
  }

  Isolate* isolate = Isolate::GetCurrent();
  Local<Context> context = Nan::GetCurrentContext();

  DWORD pid = info[0].As<Number>()->Uint32Value(context).FromMaybe(0);

  Local<Array> res = Nan::New<Array>();
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

    WINDOWINFO info;
    GetWindowInfo(windowIter, &info);

    uint64_t winId = reinterpret_cast<uint64_t>(windowIter);
    if (((info.dwStyle & WS_CAPTION) != 0) && ((info.dwStyle & WS_CHILD) == 0)) {
      res->Set(context, resIdx++, Nan::New<Number>(winId));
    }
  }

  info.GetReturnValue().Set(res);
}

NAN_METHOD(SetForegroundWin) {
  if (info.Length() != 1) {
    Nan::ThrowError("Expected 1 parameter (window id)");
    return;
  }

  Isolate* isolate = Isolate::GetCurrent();
  Local<Context> context = Nan::GetCurrentContext();

  uint64_t winId = info[0].As<Number>()->Uint32Value(context).FromMaybe(0);

  HWND hwnd = reinterpret_cast<HWND>(winId);

  if (::IsIconic(hwnd)) {
    ::ShowWindow(hwnd, 9);
  }

  BOOL res = ::SetForegroundWindow(hwnd);

  info.GetReturnValue().Set(res);
}

NAN_METHOD(SetProcessPreferredUILanguages) {
  Isolate* isolate = Isolate::GetCurrent();
  Local<Context> context = Nan::GetCurrentContext();

  if (info.Length() != 1) {
    Nan::ThrowError("Expected 1 parameter (the list of language codes, in the format \"en-US\")");
    return;
  }

  Local<Array> languages = Local<Array>::Cast(info[0]);

  std::vector<wchar_t> buffer;
  size_t offset = 0;

  ULONG count = languages->Length();

  for (ULONG i = 0; i < count; ++i) {
    v8::String::Utf8Value langV8(isolate, languages->Get(context, i).ToLocalChecked());
    const std::wstring langU16 = toWC(*langV8, CodePage::UTF8, langV8.length());
    buffer.resize(offset + langU16.length() + 2);
    wcsncpy(&buffer[offset], langU16.c_str(), langU16.length() + 1);
    offset += langU16.length() + 1;
  }

  buffer[offset] = '\0';

  if (!SetProcessPreferredUILanguages(MUI_LANGUAGE_NAME, &buffer[0], &count)) {
    isolate->ThrowException(WinApiException(::GetLastError(), "SetProcessPreferredUILanguages"));
  }
}

void GetPreferredLanguage(const Nan::FunctionCallbackInfo<v8::Value> &info,
                          BOOL (*func)(DWORD, PULONG, PZZWSTR, PULONG),
                          const char *funcName) {
  Isolate* isolate = Isolate::GetCurrent();
  Local<Context> context = Nan::GetCurrentContext();

  ULONG numLanguages = 0;
  std::vector<wchar_t> buffer;
  ULONG bufferSize = 0;
  if (!func(MUI_LANGUAGE_NAME, &numLanguages, nullptr, &bufferSize)) {
    isolate->ThrowException(WinApiException(::GetLastError(), funcName));
    return;
  }

  buffer.resize(bufferSize);

  if (!func(MUI_LANGUAGE_NAME, &numLanguages, &buffer[0], &bufferSize)) {
    isolate->ThrowException(WinApiException(::GetLastError(), funcName));
    return;
  }

  Local<Array> result = Nan::New<Array>();

  wchar_t *buf = &buffer[0];

  for (ULONG i = 0; i < numLanguages; ++i) {
    size_t len = wcslen(buf);
    result->Set(context, i, Nan::New(toMB(buf, CodePage::UTF8, len).c_str()).ToLocalChecked());
    buf += len + 1;
  }

  info.GetReturnValue().Set(result);
}

NAN_METHOD(GetUserPreferredUILanguages) {
  GetPreferredLanguage(info, &GetUserPreferredUILanguages, "GetUserPreferredUILanguages");
}

NAN_METHOD(GetSystemPreferredUILanguages) {
  GetPreferredLanguage(info, &GetSystemPreferredUILanguages, "GetSystemPreferredUILanguages");
}

NAN_METHOD(GetProcessPreferredUILanguages) {
  GetPreferredLanguage(info, &GetProcessPreferredUILanguages, "GetProcessPreferredUILanguages");
}

ITaskService *getScheduler(Isolate *isolate) {
  ITaskService *sched;
  HRESULT res = CoCreateInstance(CLSID_TaskScheduler,
    nullptr,
    CLSCTX_INPROC_SERVER,
    IID_ITaskService,
    (void **)&sched);

  if (FAILED(res)) {
    isolate->ThrowException(HResultException(res, "CoCreateInstance"));
    return nullptr;
  }

  res = sched->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());

  if (FAILED(res)) {
    isolate->ThrowException(HResultException(res, "ITaskService::Connect"));
    return nullptr;
  }

  return sched;
}

template<typename T>
using clean_ptr = std::unique_ptr<T, std::function<void(T*)>>;

template<typename T, typename FuncT>
bool clean_ptr_assign(Isolate *isolate, clean_ptr<T> &target, const FuncT &cb, const char *funcName, bool throwOnError = true) {
  T *temp = nullptr;
  HRESULT res = cb(&temp);
  if (SUCCEEDED(res)) {
    target.reset(temp);
    return true;
  }
  else {
    if (throwOnError) {
      isolate->ThrowException(HResultException(res, funcName));
    }
    return false;
  }
}

#define ASSIGN(ctx, obj, params, fieldName, convFunc) {\
  Local<Value> val = params->Get(ctx, # fieldName ## _n).ToLocalChecked();\
  if (!val->IsNullOrUndefined()) {\
    obj->put_ ## fieldName ## (convFunc(ctx, val));\
  }\
}


Local<Value> toV8(VARIANT_BOOL input) {
  return Nan::New<Boolean>(static_cast<bool>(input));
}

Local<Value> toV8(LONG input) {
  return Nan::New<Number>(input);
}

#define COMTOV8(ctx, comObj, v8Obj, key, type) {\
    type temp; \
    comObj->get_ ## key ## (&temp);\
    v8Obj->Set(ctx, # key ## _n, toV8(temp));\
}

#define TOSTRING(ctx, input) toWC(input).c_str()
#define TOBSTRING(ctx, input) CComBSTR(toWC(input).c_str())

bool toBool(const Local<Context> context, const Local<Value> input) {
  return input->IsTrue();
}

Local<Object> getObject(const Local<Context> &context, const Local<Object> &obj, const Local<String> key) {
  Local<Value> temp = obj->Get(context, key).ToLocalChecked();
  if (temp->IsNullOrUndefined()) {
    return Nan::New<Object>();
  }
  return temp->ToObject(context).ToLocalChecked();
}

std::wstring getOr(const Local<Context> &context, const Local<Object> &obj, const Local<String> &key, LPCWSTR fallback) {
  return obj->Has(context, key).ToChecked()
      ? toWC(obj->Get(context, key).ToLocalChecked())
      : fallback;
}

template<typename T>
void CoRelease(T *ptr) {
  ptr->Release();
}

bool addAction(Local<Context> context, ITaskDefinition *task, const Local<Object> &settings) {
  Isolate *isolate = context->GetIsolate();

  clean_ptr<IActionCollection> actions(nullptr, CoRelease<IActionCollection>);
  if (!clean_ptr_assign(isolate, actions, [&](IActionCollection **out) {
    return task->get_Actions(out);
    }, "IActionCollection::get_Actions")) {
    return false;
  }

  clean_ptr<IAction> action(nullptr, CoRelease<IAction>);
  if (!clean_ptr_assign(isolate, action, [&](IAction **out) {
    return actions->Create(TASK_ACTION_EXEC, out);
    }, "IActions::Create")) {
    return false;
  }

  clean_ptr<IExecAction> exec(nullptr, CoRelease<IExecAction>);
  if (!clean_ptr_assign(isolate, exec, [&](IExecAction **out) {
    return action->QueryInterface(IID_IExecAction, (void**)out);
    }, "IAction::QueryInterface")) {
    return false;
  }

  ASSIGN(context, exec, settings, Path, TOBSTRING);
  ASSIGN(context, exec, settings, Arguments, TOBSTRING);
  ASSIGN(context, exec, settings, Id, TOBSTRING);
  ASSIGN(context, exec, settings, WorkingDirectory, TOBSTRING);

  return true;
}

TASK_LOGON_TYPE convLogonType(Local<Context> context, const Local<Value> &input) {
  static const std::unordered_map<std::string, TASK_LOGON_TYPE> logonTypeMap{
      { "none", TASK_LOGON_NONE },
      { "password", TASK_LOGON_PASSWORD },
      { "s4u", TASK_LOGON_S4U },
      { "interactive_token", TASK_LOGON_INTERACTIVE_TOKEN },
      { "group", TASK_LOGON_GROUP },
      { "service_account", TASK_LOGON_SERVICE_ACCOUNT },
      { "interactive_token_or_password", TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD },
  };

  String::Utf8Value inputStr(context->GetIsolate(), input);

  auto iter = logonTypeMap.find(*inputStr);
  if (iter != logonTypeMap.end()) {
    return iter->second;
  }
  else {
    return TASK_LOGON_NONE;
  }
}

TASK_RUNLEVEL_TYPE convRunLevel(Local<Context> context, const Local<Value> &input) {
  static const std::unordered_map<std::string, TASK_RUNLEVEL_TYPE> logonTypeMap{
      { "lua", TASK_RUNLEVEL_LUA },
      { "highest", TASK_RUNLEVEL_HIGHEST },
  };

  String::Utf8Value inputStr(context->GetIsolate(), input);

  auto iter = logonTypeMap.find(*inputStr);
  if (iter != logonTypeMap.end()) {
    return iter->second;
  }
  else {
    return TASK_RUNLEVEL_LUA;
  }
}



NAN_METHOD(CreateTask) {
  Local<Context> context = Nan::GetCurrentContext();
  Isolate *isolate = context->GetIsolate();

  if (info.Length() != 2) {
    Nan::ThrowError("Expected 2 parameters (task name, task settings)");
    return;
  }

  clean_ptr<ITaskService> sched(getScheduler(isolate),
    [](ITaskService *ptr) { ptr->Release(); });

  if (sched == nullptr) {
    return;
  }

  Local<Object> parameters = info[1]->ToObject(context).ToLocalChecked();

  clean_ptr<ITaskFolder> rootFolder(nullptr, CoRelease<ITaskFolder>);
  if (!clean_ptr_assign(isolate, rootFolder, [&](ITaskFolder **out) {
    // TODO: allow tasks in folders
    return sched->GetFolder(_bstr_t("\\"), out);
    }, "ITaskService::GetFolder")) {
    return;
  }

  clean_ptr<ITaskDefinition> task(nullptr, CoRelease<ITaskDefinition>);
  if (!clean_ptr_assign(isolate, task, [&](ITaskDefinition **out) {
    return sched->NewTask(0, out);
    }, "ITaskScheduler::Nan::NewTask")) {
    return;
  }

  Local<Object> registrationInfoConf = getObject(context, parameters, "registrationInfo"_n);
  if (!registrationInfoConf.IsEmpty()) {
    clean_ptr<IRegistrationInfo> registrationInfo(nullptr, CoRelease<IRegistrationInfo>);
    if (!clean_ptr_assign(isolate, registrationInfo, [&](IRegistrationInfo **out) {
      return task->get_RegistrationInfo(out);
      }, "ITaskDefinition::get_RegistrationInfo")) {
      return;
    }

    ASSIGN(context, registrationInfo, registrationInfoConf, Author, TOBSTRING);
    ASSIGN(context, registrationInfo, registrationInfoConf, Date, TOBSTRING);
    ASSIGN(context, registrationInfo, registrationInfoConf, Description, TOBSTRING);
    ASSIGN(context, registrationInfo, registrationInfoConf, Documentation, TOBSTRING);
    ASSIGN(context, registrationInfo, registrationInfoConf, Source, TOBSTRING);
    ASSIGN(context, registrationInfo, registrationInfoConf, URI, TOBSTRING);
  }


  Local<Object> taskSettingsConf = getObject(context, parameters, "taskSettings"_n);
  if (!taskSettingsConf.IsEmpty()) {
    clean_ptr<ITaskSettings> taskSettings(nullptr, CoRelease<ITaskSettings>);
    if (!clean_ptr_assign(isolate, taskSettings, [&](ITaskSettings **out) {
      return task->get_Settings(out);
      }, "ITaskDefinition::get_Settings")) {
      return;
    }
    ASSIGN(context, taskSettings, taskSettingsConf, AllowDemandStart, toBool);
  }

  Local<Object> principalConf = getObject(context, parameters, "principal"_n);
  if (!principalConf.IsEmpty()) {
    clean_ptr<IPrincipal> principal(nullptr, CoRelease<IPrincipal>);
    if (!clean_ptr_assign(isolate, principal, [&](IPrincipal **out) {
      return task->get_Principal(out);
      }, "ITaskDefinition::get_Principal")) {
      return;
    }
    ASSIGN(context, principal, principalConf, DisplayName, TOBSTRING);
    ASSIGN(context, principal, principalConf, GroupId, TOBSTRING);
    ASSIGN(context, principal, principalConf, Id, TOBSTRING);
    ASSIGN(context, principal, principalConf, UserId, TOBSTRING);
    ASSIGN(context, principal, principalConf, LogonType, convLogonType);
    ASSIGN(context, principal, principalConf, RunLevel, convRunLevel);
  }

  v8::Local<Value> actionsVal = parameters->Get(context, "actions"_n).ToLocalChecked();
  if (!actionsVal->IsNullOrUndefined()) {
    int idx = 0;
    Local<Object> actions = actionsVal->ToObject(context).ToLocalChecked();
    while (true) {
      v8::Local<Value> action = actions->Get(context, idx++).ToLocalChecked();
      if (action->IsNullOrUndefined()) {
        break;
      }
      if (!addAction(context, task.get(), action->ToObject(context).ToLocalChecked())) {
        return;
      }
    }
  }

  // TODO: Add support for triggers

  clean_ptr<IRegisteredTask> registeredTask(nullptr, CoRelease<IRegisteredTask>);
  if (!clean_ptr_assign(isolate, registeredTask, [&](IRegisteredTask **out) {
    std::wstring taskName = toWC(info[0]);
    std::wstring userName = toWC(parameters->Get(context, "user"_n).ToLocalChecked());
    return rootFolder->RegisterTaskDefinition(_bstr_t(taskName.c_str()), task.get(), TASK_CREATE_OR_UPDATE,
      _variant_t(userName.c_str()), _variant_t(), TASK_LOGON_NONE, _variant_t(L""), out);
    }, "ITaskFolder::RegisterTaskDefinition")) {
  }
}

NAN_METHOD(GetTasks) {
  Isolate* isolate = Isolate::GetCurrent();
  Local<Context> context = Nan::GetCurrentContext();

  static const int TASKS_TO_RETRIEVE = 5;

  if (info.Length() > 1) {
    Nan::ThrowError("Expected zero or one parameters (if set, the specified folder will be listed instead of the rrot)");
    return;
  }

  clean_ptr<ITaskService> sched(getScheduler(isolate), [](ITaskService *ptr) { ptr->Release(); });
  if (sched == nullptr) {
    return;
  }

  clean_ptr<ITaskFolder> rootFolder(nullptr, CoRelease<ITaskFolder>);
  if (!clean_ptr_assign(isolate, rootFolder, [&](ITaskFolder **out) {
    std::wstring folder = info.Length() == 0 ? L"\\" : toWC(info[0]);
    return sched->GetFolder(_bstr_t(folder.c_str()), out);
    }, "ITaskService::GetFolder")) {
    return;
  }

  clean_ptr<IRegisteredTaskCollection> tasks(nullptr, CoRelease<IRegisteredTaskCollection>);
  if (!clean_ptr_assign(isolate, tasks, [&](IRegisteredTaskCollection **out) {
    return rootFolder->GetTasks(0, out);
    }, "ITaskFolder->GetTasks")) {
    return;
  }

  LONG count;
  tasks->get_Count(&count);

  Local<Array> result = Nan::New<Array>();
  int32_t resultIdx = 0;

  for (LONG i = 0; i < count; ++i) {
    DWORD numFetched = 0;
    clean_ptr<IRegisteredTask> task(nullptr, CoRelease<IRegisteredTask>);
    if (clean_ptr_assign(isolate, task, [&](IRegisteredTask **out) {
      // 1-based indices? WTF is this madness
      return tasks->get_Item(_variant_t(i + 1, VT_I4), out);
      }, "IRegisteredTaskCollection::get_Item", false)) {
      Local<Object> item = Nan::New<Object>();
      COMTOV8(context, task, item, Name, CComBSTR);
      COMTOV8(context, task, item, Enabled, VARIANT_BOOL);
      COMTOV8(context, task, item, LastTaskResult, LONG);

      result->Set(context, resultIdx++, item);
    }
  }

  info.GetReturnValue().Set(result);
}

NAN_METHOD(DeleteTask) {
  Isolate* isolate = Isolate::GetCurrent();
  Local<Context> context = Nan::GetCurrentContext();

  static const int TASKS_TO_RETRIEVE = 5;

  if (info.Length() != 1) {
    Nan::ThrowError("Expected 1 parameter (the task name)");
    return;
  }

  clean_ptr<ITaskService> sched(getScheduler(isolate), [](ITaskService *ptr) { ptr->Release(); });

  if (sched == nullptr) {
    return;
  }

  clean_ptr<ITaskFolder> rootFolder(nullptr, CoRelease<ITaskFolder>);
  if (!clean_ptr_assign(isolate, rootFolder, [&](ITaskFolder **out) {
    // TODO: allow tasks in folders
    return sched->GetFolder(_bstr_t("\\"), out);
    }, "ITaskService::GetFolder")) {
    return;
  }

  std::wstring taskName = toWC(info[0]);
  HRESULT res = rootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);

  if (FAILED(res)) {
    isolate->ThrowException(HResultException(res, "ITaskFolder::Delete"));
    return;
  }
}

void withTask(const Local<Context> context, const std::wstring &taskName, std::function<void(IRegisteredTask *)> cb) {
  Isolate* isolate = context->GetIsolate();

  clean_ptr<ITaskService> sched(getScheduler(isolate), [](ITaskService *ptr) { ptr->Release(); });
  if (sched == nullptr) {
    return;
  }

  clean_ptr<ITaskFolder> rootFolder(nullptr, CoRelease<ITaskFolder>);
  if (!clean_ptr_assign(isolate, rootFolder, [&](ITaskFolder **out) {
    // TODO: allow tasks in folders
    return sched->GetFolder(_bstr_t("\\"), out);
    }, "ITaskService::GetFolder")) {
    return;
  }

  clean_ptr<IRegisteredTask> task(nullptr, CoRelease<IRegisteredTask>);
  if (!clean_ptr_assign(isolate, task, [&](IRegisteredTask **out) {
    return rootFolder->GetTask(_bstr_t(taskName.c_str()), out);
    }, "ITaskFolder::GetTask")) {
    return;
  }

  cb(task.get());
}

NAN_METHOD(RunTask) {
  Local<Context> context = Nan::GetCurrentContext();
  Isolate* isolate = context->GetIsolate();

  if (info.Length() != 1) {
    Nan::ThrowError("Expected 1 parameter (the task name)");
    return;
  }

  std::wstring taskName = toWC(info[0]);
  withTask(context, taskName, [isolate](IRegisteredTask *task) {
    clean_ptr<IRunningTask> running(nullptr, CoRelease<IRunningTask>);
    if (!clean_ptr_assign(isolate, running, [&](IRunningTask **out) {
      return task->Run(CComVariant(), out);
      }, "IRegisteredTask::Run")) {
      return;
    }
    });
}

NAN_METHOD(StopTask) {
  Local<Context> context = Nan::GetCurrentContext();
  Isolate* isolate = context->GetIsolate();

  if (info.Length() != 1) {
    Nan::ThrowError("Expected 1 parameter (the task name)");
    return;
  }

  std::wstring taskName = toWC(info[0]);
  withTask(context, taskName, [isolate](IRegisteredTask *task) {
    clean_ptr<IRunningTask> running(nullptr, CoRelease<IRunningTask>);
    if (!clean_ptr_assign(isolate, running, [&](IRunningTask **out) {
      return task->Stop(0);
      }, "IRegisteredTask::Stop")) {
      return;
    }
    });
}

NAN_METHOD(IsThisWine) {
  Isolate* isolate = Isolate::GetCurrent();

  HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));
  FARPROC addr = GetProcAddress(ntdll, "wine_get_version");

  info.GetReturnValue().Set(addr != nullptr);
}

NAN_MODULE_INIT(Init) {
  HRESULT hr = ::CoInitialize(nullptr);

  Nan::Set(target, "SetFileAttributes"_n,
    GetFunction(Nan::New<FunctionTemplate>(SetFileAttributes)).ToLocalChecked());
  Nan::Set(target, "GetDiskFreeSpaceEx"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetDiskFreeSpaceEx)).ToLocalChecked());
  Nan::Set(target, "GetVolumePathName"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetVolumePathName)).ToLocalChecked());
  Nan::Set(target, "ShellExecuteEx"_n,
    GetFunction(Nan::New<FunctionTemplate>(ShellExecuteEx)).ToLocalChecked());

  Nan::Set(target, "GetPrivateProfileSection"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetPrivateProfileSection)).ToLocalChecked());
  Nan::Set(target, "GetPrivateProfileSectionNames"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetPrivateProfileSectionNames)).ToLocalChecked());
  Nan::Set(target, "GetPrivateProfileString"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetPrivateProfileString)).ToLocalChecked());
  Nan::Set(target, "WritePrivateProfileString"_n,
    GetFunction(Nan::New<FunctionTemplate>(WritePrivateProfileString)).ToLocalChecked());

  Nan::Set(target, "WithRegOpen"_n,
    GetFunction(Nan::New<FunctionTemplate>(WithRegOpen)).ToLocalChecked());
  Nan::Set(target, "RegGetValue"_n,
    GetFunction(Nan::New<FunctionTemplate>(RegGetValue)).ToLocalChecked());
  Nan::Set(target, "RegSetKeyValue"_n,
    GetFunction(Nan::New<FunctionTemplate>(RegSetKeyValue)).ToLocalChecked());
  Nan::Set(target, "RegEnumKeys"_n,
    GetFunction(Nan::New<FunctionTemplate>(RegEnumKeys)).ToLocalChecked());
  Nan::Set(target, "RegEnumValues"_n,
    GetFunction(Nan::New<FunctionTemplate>(RegEnumValues)).ToLocalChecked());

  Nan::Set(target, "SHGetKnownFolderPath"_n,
    GetFunction(Nan::New<FunctionTemplate>(SHGetKnownFolderPath)).ToLocalChecked());

  Nan::Set(target, "GetProcessList"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetProcessList)).ToLocalChecked());
  Nan::Set(target, "GetModuleList"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetModuleList)).ToLocalChecked());

  Nan::Set(target, "GetProcessWindowList"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetProcessWindowList)).ToLocalChecked());
  Nan::Set(target, "SetForegroundWindow"_n,
    GetFunction(Nan::New<FunctionTemplate>(SetForegroundWin)).ToLocalChecked());

  Nan::Set(target, "GetUserPreferredUILanguages"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetUserPreferredUILanguages)).ToLocalChecked());
  Nan::Set(target, "GetSystemPreferredUILanguages"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetSystemPreferredUILanguages)).ToLocalChecked());
  Nan::Set(target, "GetProcessPreferredUILanguages"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetProcessPreferredUILanguages)).ToLocalChecked());
  Nan::Set(target, "SetProcessPreferredUILanguages"_n,
    GetFunction(Nan::New<FunctionTemplate>(SetProcessPreferredUILanguages)).ToLocalChecked());

  Nan::Set(target, "CreateTask"_n,
    GetFunction(Nan::New<FunctionTemplate>(CreateTask)).ToLocalChecked());
  Nan::Set(target, "GetTasks"_n,
    GetFunction(Nan::New<FunctionTemplate>(GetTasks)).ToLocalChecked());
  Nan::Set(target, "DeleteTask"_n,
    GetFunction(Nan::New<FunctionTemplate>(DeleteTask)).ToLocalChecked());
  Nan::Set(target, "RunTask"_n,
    GetFunction(Nan::New<FunctionTemplate>(RunTask)).ToLocalChecked());
  Nan::Set(target, "StopTask"_n,
    GetFunction(Nan::New<FunctionTemplate>(StopTask)).ToLocalChecked());

  Nan::Set(target, "IsThisWine"_n,
    GetFunction(Nan::New<FunctionTemplate>(IsThisWine)).ToLocalChecked());


  node::AtExit([](void *arg) {
    ::CoUninitialize();
    });
}

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(winapi, Init)
#else
NODE_MODULE(winapi, Init)
#endif

