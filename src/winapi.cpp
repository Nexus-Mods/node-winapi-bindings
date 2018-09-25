#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <unordered_map>
#include <nan.h>
#include <iostream>
#include "string_cast.h"

using namespace Nan;
using namespace v8;

inline v8::Local<v8::Value> WinApiException(
  DWORD lastError
  , const char *func = nullptr
  , const char* path = nullptr) {

  return node::WinapiErrnoException(v8::Isolate::GetCurrent(), lastError, func, nullptr, path);
}

Local<String> operator "" _n(const char *input, size_t) {
  return Nan::New(input).ToLocalChecked();
}

DWORD mapAttributes(Local<Array> input) {
  static const std::unordered_map<std::string, DWORD> attributeMap{
    { "archive", FILE_ATTRIBUTE_ARCHIVE },
    { "hidden", FILE_ATTRIBUTE_HIDDEN },
    { "normal", FILE_ATTRIBUTE_NORMAL },
    { "not_content_indexed", FILE_ATTRIBUTE_NOT_CONTENT_INDEXED },
    { "readonly", FILE_ATTRIBUTE_READONLY },
    { "temporary", FILE_ATTRIBUTE_TEMPORARY },
  };

  DWORD res = 0;
  for (uint32_t i = 0; i < input->Length(); ++i) {
    v8::String::Utf8Value attr(input->Get(i)->ToString());

    auto attribute = attributeMap.find(*attr);
    if (attribute != attributeMap.end()) {
      res |= attribute->second;
    }
  }

  return res;
}

NAN_METHOD(SetFileAttributes) {
  Isolate* isolate = Isolate::GetCurrent();

  if (info.Length() != 2) {
    Nan::ThrowError("Expected two parameters (path, attributes)");
    return;
  }

  String::Utf8Value path(info[0]->ToString());
  Local<Array> attributes = Local<Array>::Cast(info[1]);

  if (!::SetFileAttributesW(toWC(*path, CodePage::UTF8, path.length()).c_str(), mapAttributes(attributes))) {
    isolate->ThrowException(WinApiException(::GetLastError(), "SetFileAttributes", *path));
    return;
  }
}

NAN_METHOD(GetDiskFreeSpaceEx) {
  Isolate* isolate = Isolate::GetCurrent();

  if (info.Length() != 1) {
    Nan::ThrowError("Expected one parameter (path)");
    return;
  }

  String::Utf8Value path(info[0]->ToString());

  ULARGE_INTEGER freeBytesAvailableToCaller;
  ULARGE_INTEGER totalNumberOfBytes;
  ULARGE_INTEGER totalNumberOfFreeBytes;

  if (!::GetDiskFreeSpaceExW(toWC(*path, CodePage::UTF8, path.length()).c_str(),
                             &freeBytesAvailableToCaller,
                             &totalNumberOfBytes,
                             &totalNumberOfFreeBytes)) {
    isolate->ThrowException(WinApiException(::GetLastError(), "GetDiskFreeSpaceEx", *path));
    return;
  }

  Local<Object> result = New<Object>();
  result->Set("total"_n, New<Number>(static_cast<double>(totalNumberOfBytes.QuadPart)));
  result->Set("free"_n, New<Number>(static_cast<double>(totalNumberOfFreeBytes.QuadPart)));
  result->Set("freeToCaller"_n, New<Number>(static_cast<double>(freeBytesAvailableToCaller.QuadPart)));

  info.GetReturnValue().Set(result);
}



NAN_METHOD(ShellExecuteEx) {
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
  };

  Isolate *isolate = Isolate::GetCurrent();

  if (info.Length() != 1) {
    Nan::ThrowError("Expected one parameter (options)");
    return;
  }

  Local<Object> args(info[0]->ToObject());

  if (!args->Has("file"_n) || !args->Has("show"_n)) {
    Nan::ThrowError("Parameter missing (required: file, show)");
    return;
  }

  std::vector<std::wstring> buffers;

  auto assignParameter = [&args, &buffers](LPCWSTR &target, const Local<Value> &key) {
    if (args->Has(key)) {
      String::Utf8Value value(args->Get(key)->ToString());
      buffers.push_back(toWC(*value, CodePage::UTF8, value.length()));
      target = buffers.rbegin()->c_str();
    }
    else {
      target = nullptr;
    }
  };

  SHELLEXECUTEINFOW execInfo;
  execInfo.cbSize = sizeof(SHELLEXECUTEINFO);

  execInfo.fMask = 0;
  execInfo.hwnd = nullptr;
  execInfo.hInstApp = nullptr;

  assignParameter(execInfo.lpVerb, "verb"_n);
  assignParameter(execInfo.lpFile, "file"_n);
  assignParameter(execInfo.lpDirectory, "directory"_n);
  assignParameter(execInfo.lpParameters, "parameters"_n);

  v8::String::Utf8Value show(args->Get("show"_n)->ToString());
  auto iter = showFlagMap.find(*show);
  if (iter == showFlagMap.end()) {
    Nan::ThrowRangeError("Invalid show flag");
    return;
  }
  execInfo.nShow = iter->second;


  if (!::ShellExecuteExW(&execInfo)) {
    isolate->ThrowException(WinApiException(::GetLastError(), "ShellExecuteEx",
                                           toMB(execInfo.lpFile, CodePage::UTF8, wcslen(execInfo.lpFile)).c_str()));
    return;
  }
}

NAN_METHOD(GetPrivateProfileSection) {
  Isolate* isolate = Isolate::GetCurrent();

  if (info.Length() != 2) {
    Nan::ThrowError("Expected two parameters (section, fileName)");
    return;
  }

  String::Utf8Value appName(info[0]->ToString());
  String::Utf8Value fileName(info[1]->ToString());

  DWORD size = 32 * 1024;
  std::unique_ptr<wchar_t[]> buffer(new wchar_t[size]);

  DWORD charCount = ::GetPrivateProfileSectionW(toWC(*appName, CodePage::UTF8, appName.length()).c_str(),
                                                buffer.get(), size,
                                                toWC(*fileName, CodePage::UTF8, fileName.length()).c_str());

  Local<Object> result = New<Object>();
  wchar_t *start = buffer.get();
  wchar_t *ptr = start;
  // double check. the list is supposed to end on a double zero termination but to ensure we don't overrun
  // the buffer, also verify we don't exceed the character count
  while ((*ptr != '\0') && ((ptr - start) < charCount)) {
    
    wchar_t *eqPos = wcschr(ptr, L'=');
    size_t valLength = wcslen(eqPos);
    result->Set(New<String>(toMB(ptr, CodePage::UTF8, eqPos - ptr)).ToLocalChecked(),
                New<String>(toMB(eqPos + 1, CodePage::UTF8, valLength - 1)).ToLocalChecked());

    ptr = eqPos + valLength + 1;
  }

  info.GetReturnValue().Set(result);
}

NAN_METHOD(GetPrivateProfileSectionNames) {
  Isolate* isolate = Isolate::GetCurrent();

  if (info.Length() != 1) {
    Nan::ThrowError("Expected one parameter (fileName)");
    return;
  }

  String::Utf8Value fileName(info[0]->ToString());

  DWORD size = 32 * 1024;
  std::unique_ptr<wchar_t[]> buffer(new wchar_t[size]);

  DWORD charCount = ::GetPrivateProfileSectionNamesW(buffer.get(), size,
    toWC(*fileName, CodePage::UTF8, fileName.length()).c_str());

  Local<Array> result = New<Array>();
  wchar_t *start = buffer.get();
  wchar_t *ptr = start;
  int idx = 0;
  // double check. the list is supposed to end on a double zero termination but to ensure we don't overrun
  // the buffer, also verify we don't exceed the character count
  while ((*ptr != '\0') && ((ptr - start) < charCount)) {
    size_t len = wcslen(ptr);
    result->Set(idx++, New<String>(toMB(ptr, CodePage::UTF8, len)).ToLocalChecked());
    ptr += len + 1;
  }

  info.GetReturnValue().Set(result);
}

NAN_METHOD(WritePrivateProfileString) {
  Isolate* isolate = Isolate::GetCurrent();

  if (info.Length() != 4) {
    Nan::ThrowError("Expected four parameters (section, key, value, fileName)");
    return;
  }

  String::Utf8Value appName(info[0]->ToString());
  String::Utf8Value keyName(info[1]->ToString());
  String::Utf8Value value(info[2]->ToString());
  String::Utf8Value fileName(info[3]->ToString());

  BOOL res = ::WritePrivateProfileStringW(
    toWC(*appName, CodePage::UTF8, appName.length()).c_str(),
    toWC(*keyName, CodePage::UTF8, keyName.length()).c_str(),
    toWC(*value, CodePage::UTF8, value.length()).c_str(),
    toWC(*fileName, CodePage::UTF8, fileName.length()).c_str());

  if (!res) {
    isolate->ThrowException(WinApiException(::GetLastError(), "WritePrivateProfileString", *fileName));
  }
}

NAN_MODULE_INIT(Init) {
  Nan::Set(target, "SetFileAttributes"_n,
    GetFunction(New<FunctionTemplate>(SetFileAttributes)).ToLocalChecked());
  Nan::Set(target, "GetDiskFreeSpaceEx"_n,
    GetFunction(New<FunctionTemplate>(GetDiskFreeSpaceEx)).ToLocalChecked());
  Nan::Set(target, "ShellExecuteEx"_n,
    GetFunction(New<FunctionTemplate>(ShellExecuteEx)).ToLocalChecked());
  Nan::Set(target, "GetPrivateProfileSection"_n,
    GetFunction(New<FunctionTemplate>(GetPrivateProfileSection)).ToLocalChecked());
  Nan::Set(target, "GetPrivateProfileSectionNames"_n,
    GetFunction(New<FunctionTemplate>(GetPrivateProfileSectionNames)).ToLocalChecked());
  Nan::Set(target, "WritePrivateProfileString"_n,
    GetFunction(New<FunctionTemplate>(WritePrivateProfileString)).ToLocalChecked());
}

NODE_MODULE(winapi, Init)
