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
  String::Utf8Value path(info[0]->ToString());
  Local<Array> attributes = Local<Array>::Cast(info[1]);

  if (!::SetFileAttributesW(toWC(*path, CodePage::UTF8, path.length()).c_str(), mapAttributes(attributes))) {
    isolate->ThrowException(ErrnoException(::GetLastError(), "SetFileAttributes", "Failed to set attributes", *path));
    return;
  }
}

NAN_METHOD(GetDiskFreeSpaceEx) {
  Isolate* isolate = Isolate::GetCurrent();
  String::Utf8Value path(info[0]->ToString());

  ULARGE_INTEGER freeBytesAvailableToCaller;
  ULARGE_INTEGER totalNumberOfBytes;
  ULARGE_INTEGER totalNumberOfFreeBytes;

  if (!::GetDiskFreeSpaceExW(toWC(*path, CodePage::UTF8, path.length()).c_str(),
                             &freeBytesAvailableToCaller,
                             &totalNumberOfBytes,
                             &totalNumberOfFreeBytes)) {
    isolate->ThrowException(ErrnoException(::GetLastError(), "GetDiskFreeSpaceEx", "Failed to get free space", *path));
    return;
  }

  Local<Object> result = New<Object>();
  result->Set("total"_n, New<Number>(static_cast<double>(totalNumberOfBytes.QuadPart)));
  result->Set("free"_n, New<Number>(static_cast<double>(totalNumberOfFreeBytes.QuadPart)));
  result->Set("freeToCaller"_n, New<Number>(static_cast<double>(freeBytesAvailableToCaller.QuadPart)));

  info.GetReturnValue().Set(result);
}



NAN_METHOD(ShellExecuteEx) {
  Isolate *isolate = Isolate::GetCurrent();

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

  Local<Object> args(info[0]->ToObject());

  if (!args->Has("file"_n) || !args->Has("show"_n)) {
    Nan::ThrowError("Parameter missing");
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
    isolate->ThrowException(ErrnoException(::GetLastError(), "ShellExecuteEx", "Failed to execute external application",
                                           toMB(execInfo.lpFile, CodePage::UTF8, wcslen(execInfo.lpFile)).c_str()));
    return;
  }
}

NAN_MODULE_INIT(Init) {
  Nan::Set(target, "SetFileAttributes"_n,
    GetFunction(New<FunctionTemplate>(SetFileAttributes)).ToLocalChecked());
  Nan::Set(target, "GetDiskFreeSpaceEx"_n,
    GetFunction(New<FunctionTemplate>(GetDiskFreeSpaceEx)).ToLocalChecked());
  Nan::Set(target, "ShellExecuteEx"_n,
    GetFunction(New<FunctionTemplate>(ShellExecuteEx)).ToLocalChecked());
}

NODE_MODULE(winapi, Init)
