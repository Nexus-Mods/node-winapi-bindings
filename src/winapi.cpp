#define WIN32_LEAN_AND_MEAN
#include <windows.h>
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

NAN_MODULE_INIT(Init) {
  Nan::Set(target, "SetFileAttribute"_n,
    GetFunction(New<FunctionTemplate>(SetFileAttributes)).ToLocalChecked());
  Nan::Set(target, "GetDiskFreeSpaceEx"_n,
    GetFunction(New<FunctionTemplate>(GetDiskFreeSpaceEx)).ToLocalChecked());
}

NODE_MODULE(winapi, Init)
