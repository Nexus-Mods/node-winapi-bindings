#include "fs.h"
#include "util.h"
#include <windows.h>
#include <unordered_map>


DWORD mapAttributes(const Napi::Array &input) {
  static const std::unordered_map<std::string, DWORD> attributeMap{
    { "archive", FILE_ATTRIBUTE_ARCHIVE },
    { "hidden", FILE_ATTRIBUTE_HIDDEN },
    { "normal", FILE_ATTRIBUTE_NORMAL },
    { "not_content_indexed", FILE_ATTRIBUTE_NOT_CONTENT_INDEXED },
    { "readonly", FILE_ATTRIBUTE_READONLY },
    { "temporary", FILE_ATTRIBUTE_TEMPORARY },
  };

  DWORD res = 0;
  for (uint32_t i = 0; i < input.Length(); ++i) {
    Napi::String attr = input.Get(i).ToString();

    auto attribute = attributeMap.find(attr.Utf8Value());
    if (attribute != attributeMap.end()) {
      res |= attribute->second;
    }
  }

  return res;
}

Napi::Value SetFileAttributesWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 2) {
      throw std::runtime_error("Expected two parameters (path, attributes)");
    }

    std::string pathU8 = info[0].ToString();
    std::wstring path = toWC(pathU8.c_str(), CodePage::UTF8, pathU8.length());
    Napi::Array attributes = info[1].As<Napi::Array>();

    if (!::SetFileAttributesW(path.c_str(), mapAttributes(attributes))) {
      throw WinApiException(::GetLastError(), "SetFileAttributes", pathU8.c_str());
    }

    return info.Env().Undefined();
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetDiskFreeSpaceExWrap(const Napi::CallbackInfo &info) {

  try {
    if (info.Length() != 1) {
      throw std::runtime_error("Expected one parameter (path)");
    }

    std::string pathU8 = info[0].ToString();
    std::wstring path = toWC(pathU8.c_str(), CodePage::UTF8, pathU8.length());

    ULARGE_INTEGER freeBytesAvailableToCaller;
    ULARGE_INTEGER totalNumberOfBytes;
    ULARGE_INTEGER totalNumberOfFreeBytes;

    if (!::GetDiskFreeSpaceExW(path.c_str(),
      &freeBytesAvailableToCaller,
      &totalNumberOfBytes,
      &totalNumberOfFreeBytes)) {
      throw WinApiException(::GetLastError(), "GetDiskFreeSpaceEx", pathU8.c_str());
    }

    Napi::Object result = Napi::Object::New(info.Env());
    result.Set("total", Napi::Number::New(info.Env(), static_cast<double>(totalNumberOfBytes.QuadPart)));
    result.Set("free", Napi::Number::New(info.Env(), static_cast<double>(totalNumberOfFreeBytes.QuadPart)));
    result.Set("freeToCaller", Napi::Number::New(info.Env(), static_cast<double>(freeBytesAvailableToCaller.QuadPart)));

    return result;
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetVolumePathNameWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw std::runtime_error("Expected one parameter (path)");
    }

    std::wstring path = toWC(info[0]);

    wchar_t buffer[MAX_PATH];
    if (!::GetVolumePathNameW(path.c_str(), buffer, MAX_PATH)) {
      throw WinApiException(::GetLastError(), "GetDiskFreeSpaceEx", toMB(path.c_str(), CodePage::UTF8, path.length()).c_str());
    }

    return Napi::String::New(info.Env(), toMB(buffer, CodePage::UTF8, (std::numeric_limits<size_t>::max)()));
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

const char *fileType(DWORD type) {
  switch (type) {
   case VFT_APP: return "app";
   case VFT_DLL: return "dll";
   case VFT_DRV: return "drv";
   case VFT_FONT: return "font";
   case VFT_STATIC_LIB: return "lib";
   case VFT_VXD: return "vxd";
  }
 return "unknown";
}

Napi::Value GetFileVersionInfoWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw std::exception("Expected 1 parameter (filePath)");
    }

    std::wstring executablePath = toWC(info[0]);

    DWORD handle;
    DWORD info_len = ::GetFileVersionInfoSizeW(executablePath.c_str(), &handle);
    if (info_len == 0) {
      throw WinApiException(::GetLastError(), "GetFileVersionInfoSize", info[0].ToString().Utf8Value().c_str());
    }

    std::vector<char> buff(info_len);
    if (!::GetFileVersionInfoW(executablePath.c_str(), handle, info_len, buff.data())) {
      throw WinApiException(::GetLastError(), "GetFileVersionInfo", info[0].ToString().Utf8Value().c_str());
    }

    VS_FIXEDFILEINFO *fileInfo;
    UINT buf_len;
    if (!::VerQueryValueW(buff.data(), L"\\", reinterpret_cast<LPVOID *>(&fileInfo), &buf_len)) {
      throw WinApiException(::GetLastError(), "VerQueryValue", info[0].ToString().Utf8Value().c_str());
    }

    Napi::Object res = Napi::Object::New(info.Env());
    {
      Napi::Array version = Napi::Array::New(info.Env());
      version.Set(0U, Napi::Number::New(info.Env(), HIWORD(fileInfo->dwFileVersionMS)));
      version.Set(1U, Napi::Number::New(info.Env(), LOWORD(fileInfo->dwFileVersionMS)));
      version.Set(2U, Napi::Number::New(info.Env(), HIWORD(fileInfo->dwFileVersionLS)));
      version.Set(3u, Napi::Number::New(info.Env(), LOWORD(fileInfo->dwFileVersionLS)));
      res.Set("fileVersion", version);
    }
    {
      Napi::Array version = Napi::Array::New(info.Env());
      version.Set(0U, Napi::Number::New(info.Env(), HIWORD(fileInfo->dwProductVersionMS)));
      version.Set(1U, Napi::Number::New(info.Env(), LOWORD(fileInfo->dwProductVersionMS)));
      version.Set(2U, Napi::Number::New(info.Env(), HIWORD(fileInfo->dwProductVersionLS)));
      version.Set(3u, Napi::Number::New(info.Env(), LOWORD(fileInfo->dwProductVersionLS)));
      res.Set("productVersion", version);
    }
    {
      DWORD fileFlags = fileInfo->dwFileFlags & fileInfo->dwFileFlagsMask;
      Napi::Object flags = Napi::Object::New(info.Env());
      flags.Set("debug", (fileFlags & VS_FF_DEBUG) != 0);
      flags.Set("infoInferred", (fileFlags & VS_FF_INFOINFERRED) != 0);
      flags.Set("patched", (fileFlags & VS_FF_PATCHED) != 0);
      flags.Set("prerelease", (fileFlags & VS_FF_PRERELEASE) != 0);
      flags.Set("privateBuild", (fileFlags & VS_FF_PRIVATEBUILD) != 0);
      flags.Set("specialBuild", (fileFlags & VS_FF_SPECIALBUILD) != 0);
      res.Set("flags", flags);
    }

    res.Set("fileType", Napi::String::New(info.Env(), fileType(fileInfo->dwFileType)));
    // DWORD   dwFileSubtype;          /* e.g. VFT2_DRV_KEYBOARD */

    return res;
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

namespace FS {
  void Init(Napi::Env env, Napi::Object exports) {
    exports.Set("SetFileAttributes", Napi::Function::New(env, SetFileAttributesWrap));
    exports.Set("GetDiskFreeSpaceEx", Napi::Function::New(env, GetDiskFreeSpaceExWrap));
    exports.Set("GetVolumePathName", Napi::Function::New(env, GetVolumePathNameWrap));
    exports.Set("GetFileVersionInfo", Napi::Function::New(env, GetFileVersionInfoWrap));
  }
}

