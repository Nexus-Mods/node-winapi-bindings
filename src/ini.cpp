#include "ini.h"
#include "util.h"
#include <windows.h>

Napi::Value GetPrivateProfileSectionWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 2) {
      throw std::runtime_error("Expected two parameters (section, fileName)");
    }

    std::string appNameV8(info[0].ToString());
    std::string fileNameV8(info[1].ToString());

    std::wstring appName = toWC(appNameV8.c_str(), CodePage::UTF8, appNameV8.length());
    std::wstring fileName = toWC(fileNameV8.c_str(), CodePage::UTF8, fileNameV8.length());

    DWORD size = 32 * 1024;
    std::unique_ptr<wchar_t[]> buffer(new wchar_t[size]);

    DWORD charCount = ::GetPrivateProfileSectionW(appName.c_str(), buffer.get(), size, fileName.c_str());

    Napi::Object result = Napi::Object::New(info.Env());
    wchar_t *start = buffer.get();
    wchar_t *ptr = start;
    // double check. the list is supposed to end on a double zero termination but to ensure we don't overrun
    // the buffer, also verify we don't exceed the character count
    Napi::String lastKey;
    Napi::String lastValue;
    while ((*ptr != '\0') && ((ptr - start) < charCount)) {
      wchar_t *eqPos = wcschr(ptr, L'=');
      size_t valLength;
      if (eqPos != nullptr) {
        lastKey = Napi::String::New(info.Env(), toMB(ptr, CodePage::UTF8, eqPos - ptr));
        valLength = wcslen(eqPos);
        lastValue = Napi::String::New(info.Env(), toMB(eqPos + 1, CodePage::UTF8, valLength - 1));
        ptr = eqPos + valLength + 1;
        result.Set(lastKey, lastValue);
      }
      else {
        // ignore all lines that contain no equal sign
        ptr += wcslen(ptr) + 1;
      }
    }

    return result;
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetPrivateProfileSectionNamesWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw std::runtime_error("Expected one parameter (fileName)");
    }

    std::string fileName = info[0].ToString();

    DWORD size = 32 * 1024;
    std::unique_ptr<wchar_t[]> buffer(new wchar_t[size]);

    DWORD charCount = ::GetPrivateProfileSectionNamesW(buffer.get(), size,
      toWC(fileName.c_str(), CodePage::UTF8, fileName.length()).c_str());

    return convertMultiSZ(info.Env(), buffer.get(), charCount);
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetPrivateProfileStringWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 4) {
      throw std::exception("Expected four parameters (section, key, default, fileName)");
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
          throw WinApiException(::GetLastError(), "GetPrivateProfileString", toMB(fileName.c_str(), CodePage::UTF8, fileName.length()).c_str());
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
    return convertMultiSZ(info.Env(), buffer.get(), charCount);
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value WritePrivateProfileStringWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 4) {
      throw std::exception("Expected four parameters (section, key, value, fileName)");
    }

    std::string appNameV8(info[0].ToString());
    std::string keyNameV8(info[1].ToString());
    std::string valueV8(info[2].ToString());
    std::string fileNameV8(info[3].ToString());

    std::wstring appName = toWC(appNameV8.c_str(), CodePage::UTF8, appNameV8.length());
    std::wstring keyName = toWC(keyNameV8.c_str(), CodePage::UTF8, keyNameV8.length());
    std::wstring value = (info[2].IsNull() || info[2].IsUndefined()) ? L"" : toWC(valueV8.c_str(), CodePage::UTF8, valueV8.length());
    std::wstring fileName = toWC(fileNameV8.c_str(), CodePage::UTF8, fileNameV8.length());

    BOOL res = ::WritePrivateProfileStringW(appName.c_str(), keyName.c_str(),
      (info[2].IsNull() || info[2].IsUndefined()) ? nullptr : value.c_str(), fileName.c_str());

    if (!res) {
      return ThrowWinApiException(info.Env(), ::GetLastError(), "WritePrivateProfileString", fileNameV8.c_str());
    }
    return info.Env().Undefined();
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

namespace INI {
  void Init(Napi::Env env, Napi::Object exports) {
    exports.Set("GetPrivateProfileSection", Napi::Function::New(env, GetPrivateProfileSectionWrap));
    exports.Set("GetPrivateProfileSectionNames", Napi::Function::New(env, GetPrivateProfileSectionNamesWrap));
    exports.Set("GetPrivateProfileString", Napi::Function::New(env, GetPrivateProfileStringWrap));
    exports.Set("WritePrivateProfileString", Napi::Function::New(env, WritePrivateProfileStringWrap));
  }
}
