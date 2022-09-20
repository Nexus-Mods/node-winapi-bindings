#include "string_cast.h"
#include <napi.h>

#ifdef _WIN32
class WinApiException : public std::exception {
public:
  WinApiException(DWORD code, const char *func, const char *path = nullptr);

  WinApiException(const WinApiException &ref);

  WinApiException &operator=(const WinApiException &ref) = delete;

  virtual const char *what() const noexcept;

  DWORD getCode() const {
    return m_Code;
  }

  const char *getFunc() const {
    return m_Func.c_str();
  }

  const char *getPath() const {
    return m_Path.c_str();
  }
private:
  std::string m_Message;
  DWORD m_Code;
  std::string m_Func;
  std::string m_Path;
};


class HResultException : public std::exception {
public:
  HResultException(HRESULT hr, const char *func, const char *path = nullptr);

  HResultException(const HResultException &ref);

  HResultException &operator=(const HResultException &ref) = delete;

  virtual const char *what() const noexcept;

  HRESULT getCode() const {
    return m_Code;
  }

  const char *getFunc() const {
    return m_Func.c_str();
  }

  const char *getPath() const {
    return m_Path.c_str();
  }
private:
  std::string m_Message;
  HRESULT m_Code;
  std::string m_Func;
  std::string m_Path;
};

template<typename T>
using clean_ptr = std::unique_ptr<T, std::function<void(T*)>>;

template<typename T, typename FuncT>
bool clean_ptr_assign(clean_ptr<T> &target, const FuncT &cb, const char *funcName, bool throwOnError = true) {
  T *temp = nullptr;
  HRESULT res = cb(&temp);
  if (SUCCEEDED(res)) {
    target.reset(temp);
    return true;
  }
  else {
    if (throwOnError) {
      throw HResultException(res, funcName);
    }
    return false;
  }
}

template<typename T>
void CoRelease(T *ptr) {
  ptr->Release();
}

#define COMTOV8(env, comObj, v8Obj, key, type) {\
    type temp; \
    comObj->get_ ## key ## (&temp);\
    v8Obj.Set(# key, toNapi(env, temp));\
}

#define TOSTRING(ctx, input) toWC(input).c_str()
#define TOBSTRING(env, input) CComBSTR(toWC(input).c_str())

napi_value MakeWinApiException(const Napi::Env& env, DWORD lastError, const char* func, const char* path = nullptr);

Napi::Value ThrowWinApiException(const Napi::Env &env, DWORD lastError, const char *func, const char *path = nullptr);
Napi::Value ThrowHResultException(const Napi::Env &env, HRESULT hr, const char *func = nullptr, const char *path = nullptr);
#endif
Napi::Value Rethrow(const Napi::Env &env, const std::exception &e);

#ifdef _WIN32
std::wstring toWC(const Napi::Value &input);

// template <typename T> Napi::Value toNapi(const Napi::Env &env, T input);

inline Napi::Value toNapi(const Napi::Env &env, const wchar_t *input) {
  return Napi::String::New(env, toMB(input, CodePage::UTF8, (std::numeric_limits<size_t>::max)()).c_str());
}
inline Napi::Value toNapi(const Napi::Env &env, VARIANT_BOOL input) {
  return Napi::Boolean::New(env, static_cast<bool>(input));
}

inline Napi::Value toNapi(const Napi::Env &env, LONG input) {
  return Napi::Number::New(env, input);
}

Napi::Array convertMultiSZ(const Napi::Env &env, wchar_t *input, DWORD maxLength);

#define checkedBool(res, name, filePath) { if (!res) { throw WinApiException(::GetLastError(), name, filePath == nullptr ? nullptr : toMB(filePath, CodePage::UTF8, wcslen(filePath)).c_str()); } }
#define checked(res, name, filePath) { if (res != ERROR_SUCCESS) { throw WinApiException(res, name, filePath == nullptr ? nullptr : toMB(filePath, CodePage::UTF8, wcslen(filePath)).c_str()); } }
#endif
