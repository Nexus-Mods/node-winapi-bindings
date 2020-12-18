#include "util.h"
#include <comdef.h>

std::wstring toWC(const Napi::Value & input) {
  std::string temp = input.ToString().Utf8Value();
  return toWC(temp.c_str(), CodePage::UTF8, temp.length());
}

Napi::Array convertMultiSZ(const Napi::Env &env, wchar_t *input, DWORD maxLength) {
  Napi::Array result = Napi::Array::New(env);
  wchar_t *start = input;
  wchar_t *ptr = start;
  int idx = 0;
  // double check. the list is supposed to end on a double zero termination but to ensure we don't overrun
  // the buffer, also verify we don't exceed the character count
  while ((*ptr != '\0') && ((ptr - start) < maxLength)) {
    size_t len = wcslen(ptr);
    result.Set(idx++, Napi::String::New(env, toMB(ptr, CodePage::UTF8, len)));
    ptr += len + 1;
  }

  return result;
}

static std::string strerror(DWORD errorno) {
  wchar_t *errmsg = nullptr;

  LCID lcid;
  GetLocaleInfoEx(L"en-US", LOCALE_RETURN_NUMBER | LOCALE_ILANGUAGE, reinterpret_cast<LPWSTR>(&lcid), sizeof(lcid));

  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
    FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, errorno,
    lcid, (LPWSTR)&errmsg, 0, nullptr);

  if (errmsg) {
    size_t len = wcslen(errmsg);
    for (int i = (len - 1);
         (i >= 0) && ((errmsg[i] == '\n') || (errmsg[i] == '\r'));
         --i) {
      errmsg[i] = '\0';
    }

    return toMB(errmsg, CodePage::UTF8, len);
  }
  else {
    return "Unknown error";
  }
}

const char *translateCode(DWORD err) {
  switch (err) {
    case ERROR_USER_MAPPED_FILE:            return "EBUSY";
    case ERROR_NOACCESS:                    return "EACCES";
    case WSAEACCES:                         return "EACCES";
    case ERROR_ELEVATION_REQUIRED:          return "EACCES";
    case ERROR_CANT_ACCESS_FILE:            return "EACCES";
    case ERROR_ADDRESS_ALREADY_ASSOCIATED:  return "EADDRINUSE";
    case WSAEADDRINUSE:                     return "EADDRINUSE";
    case WSAEADDRNOTAVAIL:                  return "EADDRNOTAVAIL";
    case WSAEAFNOSUPPORT:                   return "EAFNOSUPPORT";
    case WSAEWOULDBLOCK:                    return "EAGAIN";
    case WSAEALREADY:                       return "EALREADY";
    case ERROR_INVALID_FLAGS:               return "EBADF";
    case ERROR_INVALID_HANDLE:              return "EBADF";
    case ERROR_LOCK_VIOLATION:              return "EBUSY";
    case ERROR_PIPE_BUSY:                   return "EBUSY";
    case ERROR_SHARING_VIOLATION:           return "EBUSY";
    case ERROR_OPERATION_ABORTED:           return "ECANCELED";
    case WSAEINTR:                          return "ECANCELED";
    case ERROR_CANCELLED:                   return "ECANCELED";
    case ERROR_NO_UNICODE_TRANSLATION:      return "ECHARSET";
    case ERROR_CONNECTION_ABORTED:          return "ECONNABORTED";
    case WSAECONNABORTED:                   return "ECONNABORTED";
    case ERROR_CONNECTION_REFUSED:          return "ECONNREFUSED";
    case WSAECONNREFUSED:                   return "ECONNREFUSED";
    case ERROR_NETNAME_DELETED:             return "ECONNRESET";
    case WSAECONNRESET:                     return "ECONNRESET";
    case ERROR_ALREADY_EXISTS:              return "EEXIST";
    case ERROR_FILE_EXISTS:                 return "EEXIST";
    case ERROR_BUFFER_OVERFLOW:             return "EFAULT";
    case WSAEFAULT:                         return "EFAULT";
    case ERROR_HOST_UNREACHABLE:            return "EHOSTUNREACH";
    case WSAEHOSTUNREACH:                   return "EHOSTUNREACH";
    case ERROR_INSUFFICIENT_BUFFER:         return "EINVAL";
    case ERROR_INVALID_DATA:                return "EINVAL";
    case ERROR_INVALID_PARAMETER:           return "EINVAL";
    case ERROR_SYMLINK_NOT_SUPPORTED:       return "EINVAL";
    case WSAEINVAL:                         return "EINVAL";
    case WSAEPFNOSUPPORT:                   return "EINVAL";
    case WSAESOCKTNOSUPPORT:                return "EINVAL";
    case ERROR_BEGINNING_OF_MEDIA:          return "EIO";
    case ERROR_BUS_RESET:                   return "EIO";
    case ERROR_CRC:                         return "EIO";
    case ERROR_DEVICE_DOOR_OPEN:            return "EIO";
    case ERROR_DEVICE_REQUIRES_CLEANING:    return "EIO";
    case ERROR_DISK_CORRUPT:                return "EIO";
    case ERROR_EOM_OVERFLOW:                return "EIO";
    case ERROR_FILEMARK_DETECTED:           return "EIO";
    case ERROR_GEN_FAILURE:                 return "EIO";
    case ERROR_INVALID_BLOCK_LENGTH:        return "EIO";
    case ERROR_IO_DEVICE:                   return "EIO";
    case ERROR_NO_DATA_DETECTED:            return "EIO";
    case ERROR_NO_SIGNAL_SENT:              return "EIO";
    case ERROR_OPEN_FAILED:                 return "EIO";
    case ERROR_SETMARK_DETECTED:            return "EIO";
    case ERROR_SIGNAL_REFUSED:              return "EIO";
    case WSAEISCONN:                        return "EISCONN";
    case ERROR_CANT_RESOLVE_FILENAME:       return "ELOOP";
    case ERROR_TOO_MANY_OPEN_FILES:         return "EMFILE";
    case WSAEMFILE:                         return "EMFILE";
    case WSAEMSGSIZE:                       return "EMSGSIZE";
    case ERROR_FILENAME_EXCED_RANGE:        return "ENAMETOOLONG";
    case ERROR_NETWORK_UNREACHABLE:         return "ENETUNREACH";
    case WSAENETUNREACH:                    return "ENETUNREACH";
    case WSAENOBUFS:                        return "ENOBUFS";
    case ERROR_BAD_PATHNAME:                return "ENOENT";
    case ERROR_DIRECTORY:                   return "ENOENT";
    case ERROR_ENVVAR_NOT_FOUND:            return "ENOENT";
    case ERROR_FILE_NOT_FOUND:              return "ENOENT";
    case ERROR_INVALID_NAME:                return "ENOENT";
    case ERROR_INVALID_DRIVE:               return "ENOENT";
    case ERROR_INVALID_REPARSE_DATA:        return "ENOENT";
    case ERROR_MOD_NOT_FOUND:               return "ENOENT";
    case ERROR_PATH_NOT_FOUND:              return "ENOENT";
    case WSAHOST_NOT_FOUND:                 return "ENOENT";
    case WSANO_DATA:                        return "ENOENT";
    case ERROR_NOT_ENOUGH_MEMORY:           return "ENOMEM";
    case ERROR_OUTOFMEMORY:                 return "ENOMEM";
    case ERROR_CANNOT_MAKE:                 return "ENOSPC";
    case ERROR_DISK_FULL:                   return "ENOSPC";
    case ERROR_EA_TABLE_FULL:               return "ENOSPC";
    case ERROR_END_OF_MEDIA:                return "ENOSPC";
    case ERROR_HANDLE_DISK_FULL:            return "ENOSPC";
    case ERROR_NOT_CONNECTED:               return "ENOTCONN";
    case WSAENOTCONN:                       return "ENOTCONN";
    case ERROR_DIR_NOT_EMPTY:               return "ENOTEMPTY";
    case WSAENOTSOCK:                       return "ENOTSOCK";
    case ERROR_NOT_SUPPORTED:               return "ENOTSUP";
    case ERROR_BROKEN_PIPE:                 return "EOF";
    case ERROR_ACCESS_DENIED:               return "EPERM";
    case ERROR_PRIVILEGE_NOT_HELD:          return "EPERM";
    case ERROR_BAD_PIPE:                    return "EPIPE";
    case ERROR_NO_DATA:                     return "EPIPE";
    case ERROR_PIPE_NOT_CONNECTED:          return "EPIPE";
    case WSAESHUTDOWN:                      return "EPIPE";
    case WSAEPROTONOSUPPORT:                return "EPROTONOSUPPORT";
    case ERROR_WRITE_PROTECT:               return "EROFS";
    case ERROR_SEM_TIMEOUT:                 return "ETIMEDOUT";
    case WSAETIMEDOUT:                      return "ETIMEDOUT";
    case ERROR_NOT_SAME_DEVICE:             return "EXDEV";
    case ERROR_INVALID_FUNCTION:            return "EISDIR";
    case ERROR_META_EXPANSION_TOO_LONG:     return "E2BIG";
    default:                                return "UNKNOWN";
  }
}

napi_value MakeWinApiException(const Napi::Env& env, DWORD lastError, const char* func, const char* path) {
  std::string errMessage = strerror(lastError);
  const char *code = translateCode(lastError);
  napi_value err;
  napi_status s = napi_create_error(
    env,
    Napi::String::New(env, code),
    Napi::String::New(env, errMessage.c_str()),
    &err);

  if (s == napi_ok) {
    napi_set_property(env, err, Napi::String::New(env, "name"), Napi::String::New(env, "WinApiException"));
    napi_set_property(env, err, Napi::String::New(env, "code"), Napi::String::New(env, code));
    napi_set_property(env, err, Napi::String::New(env, "systemCode"), Napi::Number::New(env, lastError));
    if (func != nullptr) {
      napi_set_property(env, err, Napi::String::New(env, "func"), Napi::String::New(env, func));
    }
    if (path != nullptr) {
      napi_set_property(env, err, Napi::String::New(env, "path"), Napi::String::New(env, path));
    }

    return err;
  }
  else {
    return nullptr;
  }
}

// using napi directly because the wrappers in napi-addon-api doesn't relay properties on the error object correctly
Napi::Value ThrowWinApiException(const Napi::Env &env, DWORD lastError, const char *func, const char *path) {
  napi_value err = MakeWinApiException(env, lastError, func, path);
  napi_status s = napi_invalid_arg;

  if (err != nullptr) {
    napi_throw(env, err);
  }
  if (s != napi_ok) {
    // fallback
    std::string errMessage = strerror(lastError);
    const char *code = translateCode(lastError);
    napi_throw_error(env, code, errMessage.c_str());
  }

  return env.Undefined();
}

// using napi directly because the wrappers in napi-addon-api doesn't relay properties on the error object correctly
Napi::Value ThrowHResultException(const Napi::Env &env, HRESULT hr, const char *func, const char *path) {
  _com_error comErr(hr);
  LPCWSTR errMsg = comErr.ErrorMessage();
  std::string errMsgUtf8 = toMB(errMsg, CodePage::UTF8, wcslen(errMsg));

  napi_value err;
  napi_status s = napi_create_error(
    env,
    Napi::String::New(env, "UNKNOWN"),
    Napi::String::New(env, errMsgUtf8.c_str()),
    &err);

  if (s == napi_ok) {
    napi_set_property(env, err, Napi::String::New(env, "name"), Napi::String::New(env, "HResultException"));
  
    napi_set_property(env, err, Napi::String::New(env, "code"), Napi::String::New(env, "UNKNOWN"));
    napi_set_property(env, err, Napi::String::New(env, "systemCode"), Napi::Number::New(env, hr & 0xFFFF));
    if (func != nullptr) {
      napi_set_property(env, err, Napi::String::New(env, "func"), Napi::String::New(env, func));
    }
    if (path != nullptr) {
      napi_set_property(env, err, Napi::String::New(env, "path"), Napi::String::New(env, path));
    }
    s = napi_throw(env, err);
  }
  
  if (s != napi_ok) {
    // fallback
    napi_throw_error(env, "UNKNOWN", errMsgUtf8.c_str());
  }

  return env.Undefined();
}

WinApiException::WinApiException(DWORD code, const char *func, const char *path)
  : std::exception()
  , m_Message(strerror(code))
  , m_Code(code)
  , m_Func(func)
  , m_Path(path != nullptr ? path : "")
{
}

WinApiException::WinApiException(const WinApiException &ref)
  : std::exception()
  , m_Message(ref.m_Message)
  , m_Code(ref.m_Code)
  , m_Func(ref.m_Func)
  , m_Path(ref.m_Path)
{

}

const char *WinApiException::what() const noexcept {
  return m_Message.c_str();
}

HResultException::HResultException(HRESULT code, const char *func, const char *path)
  : std::exception()
  , m_Code(code)
  , m_Func(func)
  , m_Path(path != nullptr ? path : "")
{
  _com_error comErr(code);
  LPCWSTR errMsg = comErr.ErrorMessage();
  m_Message = toMB(errMsg, CodePage::UTF8, wcslen(errMsg));
}

HResultException::HResultException(const HResultException &ref)
  : std::exception()
  , m_Message(ref.m_Message)
  , m_Code(ref.m_Code)
  , m_Func(ref.m_Func)
  , m_Path(ref.m_Path)
{
}

const char *HResultException::what() const noexcept {
  return m_Message.c_str();
}

Napi::Value Rethrow(const Napi::Env &env, const std::exception &e) {
  try {
    throw;
  }
  catch (const WinApiException &e) {
    ThrowWinApiException(env, e.getCode(), e.getFunc(), e.getPath());
  }
  catch (const HResultException &e) {
    ThrowHResultException(env, e.getCode(), e.getFunc(), e.getPath());
  }
  catch (const Napi::Error &e) {
    e.ThrowAsJavaScriptException();
  }
  catch (const std::exception &e) {
    napi_throw_error(env, "UNKNOWN", e.what());
  }
  catch (...) {
    napi_throw_error(env, "UNKNOWN", "Unhandled exception type");
  }

  return env.Undefined();
}
