#pragma once
#ifdef _WIN32

#include <sstream>
#include <vector>
#include <cassert>
#include <windows.h>

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

/**
 * @brief C++ wrapper for the windows UNICODE_STRING structure
 */
class UnicodeString {
  friend std::ostream &operator<<(std::ostream &os, const UnicodeString &str);
public:

  UnicodeString();

  explicit UnicodeString(LPCWSTR string, size_t length = std::string::npos);

  /**
   * @brief convert to a WinNt Api-style unicode string. This is only valid as long
   *        as the string isn't modified
   */
  explicit operator PUNICODE_STRING();

  /**
   * @brief convert to a Win32 Api-style unicode string. This is only valid as long
   *        as the string isn't modified
   */
  explicit operator LPCWSTR() const;

  /**
   * @return length of the string in 16-bit words (not including zero termination)
   */
  size_t size() const;

private:

  void update();

private:
  UNICODE_STRING m_Data;
  std::vector<wchar_t> m_Buffer;
};
#endif
