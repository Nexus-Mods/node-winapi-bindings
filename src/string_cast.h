#pragma once

#include <string>
#include <windows.h>

enum class CodePage {
  LOCAL,
  LATIN1,
  UTF8
};

UINT windowsCP(CodePage codePage);

std::wstring toWC(const char * const &source, CodePage codePage, size_t sourceLength);

std::string toMB(const wchar_t * const &source, CodePage codePage, size_t sourceLength);
