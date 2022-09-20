#include "UnicodeString.h"
#ifdef _WIN32
UnicodeString::UnicodeString()
{
  m_Data.Length = m_Data.MaximumLength = 0;
  m_Data.Buffer = nullptr;
}

UnicodeString::UnicodeString(LPCWSTR string, size_t length)
{
  if (length == std::string::npos) {
    length = wcslen(string);
  }
  try {
    m_Buffer.resize(length);
    memcpy(&m_Buffer[0], string, length * sizeof(WCHAR));
  }
  catch (const std::length_error& e) {
    m_Buffer.resize(0);
  }
  update();
}


size_t UnicodeString::size() const {
  return m_Buffer.size() > 0 ? m_Buffer.size() - 1 : 0;
}

void UnicodeString::update() {
  while ((m_Buffer.size() > 0) && (*m_Buffer.rbegin() == L'\0')) {
    m_Buffer.resize(m_Buffer.size() - 1);
  }
  m_Data.Length = static_cast<USHORT>(m_Buffer.size() * sizeof (WCHAR));
  m_Data.MaximumLength = static_cast<USHORT>(m_Buffer.capacity() * sizeof(WCHAR));
  m_Buffer.push_back(L'\0');
}

UnicodeString::operator LPCWSTR() const {
  return m_Buffer.data();
}

UnicodeString::operator PUNICODE_STRING() {
  m_Data.Buffer = &m_Buffer[0];
  return &m_Data;
}
#endif
