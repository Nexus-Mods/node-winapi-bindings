#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <set>

#include "./walk.h"
#include "./string_cast.h"
#include "./UnicodeString.h"
#include "scopeguard.hpp"
#include "util.h"

const uint64_t UNIX_EPOCH = 0x019DB1DED53E8000; // 100ns ticks between windows epoch (1601) and unix epoch (1970)
const uint64_t NS100_TO_SECOND = 10000000; // 100ns -> seconds

typedef struct _FILE_FULL_DIR_INFORMATION {
  ULONG NextEntryOffset;
  ULONG FileIndex;
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  LARGE_INTEGER EndOfFile;
  LARGE_INTEGER AllocationSize;
  ULONG FileAttributes;
  ULONG FileNameLength;
  ULONG EaSize;
  WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef LONG NTSTATUS;

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  } DUMMYUNIONNAME;

  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID(NTAPI *PIO_APC_ROUTINE)(PVOID ApcContext,
                                     PIO_STATUS_BLOCK IoStatusBlock,
                                     ULONG Reserved);

typedef enum _FILE_INFORMATION_CLASS FILE_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS {
  FileDirectoryInformation       = 1,
  FileFullDirectoryInformation   = 2,
  FileBothDirectoryInformation   = 3,
  FileNamesInformation           = 12,
  FileAllInformation             = 18,
  FileObjectIdInformation        = 29,
  FileReparsePointInformation    = 33,
  FileIdBothDirectoryInformation = 37,
  FileIdFullDirectoryInformation = 38
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;


typedef struct _FILE_BASIC_INFORMATION {
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
  LARGE_INTEGER AllocationSize;
  LARGE_INTEGER EndOfFile;
  ULONG NumberOfLinks;
  BOOLEAN DeletePending;
  BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef struct _FILE_INTERNAL_INFORMATION {
  LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION {
  ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
  ULONG AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {
  LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_MODE_INFORMATION {
  ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

typedef struct _FILE_ALIGNMENT_INFORMATION {
  ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION;

typedef struct _FILE_NAME_INFORMATION {
  ULONG FileNameLength;
  WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _FILE_ALL_INFORMATION {
  FILE_BASIC_INFORMATION     BasicInformation;
  FILE_STANDARD_INFORMATION  StandardInformation;
  FILE_INTERNAL_INFORMATION  InternalInformation;
  FILE_EA_INFORMATION        EaInformation;
  FILE_ACCESS_INFORMATION    AccessInformation;
  FILE_POSITION_INFORMATION  PositionInformation;
  FILE_MODE_INFORMATION      ModeInformation;
  FILE_ALIGNMENT_INFORMATION AlignmentInformation;
  FILE_NAME_INFORMATION      NameInformation;
  char buffer[100];
} FILE_ALL_INFORMATION;

typedef NTSTATUS(WINAPI *NtQueryDirectoryFile_type)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);

typedef NTSTATUS(WINAPI *NtQueryInformationFile_type)(
  HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

NtQueryDirectoryFile_type NtQueryDirectoryFile = nullptr;
NtQueryInformationFile_type NtQueryInformationFile = nullptr;

static const unsigned int BUFFER_SIZE = 1024;

bool getFileDetails(const std::wstring &filePath, FILE_ALL_INFORMATION *fileInfo, size_t size) {
  DWORD flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;

  HANDLE handle = CreateFileW(filePath.c_str(),
    FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    nullptr,
    OPEN_EXISTING,
    flags,
    nullptr);

  IO_STATUS_BLOCK ioStatus;

  NTSTATUS res = NtQueryInformationFile(handle, &ioStatus, fileInfo, size, FileAllInformation);
  ::CloseHandle(handle);
  // TODO: Awesome error handling...
  return res == STATUS_SUCCESS;
}

HANDLE openDirectory(const std::wstring &name) {
  return ::CreateFileW(name.c_str()
    , GENERIC_READ
    , FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    , nullptr
    , OPEN_EXISTING
    , FILE_FLAG_BACKUP_SEMANTICS
    , nullptr);
}

bool isReparsePoint(FILE_FULL_DIR_INFORMATION *info) {
  // only care about directories
  return ((info->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    && ((info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
}

std::vector<Entry> quickFindFiles(const std::wstring &directoryName, LPCWSTR pattern, bool details, bool skipHidden, bool skipInaccessible)
{
  std::vector<Entry> result;

  std::wstring prefix = (directoryName[0] == directoryName[1]) && (directoryName[0] == '\\') ? L"" : L"\\\\?\\";
  std::wstring suffix = (*directoryName.rbegin() == ':') ? L"\\" : L"";

  std::wstring name = prefix + directoryName + suffix;
  HANDLE hdl = INVALID_HANDLE_VALUE;
  int tries = 3;
  static std::set<DWORD> RETRY_ERRORS{ ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION };

  while ((hdl == INVALID_HANDLE_VALUE) && (tries > 0)) {
    --tries;
    hdl = openDirectory(name);

    if (hdl == INVALID_HANDLE_VALUE) {
      if (RETRY_ERRORS.find(::GetLastError()) == RETRY_ERRORS.end()) {
        // don't retry if it doesn't make sense for this error code
        break;
      }
      else {
        ::Sleep(100);
      }
    }
  }

  if (hdl == INVALID_HANDLE_VALUE) {
    DWORD err = ::GetLastError();
    if (err == ERROR_NOT_FOUND) {
      // the directory might have been deleted while the search is in progress, that is not something we can
      // influence and thus should never lead to an error
      return result;
    } else if (skipInaccessible && (err == ERROR_ACCESS_DENIED)) {
      return result;
    }
    else {
      throw WinApiException(err, "CreateFile", toMB(directoryName.c_str(), CodePage::UTF8, directoryName.size()).c_str());
    }
  }

  ScopeGuard cleanHDL([hdl]() { ::CloseHandle(hdl); });

  result.reserve(1000);

  uint8_t buffer[BUFFER_SIZE];

  NTSTATUS res = STATUS_SUCCESS; // status success

  std::vector<char> detailsBuffer;
  if (details) {
    detailsBuffer.resize(sizeof(FILE_ALL_INFORMATION) + 32768);
  }

  while (res == STATUS_SUCCESS) {
    IO_STATUS_BLOCK status;

    res = NtQueryDirectoryFile(hdl
                               , nullptr
                               , nullptr
                               , nullptr
                               , &status
                               , buffer
                               , BUFFER_SIZE
                               , FileFullDirectoryInformation
                               , FALSE
                               , static_cast<PUNICODE_STRING>(UnicodeString(pattern))
                               , FALSE);
    if (res == STATUS_SUCCESS) {
      FILE_FULL_DIR_INFORMATION *info = reinterpret_cast<FILE_FULL_DIR_INFORMATION*>(buffer);
      void *endPos = buffer + status.Information;
      while (info < endPos) {
        size_t nameLength = info->FileNameLength / sizeof(wchar_t);
        if ((!skipHidden || ((info->FileAttributes & FILE_ATTRIBUTE_HIDDEN) == 0))
            && (wcsncmp(info->FileName, L".", nameLength) != 0)
            && (wcsncmp(info->FileName, L"..", nameLength) != 0)) {
          Entry file;
          file.filePath = (*directoryName.rbegin() == L'\\')
            ? directoryName + std::wstring(info->FileName, nameLength)
            : directoryName + L"\\" + std::wstring(info->FileName, nameLength);
          file.attributes = info->FileAttributes;
          file.size = info->AllocationSize.QuadPart;
          file.mtime = static_cast<uint32_t>((info->LastWriteTime.QuadPart - UNIX_EPOCH) / NS100_TO_SECOND);
          if (details) {
            FILE_ALL_INFORMATION *allInfo = (FILE_ALL_INFORMATION*)&detailsBuffer[0];
            if (getFileDetails(file.filePath, allInfo, detailsBuffer.size())) {
              file.linkCount = allInfo->StandardInformation.NumberOfLinks;
              file.id = allInfo->InternalInformation.IndexNumber.QuadPart;
              file.idStr = std::to_string(allInfo->InternalInformation.IndexNumber.QuadPart);
            }
          }

          result.push_back(file);
        }
        if (info->NextEntryOffset == 0) {
          break;
        } else {
          info = reinterpret_cast<FILE_FULL_DIR_INFORMATION*>(reinterpret_cast<uint8_t*>(info) + info->NextEntryOffset);
        }
      }
    }
  }

  return result;
}

bool walkInner(const std::wstring &basePath,
               const std::function<bool(const std::vector<Entry> &results)> &append,
               const WalkOptions &options) {
  std::vector<Entry> content = quickFindFiles(basePath, L"*", options.details.value_or(false),
                                              options.skipHidden.value_or(true),
                                              options.skipInaccessible.value_or(true));

  if (!append(content)) {
    return false;
  }

  if (options.recurse.value_or(true)) {
    for (auto &iter : content) {
      if (((iter.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
          && (((iter.attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) || !options.skipLinks.value_or(true))) {
        if (!walkInner(iter.filePath, append, options)) {
          return false;
        }
      }
    }
  }

  if (options.terminators.value_or(false)) {
    Entry terminator;
    terminator.filePath = basePath;
    terminator.attributes = 0x80000000 | FILE_ATTRIBUTE_DIRECTORY;
    terminator.size = 0;
    if (!append({terminator})) {
      return false;
    }
  }
  return true;
}

void walk(const std::wstring &basePath,
          std::function<bool(const std::vector<Entry> &results)> cb,
          const WalkOptions &options) {
  if ((NtQueryDirectoryFile == nullptr)
      || (NtQueryInformationFile == nullptr)) {
    HMODULE ntdll = ::LoadLibrary(TEXT("ntdll.dll"));
    NtQueryDirectoryFile = (NtQueryDirectoryFile_type)::GetProcAddress(ntdll, "NtQueryDirectoryFile");
    NtQueryInformationFile = (NtQueryInformationFile_type)::GetProcAddress(ntdll, "NtQueryInformationFile");
  }

  std::vector<Entry> res;

  auto append = [&res, &cb, &options] (const std::vector<Entry> &source) -> bool {
    res.reserve(res.size() + source.size());
    res.insert(res.end(), source.begin(), source.end());
    bool cont = true;
    if (res.size() >= options.threshold.value_or(1024)) {
      cont = cb(res);
      res.clear();
    }
    return cont;
  };

  bool cancelled = !walkInner(basePath, append, options);

  if (!cancelled && (res.size() > 0)) {
    cb(res);
  }
}
