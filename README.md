# Introduction

The goal of this project is to expose windows api functions to node to provide functionality that Node doesn't have otherwise.
These functions attempt to be functionally equivalent to the windows api function while still providing a somewhat more comfortable api for javascriapt (e.g. by using exceptions to report errors instead of GetLastError and using arrays of identifiers instead of bitmasks)

This module is windows-only, when writing cross-platform applications, wrap the calls on the JS side.

# Implemented Functions

Filesystem
- SetFileAttributes
- GetDiskFreeSpaceEx
- GetVolumePathName
- ShellExecuteEx
- GetPrivateProfileSection
- GetPrivateProfileSectionNames
- GetPrivateProfileString
- WritePrivateProfileString

Registry
- WithRegOpen (wrapper for RegOpenKeyEx and RegCloseKey)
- RegGetValue
- RegEnumKeys (wrapper for RegEnumKeyEx retrieving all keys in one call)
- RegEnumValues (wrapper for RegEnumValue retrieving all value names in one call, not the values themselves though)

Shell
- SHGetKnownFolderPath

Other
- GetProcessList (wrapper for Process32First/Process32Next)
- GetModuleList (wrapper for Module32First/Module32Next)

Auxiliary
- IsThisWine

# Supported OS

* Windows (duh!)
