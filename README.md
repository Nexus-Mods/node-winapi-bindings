# Introduction

The goal of this project is to expose windows api functions to node to provide functionality that Node doesn't have otherwise.
These functions mostly attempt to be functionally equivalent to the windows api function while still providing a somewhat more comfortable api for javascript (e.g. by using exceptions to report errors instead of GetLastError and using arrays of identifiers instead of bitmasks)

This module is windows-only, when writing cross-platform applications, wrap the calls on the JS side.

# Implemented Functions

Filesystem
- SetFileAttributes
- GetDiskFreeSpaceEx
- GetVolumePathName
- GetFileVersionInfo (partial)

Ini
- GetPrivateProfileSection
- GetPrivateProfileSectionNames
- GetPrivateProfileString
- WritePrivateProfileString

Registry
- WithRegOpen (wrapper for RegOpenKeyEx and RegCloseKey)
- RegGetValue
- RegEnumKeys (wrapper for RegEnumKeyEx retrieving all keys in one call)
- RegEnumValues (wrapper for RegEnumValue retrieving all value names in one call, not the values themselves though)
- RegSetKeyValue

Shell
- SHGetKnownFolderPath
- ShellExecuteEx

Language
- GetSystemPreferredUILanguages
- GetUserPreferredUILanguages
- GetProcessPreferredUILanguages
- SetProcessPreferredUILanguages

Tasks (wrappers for the ITaskFolder interface)
- CreateTask
- GetTasks
- DeleteTask
- RunTask
- StopTask

Processes
- GetProcessList (wrapper for Process32First/Process32Next)
- GetModuleList (wrapper for Module32First/Module32Next)
- GetProcessToken (wrapper for OpenProcessToken, very limited)
- GetProcessWindowList (return HWND all windows of a process)
- SetForegroundWindow

Permissions (these are much higher abstractions than usual)
- AddFileACE
- GetUserSID

Auxiliary
- IsThisWine (returns true if process is being run in wine)
- WhoLocks (given a file path, returns list of processes with a lock on the file)
- WalkDir (recursive directory walk (more efficient on windows than the usual readdir/stat algorithm))

App Container
- CreateAppContainer (wrapper for CreateAppContainerProfile)
- DeleteAppContainer (wrapper for DeleteAppContainerProfile)
- GrantAppContainer (wrapper for Get(Named)SecurityInfo/SetEntriesInAcl/Set(Named)SecurityInfo)
- RunInContainer (wrapper for CreateProcess using an app container)

# Supported OS

* Windows (duh!)
