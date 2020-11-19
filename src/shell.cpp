#include "shell.h"
#include "util.h"
#include <unordered_map>
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <Shlobj.h>

typedef struct {
  DWORD pid;
  HWND hwnd;
} WINDOWPROCESSINFO;

static const std::unordered_map<std::string, DWORD> knownFolderFlags {
  { "default", KF_FLAG_DEFAULT },
  { "force_app_data_redirection", KF_FLAG_FORCE_APP_DATA_REDIRECTION },
  { "return_filter_redirection_target", KF_FLAG_RETURN_FILTER_REDIRECTION_TARGET },
  { "force_package_redirection", KF_FLAG_FORCE_PACKAGE_REDIRECTION },
  { "no_package_redirection", KF_FLAG_NO_PACKAGE_REDIRECTION },
  { "force_appcontainer_redirection", KF_FLAG_FORCE_APPCONTAINER_REDIRECTION },
  { "no_appcontainer_redirection", KF_FLAG_NO_APPCONTAINER_REDIRECTION },
  { "create", KF_FLAG_CREATE },
  { "dont_verify", KF_FLAG_DONT_VERIFY },
  { "dont_unexpand", KF_FLAG_DONT_UNEXPAND },
  { "no_alias", KF_FLAG_NO_ALIAS },
  { "init", KF_FLAG_INIT },
  { "default_path", KF_FLAG_DEFAULT_PATH },
  { "not_parent_relative", KF_FLAG_NOT_PARENT_RELATIVE },
  { "simple_idlist", KF_FLAG_SIMPLE_IDLIST },
  { "alias_only", KF_FLAG_ALIAS_ONLY }
};

static const std::unordered_map<std::string, REFKNOWNFOLDERID> knownFolders {
  { "AccountPictures", FOLDERID_AccountPictures },
  { "AddNewPrograms", FOLDERID_AddNewPrograms },
  { "AdminTools", FOLDERID_AdminTools },
  { "AllAppMods", FOLDERID_AllAppMods },
  { "AppCaptures", FOLDERID_AppCaptures },
  { "AppDataDesktop", FOLDERID_AppDataDesktop },
  { "AppDataDocuments", FOLDERID_AppDataDocuments },
  { "AppDataFavorites", FOLDERID_AppDataFavorites },
  { "AppDataProgramData", FOLDERID_AppDataProgramData },
  { "AppUpdates", FOLDERID_AppUpdates },
  { "ApplicationShortcuts", FOLDERID_ApplicationShortcuts },
  { "AppsFolder", FOLDERID_AppsFolder },
  { "CDBurning", FOLDERID_CDBurning },
  { "CameraRoll", FOLDERID_CameraRoll },
  { "CameraRollLibrary", FOLDERID_CameraRollLibrary },
  { "ChangeRemovePrograms", FOLDERID_ChangeRemovePrograms },
  { "CommonAdminTools", FOLDERID_CommonAdminTools },
  { "CommonOEMLinks", FOLDERID_CommonOEMLinks },
  { "CommonPrograms", FOLDERID_CommonPrograms },
  { "CommonStartMenu", FOLDERID_CommonStartMenu },
  { "CommonStartMenuPlaces", FOLDERID_CommonStartMenuPlaces },
  { "CommonStartup", FOLDERID_CommonStartup },
  { "CommonTemplates", FOLDERID_CommonTemplates },
  { "ComputerFolder", FOLDERID_ComputerFolder },
  { "ConflictFolder", FOLDERID_ConflictFolder },
  { "ConnectionsFolder", FOLDERID_ConnectionsFolder },
  { "Contacts", FOLDERID_Contacts },
  { "ControlPanelFolder", FOLDERID_ControlPanelFolder },
  { "Cookies", FOLDERID_Cookies },
  { "CurrentAppMods", FOLDERID_CurrentAppMods },
  { "Desktop", FOLDERID_Desktop },
  { "DevelopmentFiles", FOLDERID_DevelopmentFiles },
  { "Device", FOLDERID_Device },
  { "DeviceMetadataStore", FOLDERID_DeviceMetadataStore },
  { "Documents", FOLDERID_Documents },
  { "DocumentsLibrary", FOLDERID_DocumentsLibrary },
  { "Downloads", FOLDERID_Downloads },
  { "Favorites", FOLDERID_Favorites },
  { "Fonts", FOLDERID_Fonts },
  { "GameTasks", FOLDERID_GameTasks },
  { "Games", FOLDERID_Games },
  { "History", FOLDERID_History },
  { "HomeGroup", FOLDERID_HomeGroup },
  { "HomeGroupCurrentUser", FOLDERID_HomeGroupCurrentUser },
  { "ImplicitAppShortcuts", FOLDERID_ImplicitAppShortcuts },
  { "InternetCache", FOLDERID_InternetCache },
  { "InternetFolder", FOLDERID_InternetFolder },
  { "Libraries", FOLDERID_Libraries },
  { "Links", FOLDERID_Links },
  { "LocalAppData", FOLDERID_LocalAppData },
  { "LocalAppDataLow", FOLDERID_LocalAppDataLow },
  { "LocalDocuments", FOLDERID_LocalDocuments },
  { "LocalDownloads", FOLDERID_LocalDownloads },
  { "LocalMusic", FOLDERID_LocalMusic },
  { "LocalPictures", FOLDERID_LocalPictures },
  { "LocalVideos", FOLDERID_LocalVideos },
  { "LocalizedResourcesDir", FOLDERID_LocalizedResourcesDir },
  { "Music", FOLDERID_Music },
  { "MusicLibrary", FOLDERID_MusicLibrary },
  { "NetHood", FOLDERID_NetHood },
  { "NetworkFolder", FOLDERID_NetworkFolder },
  { "Objects3D", FOLDERID_Objects3D },
  { "OneDrive", FOLDERID_OneDrive },
  { "OriginalImages", FOLDERID_OriginalImages },
  { "PhotoAlbums", FOLDERID_PhotoAlbums },
  { "Pictures", FOLDERID_Pictures },
  { "PicturesLibrary", FOLDERID_PicturesLibrary },
  { "Playlists", FOLDERID_Playlists },
  { "PrintHood", FOLDERID_PrintHood },
  { "PrintersFolder", FOLDERID_PrintersFolder },
  { "Profile", FOLDERID_Profile },
  { "ProgramData", FOLDERID_ProgramData },
  { "ProgramFiles", FOLDERID_ProgramFiles },
  { "ProgramFilesCommon", FOLDERID_ProgramFilesCommon },
  { "ProgramFilesCommonX64", FOLDERID_ProgramFilesCommonX64 },
  { "ProgramFilesCommonX86", FOLDERID_ProgramFilesCommonX86 },
  { "ProgramFilesX64", FOLDERID_ProgramFilesX64 },
  { "ProgramFilesX86", FOLDERID_ProgramFilesX86 },
  { "Programs", FOLDERID_Programs },
  { "Public", FOLDERID_Public },
  { "PublicDesktop", FOLDERID_PublicDesktop },
  { "PublicDocuments", FOLDERID_PublicDocuments },
  { "PublicDownloads", FOLDERID_PublicDownloads },
  { "PublicGameTasks", FOLDERID_PublicGameTasks },
  { "PublicLibraries", FOLDERID_PublicLibraries },
  { "PublicMusic", FOLDERID_PublicMusic },
  { "PublicPictures", FOLDERID_PublicPictures },
  { "PublicRingtones", FOLDERID_PublicRingtones },
  { "PublicUserTiles", FOLDERID_PublicUserTiles },
  { "PublicVideos", FOLDERID_PublicVideos },
  { "QuickLaunch", FOLDERID_QuickLaunch },
  { "Recent", FOLDERID_Recent },
  { "RecordedCalls", FOLDERID_RecordedCalls },
  { "RecordedTVLibrary", FOLDERID_RecordedTVLibrary },
  { "RecycleBinFolder", FOLDERID_RecycleBinFolder },
  { "ResourceDir", FOLDERID_ResourceDir },
  { "RetailDemo", FOLDERID_RetailDemo },
  { "Ringtones", FOLDERID_Ringtones },
  { "RoamedTileImages", FOLDERID_RoamedTileImages },
  { "RoamingAppData", FOLDERID_RoamingAppData },
  { "RoamingTiles", FOLDERID_RoamingTiles },
  { "SEARCH_CSC", FOLDERID_SEARCH_CSC },
  { "SEARCH_MAPI", FOLDERID_SEARCH_MAPI },
  { "SampleMusic", FOLDERID_SampleMusic },
  { "SamplePictures", FOLDERID_SamplePictures },
  { "SamplePlaylists", FOLDERID_SamplePlaylists },
  { "SampleVideos", FOLDERID_SampleVideos },
  { "SavedGames", FOLDERID_SavedGames },
  { "SavedPictures", FOLDERID_SavedPictures },
  { "SavedPicturesLibrary", FOLDERID_SavedPicturesLibrary },
  { "SavedSearches", FOLDERID_SavedSearches },
  { "Screenshots", FOLDERID_Screenshots },
  { "SearchHistory", FOLDERID_SearchHistory },
  { "SearchHome", FOLDERID_SearchHome },
  { "SearchTemplates", FOLDERID_SearchTemplates },
  { "SendTo", FOLDERID_SendTo },
  { "SidebarDefaultParts", FOLDERID_SidebarDefaultParts },
  { "SidebarParts", FOLDERID_SidebarParts },
  { "SkyDrive", FOLDERID_SkyDrive },
  { "SkyDriveCameraRoll", FOLDERID_SkyDriveCameraRoll },
  { "SkyDriveDocuments", FOLDERID_SkyDriveDocuments },
  { "SkyDriveMusic", FOLDERID_SkyDriveMusic },
  { "SkyDrivePictures", FOLDERID_SkyDrivePictures },
  { "StartMenu", FOLDERID_StartMenu },
  { "StartMenuAllPrograms", FOLDERID_StartMenuAllPrograms },
  { "Startup", FOLDERID_Startup },
  { "SyncManagerFolder", FOLDERID_SyncManagerFolder },
  { "SyncResultsFolder", FOLDERID_SyncResultsFolder },
  { "SyncSetupFolder", FOLDERID_SyncSetupFolder },
  { "System", FOLDERID_System },
  { "SystemX86", FOLDERID_SystemX86 },
  { "Templates", FOLDERID_Templates },
  { "UserPinned", FOLDERID_UserPinned },
  { "UserProfiles", FOLDERID_UserProfiles },
  { "UserProgramFiles", FOLDERID_UserProgramFiles },
  { "UserProgramFilesCommon", FOLDERID_UserProgramFilesCommon },
  { "UsersFiles", FOLDERID_UsersFiles },
  { "UsersLibraries", FOLDERID_UsersLibraries },
  { "Videos", FOLDERID_Videos },
  { "VideosLibrary", FOLDERID_VideosLibrary },
  { "Windows", FOLDERID_Windows },
};

uint32_t translateExecuteMask(const std::string &name) {
  static std::unordered_map<std::string, uint32_t> map{
    { "noasync", SEE_MASK_NOASYNC },
    { "flag_no_ui", SEE_MASK_FLAG_NO_UI },
    { "unicode", SEE_MASK_UNICODE },
    { "no_console", SEE_MASK_NO_CONSOLE },
    { "waitforinputidle", SEE_MASK_WAITFORINPUTIDLE }
  };

  auto iter = map.find(name);
  if (iter != map.end()) {
    return iter->second;
  }

  return 0;
}

Napi::Value SHGetKnownFolderPathWrap(const Napi::CallbackInfo &info) {
  try {
    if ((info.Length() < 1) || (info.Length() > 2)) {
      throw std::exception("Expected 1-2 parameters (folderId, flag)");
    }

    KNOWNFOLDERID folder;
    DWORD flag = KF_FLAG_DEFAULT;

    {
      std::string folderIdV8(info[0].ToString());
      auto folderId = knownFolders.find(folderIdV8.c_str());

      if (folderId == knownFolders.end()) {
        throw std::exception("Invalid folder id");
      }
      folder = folderId->second;
    }

    if (info.Length() > 1) {
      if (!info[1].IsArray()) {
        throw std::exception("Invalid flags, expected to be an array");
      }
      Napi::Array flagList = info[1].As<Napi::Array>();

      for (uint32_t i = 0; i < flagList.Length(); ++i) {
        std::string flagV8(flagList.Get(i).ToString());

        auto flagIter = knownFolderFlags.find(flagV8);
        if (flagIter == knownFolderFlags.end()) {
          throw std::exception("Invalid folder flag");
        }

        if (flagIter != knownFolderFlags.end()) {
          flag |= flagIter->second;
        }
      }
    }

    PWSTR result;

    HRESULT res = SHGetKnownFolderPath(folder, flag, nullptr, &result);

    if (FAILED(res)) {
      throw WinApiException(res, "SHGetKnownFolderPath");
    }

    Napi::String ret = Napi::String::New(info.Env(), toMB(result, CodePage::UTF8, wcslen(result)));

    CoTaskMemFree(result);

    return ret;
  }
  catch (const std::exception &err) {
    return Rethrow(info.Env(), err);
  }
}

static BOOL CALLBACK getWindowByProcess(HWND hwnd, LPARAM lParam)
{
  WINDOWPROCESSINFO *infoPtr = (WINDOWPROCESSINFO *)lParam;
  DWORD check = 0;
  BOOL br = true;
  GetWindowThreadProcessId(hwnd, &check);
  if (check == infoPtr->pid) {
    infoPtr->hwnd = hwnd;
    return false;
  }
  return true;
}

Napi::Value ShellExecuteExWrap(const Napi::CallbackInfo &info) {
  static const DWORD SW_FOREGROUND = SW_MAX + 1;
  static const std::unordered_map<std::string, DWORD> showFlagMap{
    {"hide", SW_HIDE},
    {"maximize", SW_MAXIMIZE},
    {"minimize", SW_MINIMIZE},
    {"restore", SW_RESTORE},
    {"show", SW_SHOW},
    {"showdefault", SW_SHOWDEFAULT},
    {"showminimized", SW_SHOWMINIMIZED},
    {"showminnoactive", SW_SHOWMINNOACTIVE},
    {"showna", SW_SHOWNA},
    {"shownoactivate", SW_SHOWNOACTIVATE},
    {"shownormal", SW_SHOWNORMAL},
    {"foreground", SW_FOREGROUND}
  };

  try {
    if (info.Length() != 1) {
      throw std::exception("Expected one parameter (options)");
    }

    Napi::Object args = info[0].ToObject();

    auto hasArg = [&args, &info](const char *key) {
      return args.Has(key);
    };

    if (!hasArg("file") || !hasArg("show")) {
      throw std::exception("Parameter missing (required: file, show)");
    }

    // important: has to be a container that doesn't invalidate iterators on insertion (like vector would)
    std::list<std::wstring> buffers;

    auto assignParameter = [&args, &hasArg, &buffers](LPCWSTR &target, const char *key) {
      if (hasArg(key)) {
        buffers.push_back(toWC(args.Get(key).ToString()));
        target = buffers.rbegin()->c_str();
      }
      else {
        target = nullptr;
      }
    };

    SHELLEXECUTEINFOW execInfo;
    ZeroMemory(&execInfo, sizeof(SHELLEXECUTEINFOW));
    execInfo.cbSize = sizeof(SHELLEXECUTEINFO);

    execInfo.fMask = 0;

    if ((hasArg("mask") && args.Get("mask").IsArray())) {
      Napi::Array mask = args.Get("mask").As<Napi::Array>();
      for (uint32_t i = 0; i < mask.Length(); ++i) {
        Napi::Value val = mask.Get(i);
        if (val.IsString()) {
          execInfo.fMask |= translateExecuteMask(val.ToString());
        }
        else {
          execInfo.fMask |= val.ToNumber().Uint32Value();
        }
      }
    }

    execInfo.hwnd = nullptr;
    execInfo.hInstApp = nullptr;

    assignParameter(execInfo.lpVerb, "verb");
    assignParameter(execInfo.lpFile, "file");
    assignParameter(execInfo.lpDirectory, "directory");
    assignParameter(execInfo.lpParameters, "parameters");

    std::string show = args.Get("show").ToString();
    auto iter = showFlagMap.find(show);
    if (iter == showFlagMap.end()) {
      throw Napi::RangeError::New(info.Env(), "Invalid show flag");
    }
    if (iter->second == SW_FOREGROUND) {
      execInfo.nShow = SW_RESTORE;
      execInfo.fMask |= SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_WAITFORINPUTIDLE;
      // allow any process to set the foreground window, so that if ShellExecuteEx is handled by
      // an already-running process, that process can force itself to the foreground
      ::AllowSetForegroundWindow(ASFW_ANY);
    } else {
      execInfo.nShow = iter->second;
    }

    if (!::ShellExecuteExW(&execInfo)) {
      std::string fileName = toMB(execInfo.lpFile, CodePage::UTF8, wcslen(execInfo.lpFile));
      throw WinApiException(::GetLastError(), "ShellExecuteEx", fileName.c_str());
    }

    if (iter->second == SW_FOREGROUND) {
      WINDOWPROCESSINFO info;
      info.pid = GetProcessId(execInfo.hProcess);
      info.hwnd = 0;
      // put the process into the foreground _if_ a new process was created
      ::AllowSetForegroundWindow(info.pid);
      ::EnumWindows(getWindowByProcess, (LPARAM)&info);
      if (info.hwnd != 0) {
        ::SetForegroundWindow(info.hwnd);
        ::SetActiveWindow(info.hwnd);
      }
      ::CloseHandle(execInfo.hProcess);
    }
    return info.Env().Undefined();
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

namespace WinShell {
  void Init(Napi::Env env, Napi::Object exports) {
   exports.Set("ShellExecuteEx", Napi::Function::New(env, ShellExecuteExWrap));
   exports.Set("SHGetKnownFolderPath", Napi::Function::New(env, SHGetKnownFolderPathWrap));
  }
}
