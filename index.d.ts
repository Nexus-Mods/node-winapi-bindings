// possible file attributes
// These are only the file attributes that make sense to be set by a user, stuff that the user wouldn't control
// directly, like "compressed" are not included and should be a separate type.
export type FILE_ATTRIBUTES_USER = 'archive' | 'hidden' | 'normal' | 'not_content_indexed' | 'readonly' | 'temporary';

// change the attributes on a file
export function SetFileAttributes(filePath: string, attributes: FILE_ATTRIBUTES_USER[]): void;

// query the available disk space (in bytes) on the specified path
export function GetDiskFreeSpaceEx(filePath: string): { total: number, free: number, freeToCaller: number };

// get the volume path for the specified file path
// This will usually be something like c:\ or d:\ but since ntfs supports mounting drives to subdirectories it could also
// be c:\mount\d for example.
// Please note: The path specified needs to be an existing file, otherwise the resolution appears to fall back to just
// returning tghe drive letter.
export function GetVolumePathName(filePath: string): string;

export type ShellExecuteVerb = 'edit' | 'explore' | 'find' | 'open' | 'print' | 'properties' | 'runas';
export type ShellExecuteShow = 'hide' | 'maximize' | 'minimize' | 'restore' | 'show' | 'showdefault'
                             | 'showminimized' | 'showminnoactive' | 'showna' | 'shownoactivate' | 'shownormal';

export type ShellExecuteMask = 'noasync' | 'flag_no_ui' | 'unicode' | 'no_console' | 'waitforinputidle';

export interface ShellExecuteOptions {
  file: string;
  show: ShellExecuteShow;
  verb?: ShellExecuteVerb;
  directory?: string;
  parameters?: string;
  mask?: Array<ShellExecuteMask | number>;
}

// execute external application
export function ShellExecuteEx(options: ShellExecuteOptions): void;

export function GetPrivateProfileSection(section: string, fileName: string);
export function GetPrivateProfileSectionNames(fileName: string);
export function GetPrivateProfileString(section: string, key: string, defaultValue: string, fileName: string);
export function WritePrivateProfileString(section: string, key: string, value: string, fileName: string);

export type REGISTRY_HIVE = 'HKEY_CLASSES_ROOT' | 'HKEY_CURRENT_CONFIG' | 'HKEY_CURRENT_USER' | 'HKEY_LOCAL_MACHINE' | 'HKEY_USERS';
export type REGISTRY_TYPE = 'REG_BINARY' | 'REG_DWORD' | 'REG_DWORD_BIG_ENDIAN' | 'REG_EXPAND_SZ' | 'REG_LINK' | 'REG_MULTI_SZ'
                          | 'REG_NONE' | 'REG_QWORD' | 'REG_SZ';

// open a registry handle. To ensure the handle isn't leaked it's only available within the callback.
export function WithRegOpen(hive: REGISTRY_HIVE, path: string, cb: (hkey: Buffer) => void);
// get a value from the registry using a handle created by WithRegOpen or a hive, and a path and valuename within that hkey.
export function RegGetValue(hkey: Buffer | REGISTRY_HIVE, path: string, key: string): { type: RegType, value: string | string[] | number | Buffer };
// get a list of keys within an hkey
export function RegEnumKeys(hkey: Buffer): Array<{ class: string, key: string, lastWritten: number }>;
// get a list of value names within an hkey
export function RegEnumValues(hkey: Buffer): Array<{ type: REGISTRY_TYPE, key: string }>;

export type KNOWNFOLDER =
  'AccountPictures' | 'AddNewPrograms' | 'AdminTools' | 'AllAppMods' | 'AppCaptures' | 'AppDataDesktop' | 'AppDataDocuments' |
  'AppDataFavorites' | 'AppDataProgramData' | 'AppUpdates' | 'ApplicationShortcuts' | 'AppsFolder' | 'CDBurning' | 'CameraRoll' |
  'CameraRollLibrary' | 'ChangeRemovePrograms' | 'CommonAdminTools' | 'CommonOEMLinks' | 'CommonPrograms' | 'CommonStartMenu' |
  'CommonStartMenuPlaces' | 'CommonStartup' | 'CommonTemplates' | 'ComputerFolder' | 'ConflictFolder' | 'ConnectionsFolder' | 'Contacts' |
  'ControlPanelFolder' | 'Cookies' | 'CurrentAppMods' | 'Desktop' | 'DevelopmentFiles' | 'Device' | 'DeviceMetadataStore' | 'Documents' |
  'DocumentsLibrary' | 'Downloads' | 'Favorites' | 'Fonts' | 'GameTasks' | 'Games' | 'History' | 'HomeGroup' | 'HomeGroupCurrentUser' | 
  'ImplicitAppShortcuts' | 'InternetCache' | 'InternetFolder' | 'Libraries' | 'Links' | 'LocalAppData' | 'LocalAppDataLow' | 
  'LocalDocuments' | 'LocalDownloads' | 'LocalMusic' | 'LocalPictures' | 'LocalVideos' | 'LocalizedResourcesDir' | 'Music' | 'MusicLibrary' | 
  'NetHood' | 'NetworkFolder' | 'Objects3D' | 'OneDrive' | 'OriginalImages' | 'PhotoAlbums' | 'Pictures' | 'PicturesLibrary' | 'Playlists' | 
  'PrintHood' | 'PrintersFolder' | 'Profile' | 'ProgramData' | 'ProgramFiles' | 'ProgramFilesCommon' | 'ProgramFilesCommonX64' | 'ProgramFilesCommonX86' | 
  'ProgramFilesX64' | 'ProgramFilesX86' | 'Programs' | 'Public' | 'PublicDesktop' | 'PublicDocuments' | 'PublicDownloads' | 'PublicGameTasks' | 
  'PublicLibraries' | 'PublicMusic' | 'PublicPictures' | 'PublicRingtones' | 'PublicUserTiles' | 'PublicVideos' | 'QuickLaunch' | 'Recent' | 
  'RecordedCalls' | 'RecordedTVLibrary' | 'RecycleBinFolder' | 'ResourceDir' | 'RetailDemo' | 'Ringtones' | 'RoamedTileImages' | 'RoamingAppData' | 'RoamingTiles' | 
  'SEARCH_CSC' | 'SEARCH_MAPI' | 'SampleMusic' | 'SamplePictures' | 'SamplePlaylists' | 'SampleVideos' | 'SavedGames' | 'SavedPictures' | 'SavedPicturesLibrary' | 
  'SavedSearches' | 'Screenshots' | 'SearchHistory' | 'SearchHome' | 'SearchTemplates' | 'SendTo' | 'SidebarDefaultParts' | 'SidebarParts' | 'SkyDrive' | 
  'SkyDriveCameraRoll' | 'SkyDriveDocuments' | 'SkyDriveMusic' | 'SkyDrivePictures' | 'StartMenu' | 'StartMenuAllPrograms' | 'Startup' | 'SyncManagerFolder' | 
  'SyncResultsFolder' | 'SyncSetupFolder' | 'System' | 'SystemX86' | 'Templates' | 'UserPinned' | 'UserProfiles' | 'UserProgramFiles' | 'UserProgramFilesCommon' | 
  'UsersFiles' | 'UsersLibraries' | 'Videos' | 'VideosLibrary' | 'Windows';

export type KNOWNFOLDER_FLAG =
  "force_app_data_redirection" | "return_filter_redirection_target" | "force_package_redirection" | "no_package_redirection" |
  "force_appcontainer_redirection" | "no_appcontainer_redirection" | "create" | "dont_verify" | "dont_unexpand" | "no_alias" | "init" |
  "default_path" | "not_parent_relative" | "simple_idlist" | "alias_only";

// get a known folder path
export function SHGetKnownFolderPath(folder: KNOWNFOLDER, flag?: KNOWNFOLDER_FLAG[]): string;

