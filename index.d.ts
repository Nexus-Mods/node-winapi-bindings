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
                             | 'showminimized' | 'showminnoactive' | 'showna' | 'shownoactivate' | 'shownormal'
                             | 'foreground';

export type ShellExecuteMask = 'noasync' | 'flag_no_ui' | 'unicode' | 'no_console' | 'waitforinputidle';

export interface ShellExecuteOptions {
  file: string;
  show: ShellExecuteShow;
  verb?: ShellExecuteVerb;
  directory?: string;
  parameters?: string;
  mask?: Array<ShellExecuteMask | number>;
}

export interface ProcessEntry {
  // number of threads in this process
  numThreads: number;
  // pid
  processID: number;
  // pid of the parent process
  parentProcessID: number;
  // default priority of threads spawned in this process
  priClassBase: number;
  // name of the executable
  exeFile: string;
}

export interface ModuleEntry {
  // memory address the module is loaded at
  baseAddr: number;
  // size of the module in bytes
  baseSize: number;
  // file name of the module
  module: string;
  // path of the module
  exePath: string;
}

// get list of processes currently running
export function GetProcessList(): ProcessEntry[];
// get list of modules loaded in the specified process
export function GetModuleList(pid: number): ModuleEntry[];

// get list of main windows of the specified process
export function GetProcessWindowList(pid: number): number[];
// bring the specified window to the front (and restores it if necessary)
export function SetForegroundWindow(hwnd: number): boolean;

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
// set a value in the registry
export function RegSetKeyValue(key: Buffer | REGISTRY_HIVE, path: string, key: string, value: string | string[] | number | Buffer);
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

// get list of system-preferred UI languages
export function GetSystemPreferredUILanguages(): string[];
// get list of user-preferred UI languages (take precedence over system-preference)
export function GetUserPreferredUILanguages(): string[];
// get list of process-preferred UI languages (take precedence over user- and system-preference)
export function GetProcessPreferredUILanguages(): string[];
// set list of process-preferred UI languages (windows seem to pick the first language actually installed, so
// setting a language that the user doesn't have installed has no effect, no error gets reported)
export function SetProcessPreferredUILanguages(languages: string[]): void;


export interface ITaskRegistrationInfo {
  Author?: string;
  Date?: string;
  Description?: string;
  Documentation?: string;
  Source?: string;
  URI?: string;
}

export interface ITaskSettings {
  AllowDemandStart?: boolean;
}

export type LogonType = 'none' | 'password' | 's4u' | 'interactive_token' | 'group' | 'service_account' | 'interactive_token_or_password';

export interface IPrincipalSettings {
  DisplayName?: string;
  GroupId?: string;
  Id?: string;
  UserId?: string;
  LogonType?: LogonType;
  RunLevel?: 'lua' | 'highest';
}

export interface ITaskAction {
  Path: string;
  Arguments?: string;
  Id?: string;
  WorkingDirectory?: string;
}

export interface ITaskOptions {
  user: string;

  registrationInfo?: ITaskRegistrationInfo;
  taskSettings: ITaskSettings;
  principal?: IPrincipalSettings;

  actions: ITaskAction[];
}

export interface ITaskEntry {
  Name: string;
  Enabled: boolean;
  LastTaskResult: number;
}

// Create a task in the task scheduler. The name is unique, if a task by that name exists it will be replaced
// currently all tasks are created on the top-level. In the future we will support names like "folder\taskname"
// such that a task "taskname" is created within the task folder "folder" but this is not supported _now_, I'm
// just telling you so you don't create tasks with a \ in their name because the behaviour of that will change
export function CreateTask(name: string, options: ITaskOptions);

// get list of tasks
// Note: this lists only tasks, not subfolders. There is currently no way to get at the list of subfolders
// Also note: This silently skips any tasks that we can't access (e.g. for security reasons) so this list may
//   not be the same as what you get from the ui.
export function GetTasks(path?: string): ITaskEntry[];

// delete a task
export function DeleteTask(name: string);

// run a task
export function RunTask(name: string);

// stop a task
export function StopTask(name: string);


// return whether this process is being run on linux through wine
export function IsThisWine(): boolean;

export type FileVersionFlag = 'debug' | 'infoInferred' | 'patched' | 'prerelease' | 'privateBuild' | 'specialBuild';

export interface IFileVersionInfo {
  fileVersion: [number, number, number, number];
  productVersion: [number, number, number, number];
  flags: FileVersionFlag[];
  fileType: 'app' | 'dll' | 'drv' | 'font' | 'lib' | 'vxd';
}

/**
 * get version info about a file (has to be a supported file type of course)
 */
export function GetFileVersionInfo(filePath: string): IFileVersionInfo;

export interface IElevationToken {
  isElevated: boolean;
}

/**
 * receive process token. Currently we only support the elevation token
 * @param type determine the type of token to retrieve
 * @param pid process id of the process to query. if left undefined will retrieve the token for the running process itself
 */
export function GetProcessToken(type: 'elevation', pid?: number): IElevationToken;

export interface ILocker {
  appName: string;
  pid: number;
}

/**
 * return a list of processes that have a lock on the specified file
 */
export function WhoLocks(filePath: string): ILocker[];

export interface IEntry {
  // full path to the file
  filePath: string;
  // whether this is a directory
  isDirectory: boolean;
  // whether this is a reparse point (symbolic link or junction point)
  isReparsePoint: boolean
  // size in bytes
  size: number;
  // last modification time (as seconds since the unix epoch)
  mtime: number;
  // if the terminators option was set, this indicates whether an entry is such a terminator
  isTerminator?: boolean;
  // unique id of the file (could have collisions due to the limited range of the number type)
  id?: number;
  // stringified file id (should be unique)
  idStr?: string;
  // number of (hard-)links to the data
  linkCount?: number;
}

export interface IWalkOptions {
  // add a fake entry to the output list for each directory at the point where its
  // done. This can be useful to simplify parsing the output (default: false)
  terminators?: boolean;
  // add linkCount and id attributes to the output. This makes the walk slower (default: false)
  details?: boolean;
  // minimum number of entries per call to the progress callback (except for the last
  // invocation of course). Higher numbers should increase performance but also memory usage
  // and responsiveness for all kinds of progress indicators (default: 1024)
  threshold?: number;
  // recurse into subdirectories (default: true)
  recurse?: boolean;
  // ignore files with the "hidden" attribute (default: true)
  skipHidden?: boolean;
  // don't recurse into links (junctions), otherwise we may end in an endless loop (default: true)
  // Note: Before 2.0.0 the behavior of this flag wasn't what's documented here. This previously
  //   left out all links from the result, both directories (junctions) and files (symbolic links).
  //   Now it simply doesn't recurse into junction points but still lists them in the output
  skipLinks?: boolean;
  // skip past directories that aren't accessible without producing an error (default: true)
  skipInaccessible?: boolean;
}

/**
 * quickly read a directory (recursively by default)
 * Rationale: The typical pattern to read a directory recursively on posix and node.js is to readdir, a stat on each result to
 *   determine directories, then recurse into those.
 *   This is very inefficient on windows because stat is relatively expensive and the functions used under the hood to implement readdir
 *   already know whether a file is a directory, that information is just dropped to conform with the posix api.
 * results are returned by invoking "progress" with a chunk of data, this way you may be able to start processing while the directory read
 * is still going on. returning false from progress cancels the search, however queued results are still returned so it's likely progress
 * gets called one more time after an invocation returned false.
 */
export function WalkDir(basePath: string, progress: (entries: IEntry[]) => boolean, cb: (err: Error) => void);
export function WalkDir(basePath: string, progress: (entries: IEntry[]) => boolean, options: IWalkOptions, cb: (err: Error) => void);

interface IAccess {}

export type UserGroups = "everyone" | "owner" | "group" | "guest" | "administrator";
export type Permission = 'r' | 'w' | 'x' | 'rw' | 'rx' | 'wx' | 'rwx';

export type UserSID = string;

type AccessFunc = (sid: UserGroups | UserSID, permissions: Permission) => IAccess;

export const Access: {
  /**
   * grant access to the item
   */
  Grant: AccessFunc,
  /**
   * deny access to the item
   */
  Deny: AccessFunc,
  /**
   * revoke access to the item. This means it will fully remove the "Grant" ACE containing
   * the specified permission but it will not add a "Deny" ACE nor will it not remove
   * any Deny ACEs.
   * Thus the effective permissions after the revoke may actually still contain the
   * specified permission (if another ACE allows it) or it may take away further
   * permissions if the revoked ACE provided more permissions than specified in the revoke
   */
  Revoke: AccessFunc
} = { Grant, Deny, Revoke };

/**
 * add ACE to a file
 * @param acc the access to apply for the user
 * @param filePath path to the file to change permission
 */
export function AddFileACE(acc: IAccess, filePath: string): void;


export type Privilege = 'SeCreateTokenPrivilege'
                      | 'SeAssignPrimaryTokenPrivilege'
                      | 'SeLockMemoryPrivilege'
                      | 'SeIncreaseQuotaPrivilege'
                      | 'SeMachineAccountPrivilege'
                      | 'SeTcbPrivilege'
                      | 'SeSecurityPrivilege'
                      | 'SeTakeOwnershipPrivilege'
                      | 'SeLoadDriverPrivilege'
                      | 'SeSystemProfilePrivilege'
                      | 'SeSystemtimePrivilege'
                      | 'SeProfileSingleProcessPrivilege'
                      | 'SeIncreaseBasePriorityPrivilege'
                      | 'SeCreatePagefilePrivilege'
                      | 'SeCreatePermanentPrivilege'
                      | 'SeBackupPrivilege'
                      | 'SeRestorePrivilege'
                      | 'SeShutdownPrivilege'
                      | 'SeDebugPrivilege'
                      | 'SeAuditPrivilege'
                      | 'SeSystemEnvironmentPrivilege'
                      | 'SeChangeNotifyPrivilege'
                      | 'SeRemoteShutdownPrivilege'
                      | 'SeUndockPrivilege'
                      | 'SeSyncAgentPrivilege'
                      | 'SeEnableDelegationPrivilege'
                      | 'SeManageVolumePrivilege'
                      | 'SeImpersonatePrivilege'
                      | 'SeCreateGlobalPrivilege'
                      | 'SeTrustedCredManAccessPrivilege'
                      | 'SeRelabelPrivilege'
                      | 'SeIncreaseWorkingSetPrivilege'
                      | 'SeTimeZonePrivilege'
                      | 'SeCreateSymbolicLinkPrivilege'
                      | 'SeDelegateSessionUserImpersonatePrivilege';

/**
 * get the SID of the active user
 */
export function GetUserSID(): UserSID;

/**
 * return the sid (string form) for the specified account name
 * @param name 
 */
export function LookupAccountName(name: string);

/**
 * return the effective privilege list for the logged in user. This includes privileges granted
 * to the user group
 */
export function CheckYourPrivilege(): Privilege[];

/**
 * get list of privileges assigned to the specified user. This is different from CheckYourPrivilege!
 * this only returns the privileges assigned to the user, not their group plus it's not necessarily
 * the same as their effective privileges. If you assign a user a new privilege it will not take
 * effect until the user logged out and logged in again.
 * 
 * @param sid user sid as returned by GetUserSID or LookupAccountName
 * 
 * @note this has to be run in an elevated process
 */
export function GetUserPrivilege(sid: string): Privilege[];

/**
 * grant a user a privilege
 * @param sid user sid as returned by GetUserSID or LookupAccountName
 * @param privilege the privilege to add
 * 
 * @note this has to be run in an elevated process
 */
export function AddUserPrivilege(sid: string, privilege: Privilege): void;

/**
 * take away a privilege
 * @param sid user sid as returned by GetUserSID or LookupAccountName
 * @param privilege the privilege to remove
 * 
 * @note this has to be run in an elevated process
 */
export function RemoveUserPrivilege(sid: string, privilege: Privilege): void;

/**
 * Schedule a system shutdown
 * @param message The message to display to the user
 * @param delay the delay (in seconds) before the shutdown actually happens
 * @param askToClose whether the user will be required to close running applications. If false they will be force-closed, potentially causing data loss
 * @param reboot whether the system should reboot. If false the system turns off
 */
export function InitiateSystemShutdown(message: string, delay: number, askToClose: boolean, reboot: boolean): boolean;

/**
 * Abort a scheduled system shutdown.
 * Returns true if a shutdown was canceled, false if there wasn't one
 */
export function AbortSystemShutdown(): boolean;


