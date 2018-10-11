// possible file attributes
// These are only the file attributes that make sense to be set by a user, stuff that the user wouldn't control
// directly, like "compressed" are not included and should be a separate type.
export type FILE_ATTRIBUTES_USER = 'archive' | 'hidden' | 'normal' | 'not_content_indexed' | 'readonly' | 'temporary';

// change the attributes on a file
export function SetFileAttributes(filePath: string, attributes: FILE_ATTRIBUTES_USER[]): void;

// query the available disk space (in bytes) on the specified path
export function GetDiskFreeSpaceEx(filePath: string): { total: number, free: number, freeToCaller: number };

export type ShellExecuteVerb = 'edit' | 'explore' | 'find' | 'open' | 'print' | 'properties' | 'runas';
export type ShellExecuteShow = 'hide' | 'maximize' | 'minimize' | 'restore' | 'show' | 'showdefault'
                             | 'showminimized' | 'showminnoactive' | 'showna' | 'shownoactivate' | 'shownormal';

export interface ShellExecuteOptions {
  file: string;
  show: ShellExecuteShow;
  verb?: ShellExecuteVerb;
  directory?: string;
  parameters?: string;
}

// execute external application
export function ShellExecuteEx(options: ShellExecuteOptions): void;

export function GetPrivateProfileSection(section: string, fileName: string);
export function GetPrivateProfileSectionNames(fileName: string);
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
