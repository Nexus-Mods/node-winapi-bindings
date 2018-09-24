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
