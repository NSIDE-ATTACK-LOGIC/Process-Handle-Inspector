# Process Handle Inspector
This is a small proof of concept program that prints the permissions associated with a process handle.

## How It Works
A handle to the target process is opened (currently `lsass.exe`) via the `OpenProcess` WinAPI. The obtained handle is then passed to the `NtQueryObject` API, which returns an `objectInfo` struct that contains the `GrantedAccess` field. This field is a bit mask where each bit represnts a permission listed in the [official documentation](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).

