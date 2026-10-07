# Remove Windows Package Manager (winget)

`Remove-WindowsPackageManager.ps1` remotely removes Windows Package Manager
(winget / App Installer, `Microsoft.DesktopAppInstaller`) from many Windows 11
machines at once. It doesn't need the Microsoft Store.

It runs from Windows PowerShell 5.1 as an administrator and reaches each machine over WinRM. On each one it
creates a temporary scheduled task that runs as SYSTEM. That task:

1. Removes the provisioned package, so new user profiles don't get it.
2. Removes the installed package for all user profiles.
3. With `-DisablePolicy`, also sets the `EnableAppInstaller = 0` policy.

The removal runs locally as SYSTEM because `Remove-AppxPackage` fails inside a
remote WinRM session with error `0x80073D19`.

## Usage

1. Copy `machines.example.txt` to `machines.txt` in the same folder as the script.
   Put one computer name per line. Lines starting with `#` are skipped.
2. Do a dry run. This only reports what's installed and changes nothing:

   ```powershell
   .\Remove-WindowsPackageManager.ps1 -ReportOnly
   ```

3. Run the removal:

   ```powershell
   .\Remove-WindowsPackageManager.ps1 -DisablePolicy
   ```

| Parameter | Default | Purpose |
|---|---|---|
| `-ComputerListPath` | `machines.txt` next to the script | List of target machines |
| `-ReportOnly` | off | Report only; change nothing |
| `-DisablePolicy` | off | Set the policy that disables App Installer / winget |
| `-Credential` | current user | Admin credentials for the targets |
| `-ThrottleLimit` | 20 | Machines processed in parallel |
| `-TimeoutSeconds` | 600 | Per-machine wait for the removal task |
| `-ReportPath` | `.\WinGetRemoval_<timestamp>.csv` | CSV results report |

The CSV report gives each machine a status: `Removed`, `StillPresent`, `Error`,
`ReportOnly` or `Unreachable`.

## Requirements

- WinRM must be enabled on the target machines. It's on by default for domain-joined
  machines; otherwise run `Enable-PSRemoting -Force` on each one or enable it via GPO.
- If running scripts is blocked, allow it for the current PowerShell window only:
  `Set-ExecutionPolicy -Scope Process Bypass -Force`

## Notes

- Removal can't be undone from the Store. To put winget back, sideload the
  App Installer `.msixbundle` from the
  [winget-cli releases](https://github.com/microsoft/winget-cli/releases).
- A Windows feature update may reinstall App Installer. To keep it disabled, use
  `-DisablePolicy` or set the GPO *Administrative Templates → Windows Components →
  Desktop App Installer → Enable App Installer = Disabled*.
