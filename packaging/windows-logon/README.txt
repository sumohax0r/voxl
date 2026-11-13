Voxl Windows desktop sign-in (opt-in)

This provider supports a single allowed Windows account per Voxl console instance.
Voxl must run as SYSTEM in the active console session, not inside an RDP session.
The normal Windows password providers remain installed; no provider is filtered,
no RDP policy is changed, and no Windows password is stored on disk.

Install the bridge with install-windows-logon.ps1 from the build artifact, then
add --windows-sign-in=true to the existing --auth-mode=os --auth-users=ai launcher.
The DLL resides in the protected Program Files/VoxlLogon directory.
Keep uninstall-windows-logon.ps1 available via RDP for rollback.
A LogonUI instance that was already open may need to be recreated before it
loads the newly registered provider. Do not reboot or sign users out silently.

Voxl submits credentials once to the Windows logon interface over a local-only,
SYSTEM-only named pipe. Windows performs the actual interactive logon. The web
session is issued only after that user's console desktop is open. Failed,
expired, conflicting and unavailable logons do not grant desktop access.

Session policy:
- Any active/connecting RDP session blocks automatic sign-in.
- A disconnected session belonging to the authenticated account is resumed.
  Its open applications are preserved. The login page retries automatically
  while the supervisor follows the console-session change.
- Another account already on the console blocks sign-in.
- Voxl never disconnects an active RDP session or signs another user out.
  WTSConnectSession is used only for the authenticated account after verifying
  that its session is disconnected and no RDP viewer is active.
- A newly active RDP connection revokes browser sessions; it is not disconnected.
- Secure desktop changes and transient DXGI capture failures retry in the existing
  server process, preserving browser sessions and avoiding manual refresh.

Verification required before production deployment:
1. On an isolated Windows test machine, install without disabling system providers.
2. Reject sign-in while an RDP session is active; verify RDP remains connected.
3. Resume the target account's disconnected session without closing its apps.
   Verify the browser completes sign-in without a manual refresh.
4. With no conflicting session, submit browser credentials from the signed-out
   console; verify Windows desktop appears and video/input recover without reload.
5. Lock Windows and repeat; verify UAC, lock/unlock, wrong and disabled accounts.
6. Verify rollback through the normal password provider and RDP.

The CMake/CTest contract checks do not replace interactive LogonUI testing.
