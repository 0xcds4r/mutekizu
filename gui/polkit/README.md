# Polkit

No custom action/policy file is installed by this GUI.

* Starting/stopping/restarting `mutekizu.service` goes through the systemd
  D-Bus API. systemd itself checks the standard Polkit action
  `org.freedesktop.systemd1.manage-units`; the desktop authentication agent
  prompts the user.
* Writing `/etc/mutekizu/*` goes through `pkexec` and
  `/usr/libexec/mutekizu-config-helper`. pkexec uses the standard Polkit
  action `org.freedesktop.policykit.exec`; no permissive custom rule is
  shipped, and the helper is root-owned, not setuid.
* The GUI never requests or stores a sudo password and has no fallback to a
  less secure path when no authentication agent is available.

## Opt-in passwordless rule

`scripts/install-all.sh --polkit-noauth` (or
`gui/install-gui.sh --polkit-noauth`) installs
`49-mutekizu-wheel.rules`. It matches only local, active members of `wheel` or
`sudo` — users who can already become root — and only:

* `org.freedesktop.systemd1.manage-units` for `mutekizu.service`;
* `org.freedesktop.policykit.exec` for the fixed root-owned
  `/usr/libexec/mutekizu-config-helper`.

It does not grant a shell, arbitrary systemd units, arbitrary pkexec programs,
or root access to the GUI. This is opt-in, not installed by default.
