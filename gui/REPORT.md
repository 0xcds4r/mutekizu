# Mutekizu GUI — implementation report

## 1. Stack and environment

* C++20, Qt 6.12 (Core, Gui, Network, Quick, QML, DBus, QuickControls2,
  Material style), CMake 4.4, Wayland.
* Verified locally: Qt 6.12.0 dev packages, Polkit 127, systemd 262,
  `libnetfilter_queue` (engine), GCC 16.
* The GUI is a separate target `mutekizu-gui`; the engine and its
  `libnfq`/nftables data path are unchanged.
* The engine/service is **not installed** in this environment
  (`/etc/mutekizu` and `mutekizu.service` absent), so real service
  start/stop and config apply are marked untested below.

## 2. Architecture

```
gui/
  src/main.cpp        app, CLI flags, screenshots, self-test
  src/backend.*       real + mock backend, D-Bus, config, doctor, logs, apply
  qml/                Material-styled Quick UI
  helper/helper.cpp   narrow root writer (pkexec), fixed files only
  tests/helper-check.sh
```

* **Real backend**:
  * service state via `org.freedesktop.systemd1` D-Bus
    (`LoadUnit`, `GetAll` properties, `StartUnit`, `StopUnit`, `RestartUnit`,
    `PropertiesChanged` subscription + 2 s polling);
  * config/domains/MSS lists read from `/etc/mutekizu/` (unprivileged read);
  * `doctor` and `validate` run as the **user**, asynchronously, via QProcess
    with fixed argv (no shell, timeout, output cap via the engine CLI);
  * journal is `journalctl -u mutekizu.service -n 200` with fixed args; access
    errors are displayed instead of a fake empty log;
  * apply runs `pkexec /usr/libexec/mutekizu-config-helper` with a JSON
    document on stdin, after `validate` and conflict checks.
* **Mock backend** (`--demo`): fake states, config, diagnostics and logs.
  The UI shows a permanent `ДЕМО` banner; no system calls are made.
  Start/stop are simulated. Screenshots use this mode.
* **Privileges**:
  * GUI never runs as root and has no `CAP_NET_ADMIN`/`CAP_NET_RAW`;
  * service control is systemd D-Bus + Polkit;
  * config write is a narrow helper only: fixed `/etc/mutekizu` paths,
    JSON schema, size limit, domain/IP validation, `O_NOFOLLOW`/`openat`,
    root ownership, `0644`, backups and rollback, not setuid; pkexec performs
    the authorization. No custom permissive Polkit rule is shipped.
* **Apply flow**: edit → validate (local + engine `validate` in a temp dir) →
  diff dialog → external-change hash check → pkexec helper → reload from disk →
  restart via D-Bus if the service is running → report the actual result.
  The GUI never generates nftables rules and never changes DNS/QUIC.

## 3. Screens

* Overview: service state, active modes, draft state, diagnostics summary,
  last error with hint, start/stop/restart.
* Domains: add/edit/delete, search, paste multiple, import/export, validation,
  duplicate detection, ASCII/punycode note.
* Settings: split/MSS toggles, split summary, MSS IP target dialog, theme,
  advanced engine parameters with ranges and explanations. `split_gap_ms`
  is marked experimental; `mss` (chunk size) is explicitly distinguished from
  MSS-clamp; multi-split overhead is explained.
* Diagnostics: async `doctor`, OK/warn/fail/unknown, raw output, export warning.
* Journal: service-scoped, level filter, pause, copy, export; no payload logs.
* About: limitations, historical results with source/date/sample size, privacy.

Keyboard: `Alt+1…6` pages; Material focus rings; no tray dependency; responsive
TabBar below 980 px; dark/light/system theme.

## 4. Verification performed

### Automated

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMUTEKIZU_GUI=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

Result: **5/5 tests pass**:

* `tls_and_strategy` (engine parser/strategy);
* `dpi_ladder_unit` (synthetic DPI corpus);
* `gui_backend_self_test` — demo start/stop transitions, invalid domains/ranges,
  CIDR rejection, demo apply, and real-mode refusal when the privileged helper
  is not installed;
* `gui_screenshot_smoke` — offscreen QML render to PNG;
* `gui_helper_check` — valid JSON accepted; invalid domain, range and CIDR
  rejected.

### Helper write (isolated user+mount namespace)

In `unshare -rm --map-root-user`, with a tmpfs over `/etc`:

* valid payload wrote `mutekizu.conf`, `domains.txt`, `mss_targets.txt`,
  mode `0644`, root-owned in the namespace;
* a symlink at `mutekizu.conf` was refused (`refusing symlink`);
* the host `/etc` was never touched. Actual host installation was not run.

### Installed-binary QML fix

The first installed build failed at startup with
`Module "Mutekizu" contains no type named "Main"`. Cause: the generated
`qmldir` used `prefer :/Mutekizu/` while the installed binary expects the
default `:/qt/qml/` prefix; the build-tree binary only worked because the QML
files were also on disk. Fixed with `RESOURCE_PREFIX "/qt/qml"` and Qt policy
QTP0001. Verified by copying the binary + engine into an otherwise empty
directory and rendering/screenshotting it there.

### Real backend, no service

`--probe-real` → `state=not-installed installed=0 config=0 helper=0`.
Screenshot `real-not-installed.png` shows the exact state; no fake success.

### Wayland and scaling

* `QT_QPA_PLATFORM=wayland` self-test and screenshot succeeded
  (`wayland-overview.png`, 958×1040).
* 150% and 200% offscreen screenshots: 1830×1230 and 2440×1640.
* Narrow layout at 820×900: sidebar replaced by tabs (`narrow-dark.png`).

### Screenshots

All except `real-not-installed.png` are **demo** and carry the `ДЕМО` badge:

```
gui/screenshots/overview.png              dark, stopped
gui/screenshots/overview-running.png      dark, running
gui/screenshots/overview-light.png        light, running
gui/screenshots/domains.png               domains editor
gui/screenshots/settings.png              settings, dark
gui/screenshots/settings-light.png        settings, light
gui/screenshots/diagnostics.png           diagnostics
gui/screenshots/logs.png                  journal
gui/screenshots/about.png                 limitations/results
gui/screenshots/narrow-dark.png           responsive 820 px
gui/screenshots/overview-150.png          150% scale
gui/screenshots/overview-200.png          200% scale
gui/screenshots/wayland-overview.png      native Wayland capture
gui/screenshots/real-not-installed.png    REAL, service absent
```

## 5. Not verified in this environment

* **systemd start/stop and restart** against a real installed unit: the unit is
  absent; the GUI correctly shows `not-installed`, but the successful Polkit
  transition was not exercised.
* **Polkit authorization/cancel** for `StartUnit`/`pkexec`: no installed
  service/helper and no interactive agent test; the error paths are implemented
  but untested end-to-end.
* **Actual config apply** via pkexec to `/etc`: helper is not installed; only
  the isolated write test above was run.
* **External CLI start/stop** and `PropertiesChanged` live updates while the
  service runs; D-Bus code is present, only the not-installed path was probed.
* **File conflict / concurrent CLI writer** and rollback after a partial
  multi-file write: code exists (hash check + helper backup/rollback), not
  exercised with a live installed config.
* **Large journal volume / journal permission denial**: the UI handles errors,
  but only the absent-service path was run.
* **Full keyboard traversal and all interactive dialogs**: not automated.
* **Installation scripts**: syntax-checked; not executed (require root).
* No claim is made that the GUI improves bypass effectiveness; historical
  results are shown as historical, with sample sizes and conditions.

## 6. User instructions

Build/run:

```bash
cd ~/mutekizu
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMUTEKIZU_GUI=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
./build/gui/mutekizu-gui --demo          # mock, no system changes
./build/gui/mutekizu-gui                 # real backend
```

Install only the GUI (engine/service remain separate):

```bash
sudo gui/install-gui.sh
# then start the GUI as your normal user
sudo gui/uninstall-gui.sh                  # removes GUI/helper only
```

The engine/service must be installed separately (`sudo scripts/install.sh`,
`systemctl enable --now mutekizu`). The GUI does not enable or start it
automatically. A Polkit authentication agent is required for start/stop and for
pkexec config writes; without it the GUI shows an explicit error.

## 7. Limitations

* `doctor` runs as the GUI user, so missing `CAP_NET_ADMIN`/`CAP_NET_RAW` is
  expected; the service itself is started by systemd with its own capabilities.
* Domain matching is ASCII/punycode; no wildcard or automatic IDN normalization.
  The domain list edits SNI targets, not DNS.
* MSS-clamp is IP-based and affects the whole upload; one IP can cover several
  sites.
* The GUI is a control surface, not a VPN/proxy and not an anonymity tool.
* If the privileged helper is not installed, apply is refused; there is no
  insecure fallback.
* Historical real-path percentages are small samples from one network/time and
  are not a prediction.
