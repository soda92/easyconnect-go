# Legacy Sangfor EasyConnect / aTrust Linux Package Security Review

Binary/package review of the Sangfor Linux clients used for EasyConnect and
aTrust. Windows installers are present locally but not yet unpacked in this pass.

The Docker build references are preserved under the gitignored
`bin/docker-easyconnect/` directory.

## 1. Artifacts

| Artifact | Source | SHA-256 |
|---|---|---|
| `easyconn_7.6.8.2-ubuntu_amd64.deb` | `shmilee/scripts` release (used by docker-easyconnect CLI) | `4d84010334bc46bb68daddda5092030ee02d17a8408b94f7ae951722c863c2b0` |
| `EasyConnect_x64_7_6_7_3.deb` | official Sangfor CDN | `ae623c6dc0354ff87afefbb770de5013bfd943051c9a653b93db708253b2f0d3` |
| `aTrustInstaller_2.5.16.20_amd64.deb` | official aTrust CDN | `fea38f63297e2c9bf853f33c566130a2f62f406926f60cf4e87f6d24a8e397d9` |

The Linux `.deb` packages do not carry a verifiable package signature in the
archive members; the install scripts run as root directly from the package.

## 2. EasyConnect Linux: setuid root services

`postinst` installs to `/usr/share/sangfor/EasyConnect` and runs
`change_authority` as root:

```sh
chmod 777 ${ResourcesDir}/logs
chmod 777 ${ResourcesDir}/conf -R
chown root:root ${ResourcesDir}/bin/ECAgent
chown root:root ${ResourcesDir}/bin/svpnservice
chown root:root ${ResourcesDir}/bin/CSClient
chmod +s ${ResourcesDir}/bin/ECAgent
chmod +s ${ResourcesDir}/bin/svpnservice
chmod +s ${ResourcesDir}/bin/CSClient
```

Both 7.6.7 and 7.6.8.2 do this. `svpnservice` and `CSClient` do not import
`setuid`/`seteuid`/`setresuid`, so the setuid-root bit is not obviously dropped.
`ECAgent` does import `seteuid`, which suggests it may drop privileges, but the
other two need explicit review.

Additional issues:

- `/usr/share/sangfor/EasyConnect/resources/conf` and `logs` are world-writable.
  Setuid/root services reading or writing those paths create configuration
  tampering and symlink-attack exposure.
- `EasyMonitor.sh` is installed into `/etc/init.d` and starts `EasyMonitor` as
  root. The daemon and logs are in the same installation tree.
- The bundles contain both Linux ELF binaries and a large macOS payload
  (Mach-O, kexts, dylibs), which increases package complexity and extraction
  surface.

ELF hardening of the Linux EasyConnect binaries is otherwise good: PIE, full
RELRO, `BIND_NOW`, non-executable stack, and stack canaries.

## 3. aTrust Linux: root services and unsafe permissions

`aTrustInstaller_2.5.16.20_amd64.deb` includes an Electron tray
(`aTrustTray`, 129 MB), native Node addons, and a root `aTrustDaemon` service.

### 3.1 Root service reads a command from `/tmp`

`/usr/lib/systemd/system/aTrustShell.service`:

```ini
[Service]
Type=oneshot
EnvironmentFile=/tmp/aTrustShell_root.conf
ExecStart=/bin/bash -c "${SHELL_CMD}"
```

A root system service executing a command sourced from `/tmp` is a critical
design. Even if the current installer does not create that file today, any
future helper or local user able to create it can inject a root command. The
file must live in a root-owned, non-writable directory and the service must not
execute arbitrary environment text.

### 3.2 `/root` permissions changed

`postinst` runs:

```sh
chmod 755 /root
```

Changing the root home directory from its secure default to world-readable
allows local users to list its contents and may expose files that rely on
directory permissions.

### 3.3 World-writable application and runtime directories

`postinst` also runs:

```sh
chmod -R 777 "${atrust_share_path}/var"
chmod -R 777 "/usr/share/sangfor/aTrust/resources/app"
```

The Electron application directory includes JavaScript, native addons, and
resource files. It is writable by every local user. The tray is launched with
`--no-sandbox` (both in `aTrustTrayStart.sh` and the binary’s fallback command),
so Chromium’s renderer sandbox is disabled. A local user can modify the app
code/native addons and influence another user’s tray session; the root daemon’s
config/runtime directory is also world-writable.

### 3.4 Root daemon and large Electron surface

`aTrustDaemon.service` starts `aTrustAgent` as root and restarts it on a broad
set of signals. The package includes a 129 MB Electron tray, many native Node
modules, `linuxHelper`, `aTrustXtunnel-64`, certificate/login tools, and UEM
components. This is a much larger attack surface than a VPN connection needs.
The `uem_installer` path also conditionally receives `chmod a+s` when present.

### 3.5 Hardening

- `aTrustAgent`, `aTrustTray2`, `ConfigUpgrade`, `PkcsLogin`, and `linuxHelper`
  are PIE with full RELRO and `BIND_NOW`, with stack canaries.
- `aTrustXtunnel-64` is non-PIE (`EXEC`), partial RELRO, no `BIND_NOW`.
- `aTrustClientTools` is a non-PIE Go executable.
- `aTrustTray` is a very large Electron binary; the tray is run with
  `--no-sandbox`.

## 4. Docker-easyconnect findings

The preserved reference (`bin/docker-easyconnect/`) is a third-party Docker
project, not an official Sangfor distribution. It contains:

- EasyConnect 7.6.3 and 7.6.7 build args for amd64, i386, arm64, and mips64el.
- aTrust 2.2.16, 2.3.10.65, 2.3.10 SP3/SP4, 2.4.10.50, and 2.5.16.20 build args
  for amd64, arm64, and mips64el.
- Official Sangfor download URLs plus the `shmilee` CLI `.deb`.

The CLI Dockerfile re-applies the vendor setuid bits:

```sh
chmod +xs ${EC_DIR}/bin/{CSClient,ECAgent,svpnservice}
```

Running the vendor postinst and setuid binaries inside a container limits host
impact, but the container still runs the vendor code as root; it is not a
substitute for fixing the client design.

## 5. Positive findings

- EasyConnect Linux binaries are PIE, full RELRO, `BIND_NOW`, NX, and canaried.
- aTrust’s main daemon/tray helpers are similarly hardened, and the package does
  not setuid-root the aTrust binaries.
- aTrust includes an anti-MITM implementation in the Go client path.
- Our Go EasyConnect/aTrust implementation avoids setuid binaries, root
  services, Electron, and browser plugins.
