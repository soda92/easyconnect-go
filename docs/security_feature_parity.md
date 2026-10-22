# EasyConnect / aTrust Security Feature Parity

Comparison between the Sangfor Linux packages and the Go implementation.
Vendor package defects are in
[`legacy_client_binary_defects.md`](legacy_client_binary_defects.md).

## 1. Parity matrix

| Control | Sangfor Linux packages | Go client / vpngui | Status |
|---|---|---|---|
| Linux privilege model | EasyConnect sets setuid-root on `ECAgent`, `svpnservice`, `CSClient`; root EasyMonitor service | No setuid; userspace mode unprivileged; TUN path uses Wintun or kernel TUN with elevation | **Much better** |
| Linux config/log permissions | EasyConnect `conf`/`logs` 777; aTrust app/var 777 | No install script or world-writable app tree | **Much better** |
| aTrust root shell service | `aTrustShell.service` executes `${SHELL_CMD}` from `/tmp/aTrustShell_root.conf` | No equivalent | **Much better** |
| `/root` permissions | aTrust postinst does `chmod 755 /root` | No change | **Much better** |
| Electron/browser surface | aTrust 129 MB Electron tray, `--no-sandbox`, native Node addons | Go-only client | **Much better** |
| EasyConnect ELF hardening | PIE, full RELRO, BIND_NOW, NX, canary | Go PIE, full RELRO, BIND_NOW | Parity |
| aTrust ELF hardening | Mostly PIE/full RELRO; `aTrustXtunnel-64` non-PIE; Go tool non-PIE | Go uses PIE | Better |
| Gateway TLS validation | EasyConnect installs a CA via `ECAgent --install-import-cert`; aTrust has anti-MITM but also insecure TLS setup | `InsecureSkipVerify: true` throughout; no CA/pin | **Missing / weaker** |
| Certificate pinning | Vendor imports a CA; aTrust anti-MITM certificate check | No CA/pin; only aTrust anti-MITM where server enables it | **Missing** |
| Client certificate auth | EasyConnect supports a certificate in its auth options; provider does not expose it | Library supports `tls.Certificate`, but vpngui provider exposes only user/password/TOTP | **Provider gap** |
| Windows signing | Windows installers and main clients are signed by Sangfor | Release executable unsigned | **Missing** |
| Windows package hygiene | Debug CRT DLLs, unsigned SQLite, IE BHO, large bundled module set | No debug CRT, SQLite, BHO, or module installers | **Better** |
| Package integrity | Linux `.deb` files are unsigned; install scripts run as root | Locally built package; Windows exe unsigned | Weak on both sides |
| Auto-update | Vendor updater/browser components present | No auto-updater | Smaller attack surface |

## 2. Required fixes

### P0 — Stop forcing `InsecureSkipVerify` for EasyConnect

`easyconnect-go` sets `InsecureSkipVerify: true` in:

- `client/easyconnect/client.go`
- `client/easyconnect/protocol.go`
- `client/easyconnect/request.go`
- `client/atrust/auth/auth.go`
- `client/atrust/tls.go`

The vendor EasyConnect installer imports a CA with
`ECAgent --install-import-cert`, and aTrust has an anti-MITM certificate
identity check. A blanket skip means the Go client loses those protections.

Required:

1. default to system-root verification,
2. add a CA bundle/pin option for the Sangfor gateway,
3. keep `ServerName` set on all control and data connections,
4. make insecure mode explicit and profile-scoped,
5. add tests for untrusted and pinned certificates.

### P1 — Expose client-certificate auth in the provider

The EasyConnect library already accepts `tls.Certificate`, but the vpngui
provider’s `AuthOptions` only exposes username/password/TOTP. Add certificate
and key selection where deployments require mutual TLS.

### P1 — Sign Windows releases

The Go Windows executable is unsigned while the vendor Windows installers are
signed. Add Authenticode and timestamping.

### P2 — Keep the reduced Linux packaging

Do not reproduce the vendor setuid trio, root EasyMonitor, aTrust root shell
service, 777 app/config trees, or Electron tray. The Go client’s lack of these
components is a security advantage.

## 3. Docker-easyconnect reference

The third-party Docker project is useful for enumerating official Linux
packages, but it does not fix their security model:

- EasyConnect 7.6.3/7.6.7 for amd64, i386, arm64, mips64el.
- aTrust 2.2.16, 2.3.10.65, 2.3.10 SP3/SP4, 2.4.10.50, 2.5.16.20 for amd64,
  arm64, and mips64el.
- The CLI image reapplies the EasyConnect setuid bits inside the container.

Use it as a package-source index, not as a trusted client.
