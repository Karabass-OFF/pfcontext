# pfcontext

## Purpose of the project
Automation of the initial configuration of a pfSense virtual machine deployed in OpenNebula. The scripts read the `context.sh` file from the VM's virtual CD-ROM and, based on the provided variables, update `config.xml`, configure network interfaces, pfSense services, and FRR/BGP components. This enables a ready-to-use router immediately after the VM's first boot without manual intervention.

## Repository structure
| Path | Description |
| --- | --- |
| `pfSense/INSTALL` | Brief checklist for deploying the context scripts package on pfSense. |
| `pfSense/etc/rc.initial` | Modified `rc.initial` which, during the first ~120 seconds of uptime, sequentially runs `/etc/context.d/modules/ResizeZfs` and `ContextOnly`, and records successful start in `/var/run/contextallrun_started`. |
| `pfSense/etc/context.d/ContextOnly` | Main module: reads `context.sh`, applies network and system settings and calls child modules. |
| `pfSense/etc/context.d/VERSION` | Text file with the package version shown in logs. |
| `pfSense/etc/context.d/modules/ResizeZfs` | Expands ZFS partition and pool when the virtual disk is enlarged. |
| `pfSense/etc/context.d/modules/addsshkey.sh` | Adds the public key from `SSH_PUBLIC_KEY` to `/root/.ssh/authorized_keys` and to `config.xml` (base64). |
| `pfSense/etc/context.d/modules/bgp` | Integration with FRR/BGP and incremental routing updates. |
| `pfSense/etc/context.d/modules/ipsec.sh` | Generates and idempotently updates IPsec tunnels, manages strongSwan and invokes plugins. |
| `pfSense/etc/context.d/modules/ipsec-plugins/firewall-rules.sh` | Creates/updates IKE/NAT‑T/ESP rules on Phase1 interfaces and generic allow‑all rules for IPsec/enc0. |
| `pfSense/etc/context.d/modules/ipsec-plugins/strat-nonblok.sh` | Immediately initiates all IPsec connections via `swanctl` in non-blocking mode. |
| `pfSense/etc/context.d/modules/mgmt.sh` | Manages the dedicated MGMT interface: aliases, firewall rules and disabling anti‑lockout. |
| `pfSense/etc/context.d/modules/nat.sh` | Configures outbound NAT (automatic/hybrid/advanced/disabled) and, if needed, adds an allow‑any rule on the chosen interface excluding the interface IP. |
| `pfSense/etc/context.d/modules/pfctl.sh` | Manages WAN parameters (gateway, blockpriv/blockbogons) and decides if interfaces need restarting. |
| `pfSense/etc/context.d/modules/reload-iface.sh` | Runs `rc.reload_all` / `restartallwan` and toggles `pfctl` state according to flags. |
| `pfSense/etc/context.d/modules/pfctl_off` | Cron script: controls disabling `pfctl` via PID file `/var/run/pfctlcontext.pid`. |
| `pfSense/etc/context.d/modules/sync-conf.sh` | Compares the working copy of `config.xml` with the original and saves changes if a delta exists. |
| `pfSense/etc/devd/context.conf` | `devd` rules to run the context on CD‑ROM/disk/interface events. |
| `pfSense/etc/cron.d/context` | Cron tasks: `pfctl_off` runs every minute; at boot (`@reboot`) after 180 seconds ensures presence of `/etc/context.d/firstboot` (modules continue to run until `FIRST_BOOT` is switched to `NO`). |
| `pfSense/etc/phpshellsessions/ChangePassTool` | pfSense script for changing the `admin` password, used by the context. |

## Execution order and module interactions
1. **pfSense boot and early commands.** The patched `rc.initial` adds a sequential call to `/etc/context.d/modules/ResizeZfs` and `ContextOnly`, so the scripts start in the normal boot chain immediately after the configuration is mounted.
2. **Hardware event handling.** `devd` triggers `ContextOnly` when a CONTEXT ISO is inserted, triggers `ResizeZfs` on disk size changes, and records network interface changes in `/etc/context.d/net.pid`.
3. **Main module: ContextOnly.**
   - Mounts the CD-ROM (`/dev/cd0`) at `/mnt/context`, reads `context.sh`, backs up `config.xml`, prepares helper `get_ctx_var` and the `xmlstarlet` working file.
   - Parses required interfaces (MACs, types), clears the `<interfaces>` section in `config.xml` if needed, maps MAC addresses to logical roles (LAN/WAN/OPT), writes IP/mask/gateway entries and updates configuration.
   - Collects DNS addresses, sets the hostname, builds the `RC_RELOAD_IFACE` and `PFCTL` flags so downstream modules know what to restart; updates the `admin` password, unmounts the CD-ROM and launches the BGP module if available.
   - If `SSH_PUBLIC_KEY` is present, encodes the key in Base64, writes it to `config.xml` (the `admin` user section) and appends it to `/root/.ssh/authorized_keys` so the key is available immediately after initialization.
   - After applying changes it calls `modules/sync-conf.sh`, which diffs the working `config.xml` against the original and saves changes only if a delta exists.
4. **BGP module.** Launched from `ContextOnly`, it performs full dependency checks for FRR, loads `context.sh` if needed, generates `config.xml` via PHP, and applies runtime changes using `vtysh`. To avoid unnecessary changes it stores checksums and the state of networks/peers under `/var/run/context-bgp.*`.
5. **IPsec module (`modules/ipsec.sh`).** When `CONTEXT_IPSEC_ENABLE=YES` it reads tunnel definitions, applies Phase1/Phase2 defaults per index, idempotently creates or updates `phase1`/`phase2` sections in `config.xml`, calls `ipsec_configure()`, manages strongSwan and initiates connections via `swanctl`. Built-in plugins (`ipsec-plugins/firewall-rules.sh` and `ipsec-plugins/strat-nonblok.sh`) auto-create IKE/NAT-T/ESP rules on the required interfaces and immediately run `swanctl --initiate` in non-blocking mode.
6. **NAT module (`modules/nat.sh`).** When `NAT_ENABLE=YES` it verifies the presence of the interface specified by `NAT_IF`, sets the outbound NAT mode (automatic/hybrid/advanced/disabled) and records the result in `config.xml`.
7. **Service restarts and pfctl state (`modules/pfctl.sh`, `modules/reload-iface.sh`, `modules/pfctl_off`).** `pfctl.sh` manages WAN parameters (removes default route when BGP is enabled, toggles `blockpriv`/`blockbogons`, computes a hash of the `<interfaces>` section), while `reload-iface.sh` reacts to `RC_RELOAD_IFACE` and `PFCTL` flags: it calls `rc.reload_all`/`restartallwan`, enables or disables pfctl and, if needed, creates the PID file `/var/run/pfctlcontext.pid`. The cron job `modules/pfctl_off` checks that PID file every minute and keeps pfctl disabled until initialization completes.
8. **Management-interface module (`modules/mgmt.sh`).** Activated when `MGMT_ENABLE=YES` in `context.sh`: it converts the chosen logical interface `MGMT_IF` into managed-access mode, disables the webGUI anti-lockout, removes the gateway, synchronizes the `MGMT_PORTS` alias, builds the `[MGMT]` ACL from `MGMT_SRC` and adds a blocking rule `block any → mgmtIP` on affected interfaces. When `MGMT_ENABLE=NO` it reverts these changes and restores the previous configuration.
9. **ResizeZfs.** Can run at boot or on `devd` events; it expands the pfSense ZFS partition and pool if free space is detected and the GPT is intact.

The initial run is now performed by the standard pfSense mechanism. Control over the `bgp`, `mgmt.sh`, `ipsec.sh` and `nat.sh` modules is governed by the presence of the `/etc/context.d/firstboot` flag combined with the `FIRST_BOOT` variable: if the flag is absent the block is forced to run; if the flag exists the run is skipped only when `FIRST_BOOT=NO` in `context.sh` (setting `FIRST_BOOT=YES` forces a rerun).

## Installation process
1. Follow the prompts in `pfSense/INSTALL`.
2. Enable early context startup via `/etc/rc.initial`.
3. If needed, clear logs/backups (optional step from the original instructions).
4. Reboot the pfSense device to trigger the new initialization sequence.

## Context variables

All parameters are defined in `context.sh`, which is sourced early in the boot process. Below are the user variables grouped by function.

### System / Service
| Variable | Purpose |
| --- | --- |
| `SET_HOSTNAME` | Hostname written to the system and to `config.xml`. |
| `RC_RELOAD_IFACE` | Controls restarting services/interfaces after changes to `config.xml`. |
| `FIRST_BOOT` | Controls execution of primary modules (`bgp`, `mgmt.sh`, `ipsec.sh`, `nat.sh`). Default `NO` skips these modules on subsequent runs after the initial initialization; set to `YES` temporarily to force a re-run. |

### Network
- `ETHERNETx_TYPE` — required role (`lan`, `wan`, `optN`); determines the `<interfaces>` section in `config.xml`.

### Disk
- No additional variables required — `ResizeZfs` automatically expands the ZFS pool when free space is detected.

### Firewall and access
- `PASSWORD_ROOT` or `PASSWORD` — new `admin` password applied via `ChangePassTool`.
- `SSH_PUBLIC_KEY` — public SSH key for `admin` (encoded to Base64 and written to `config.xml`, also appended to `/root/.ssh/authorized_keys`).
- `PFCTL` — target firewall state (`YES`/`NO`) applied by `reload-iface.sh`.
- `BLOCK_PRIVATE_NETWORKS` — keeps `blockpriv` on the WAN when `YES` (default `YES`); set `NO` to remove the rule.
- `BLOCK_BOGON_NETWORKS` — controls `blockbogons` on the WAN: `YES` keeps the rule (default), `NO` removes it.

### NAT (outbound)
- `NAT_ENABLE` — enables application of `modules/nat.sh` (set to `YES`).
- `NAT_IF` — logical name of the external pfSense interface used for NAT (e.g., `wan`).
- `NAT_MODE` — outbound NAT mode (`automatic`, `hybrid`, `manual`, `disabled`). The script maps these values to pfSense modes (uses `advanced` in place of `manual`).
- `FW_IF` — the interface whose network is automatically used as the source when creating the outbound NAT rule `context-auto-outbound`, and on which a firewall rule "allow any → NOT <interface IP>" is created; default is `opt1`.

### Management interface
- `MGMT_ENABLE` — enables (`YES`) or disables (`NO`) application of the `mgmt.sh` module for the selected interface.
- `MGMT_IF` — logical pfSense interface name (`lan`, `wan`, `optN`) for which access rules are configured and the gateway is removed.
- `MGMT_PORT` — comma-separated list of TCP ports used to build the `MGMT_PORTS` alias and allow access to webGUI/SSH; ICMP is added automatically.
- `MGMT_SRC` — comma-separated list of source addresses. Supported formats: `iface:any|net`, CIDR/hosts, and combinations like `iface:CIDR`; an Allow ICMP/TCP rule is created for each entry.
- `MGMT_SRC_DEFAULT_IF` — pfSense interface to associate sources that lack an explicit `iface:` (defaults to `MGMT_IF`).

### IPsec
- `CONTEXT_IPSEC_ENABLE` — enables application of the `ipsec.sh` module (default `NO`; set to `YES` if tunnels are required).
- `CONTEXT_IPSEC_TUNNELS` — number of tunnels to process; indexes are assigned automatically for each tunnel.
- `IPSEC_P1_*` / `IPSEC_P2_*` — global Phase‑1/Phase‑2 defaults (IKE version, encryption, hash, DH group, PFS, lifetimes) inherited by tunnels unless overridden by `CONTEXT_IPSEC_<N>_*`.
- `CONTEXT_IPSEC_<N>_REMOTE`, `PSK`, `LOCALID`, `LOCAL_NET`, `REMOTE_NET` — required parameters for tunnel with index `N`; additional `P1_*`/`P2_*` keys may be specified per tunnel.
- The module rebuilds configuration only when changes are detected and, after applying updates, calls `ipsec_configure()` and `swanctl --initiate`. Therefore the context can be safely re-run to verify or refresh IPsec settings.

### Automation of restarts
- `RC_RELOAD_IFACE` — restart WAN interfaces without a full system reboot.

### BGP and FRR
- `BGP_ENABLE` — enable the `bgp` module.
- `BGP_AS` / `BGP_ROUTER_ID` — AS number and Router‑ID (required when BGP is enabled).
- `BGP_NEIGHBORS` — neighbors in the format `IP,ASN,password` (separated by spaces or `;`).
- `BGP_NETWORKS_TO_DISTRIBUTE` — networks to advertise (`CIDR,RouteMap`).
- `BGP_RMAP_DEFAULT` — default route‑map applied to neighbors and networks.
- `BGP_ADJACENCY_LOG` — enable session logging in FRR.
- `BGP_REDIST_CONNECTED` / `BGP_REDIST_STATIC` / `BGP_REDIST_KERNEL` — control redistribution of connected/static/kernel routes.
- `FRR_DEFAULT_ROUTER_ID` — FRR router‑id used when BGP settings are absent.
- `FRR_MASTER_PASSWORD` — vtysh password; can be used together with `FRR_PASSWORD_ENCRYPT` (`on` — store the password encrypted).

## Example `context.sh` file
```sh
# Bind interfaces by MAC addresses
ETH0_MAC="00:50:56:aa:bb:01"
ETH0_TYPE="wan"
ETH0_IP="203.0.113.10"
ETH0_MASK="255.255.255.252"
ETH0_GATEWAY="203.0.113.9"
ETH0_DNS="8.8.8.8 1.1.1.1"

ETH1_MAC="00:50:56:aa:bb:02"
ETH1_TYPE="lan"
ETH1_IP="192.168.10.1"
ETH1_MASK="255.255.255.0"
ETH1_DNS="192.168.10.1"

SET_HOSTNAME="pfsense-demo"
PFCTL="NO"
BLOCK_PRIVATE_NETWORKS="YES"
BLOCK_BOGON_NETWORKS="NO"
PASSWORD="SuperSecret123"
SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3Nz... user@example"

# BGP and FRR
FRR_DEFAULT_ROUTER_ID="192.0.2.1"
BGP_ENABLE="YES"
BGP_AS="65001"
BGP_ROUTER_ID="192.0.2.1"
BGP_RMAP_DEFAULT="ALL"
BGP_NETWORKS_TO_DISTRIBUTE="192.168.10.0/24,ALL"
BGP_NEIGHBORS="198.51.100.2,65002,s3cr3t"

# NAT
NAT_ENABLE="YES"
NAT_MODE="hybrid"
NAT_IF="wan"
NAT_SRC="192.168.10.0/24 192.168.201.0/24"
FW_IF="opt1"

# MGMT
MGMT_ENABLE="YES"
MGMT_IF="lan"
MGMT_PORT="22,443,4443"
```

### Module logs

The context scripts produce a single "text trace" written to the file specified by the `LOG` variable (default: `/var/log/context.log`). This is sufficient to inspect the execution sequence of `ContextOnly`, determine the order in which modules ran, and see which input variables were processed. If necessary, change the path directly in the header of `pfSense/etc/context.d/ContextOnly` and, if a unified log is required, replicate the same line, e.g. `LOG="/var/log/context.log"`, in the child modules (`ResizeZfs`, `pfctl_off`, `nat.sh`, `ipsec.sh`, etc.).

| File | Source | What is logged |
| --- | --- | --- |
| `/var/log/context.log` | `pfSense/etc/context.d/ContextOnly`, `pfSense/etc/context.d/modules/*` | Initialization sequence: ISO mounting, interface configuration, DNS, NAT, IPsec, pfctl, password update, module calls and `ResizeZfs` output. |
| `/var/log/context.log` | `pfSense/etc/context.d/modules/bgp` | Variable dump, FRR dependency checks, progress of incremental neighbor and network updates, errors applying changes via `vtysh`. |
| User-specified file via `LOG` variable | `pfSense/etc/context.d/modules/ResizeZfs`, `pfSense/etc/context.d/modules/pfctl_off` | Output about ZFS expansion and pfctl management; by default redirected to `/dev/null`, specify a path if logging is required. |

Note: IPsec plugins (`ipsec.sh`, `ipsec-plugins/*`) additionally write markers like `[context-IPSEC]` to the same `LOG` file. This helps trace Phase1/Phase2 generation, `ipsec_configure()` execution and `swanctl --initiate` without enabling extra logging levels in pfSense.