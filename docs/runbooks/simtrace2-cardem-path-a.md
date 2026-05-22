# SIMtrace2 cardem -- Path A bring-up

**Audience.** A developer comfortable with Linux and USB but new to
SIMtrace2 and PC/SC.
**Companion documents.**
- Research record: [../specs/simtrace2-cardem-research.md](../specs/simtrace2-cardem-research.md)
- Workstreams plan: [../specs/simtrace2-cardem-workstreams.md](../specs/simtrace2-cardem-workstreams.md)

## 1. What this is

Path A is a four-process bridge that lets `simrs` serve a SIM to a
real Android phone without `simrs` needing any USB code of its own:
APDUs flow Phone -> SIMtrace2 -> `simtrace2-cardem-pcsc` -> `pcscd`
(with the `vsmartcard-vpcd` reader driver) -> `simrs-vpcd` over TCP.
This is the same architecture that the Onomondo softsim team uses in
production (see the
[OsmoDevCon 2024 talk](https://media.ccc.de/v/osmodevcon2024-180-onomondo-softsim-a-software-usim-implementation)
and the [onomondo-uicc repo](https://github.com/onomondo/onomondo-uicc)).

```
Android phone  <-FPC->  SIMtrace2 board  <-USB->  simtrace2-cardem-pcsc
                                                          |
                                                        PC/SC
                                                          |
                                                  vsmartcard-vpcd (pcscd reader driver)
                                                          |
                                                        TCP :35963
                                                          |
                                                      simrs-vpcd
```

## 2. Hardware required

- **SIMtrace2 board.** Available as a kit from sysmocom:
  [shop.sysmocom.de/SIMtrace2-Hardware-Kit/simtrace2-kit](https://shop.sysmocom.de/SIMtrace2-Hardware-Kit/simtrace2-kit)
  (~EUR 101). ATSAM3S4B Cortex-M3, USB mini-B, ships with four 2FF FPC
  adapters.
- **Flex cable matching the phone's SIM form factor.** For nano-SIM
  (4FF), which is what current Androids use, the right-angle variant
  `simffc-4ff-ra-o` (~EUR 21) is the one to buy. The straight 4FF FPC
  does not fit slide-out trays -- the ribbon binds when the tray closes.
- **USB cable.** Mini-B, ships with the board.
- **Target Android phone.** Anything you are willing to power-cycle a
  lot during bring-up. Modern phones operate the SIM at 1.8 V (Class C);
  the SIMtrace2 supports Class B (3 V) and Class C.
- **Linux host computer.** USB pass-through to VMs is officially
  unsupported by Osmocom for SIMtrace2 -- run on metal.

## 3. Software prerequisites

### Debian / Ubuntu

```bash
sudo apt install \
    pcscd pcsc-tools libpcsclite-dev \
    vsmartcard-vpcd \
    dfu-util \
    libusb-1.0-0-dev \
    git make
```

If you intend to build the cardem firmware from source (see step 4 --
needed only if pre-built firmware misbehaves), additionally install
`gcc-arm-none-eabi`.

### Arch Linux

```bash
sudo pacman -S \
    pcsclite ccid pcsc-tools \
    dfu-util \
    libusb \
    git make
```

`vsmartcard-vpcd` is not in the official repos. Install from the AUR
package `vsmartcard-git`, or build from source at
[github.com/frankmorgner/vsmartcard](https://github.com/frankmorgner/vsmartcard).
For firmware builds, also install `arm-none-eabi-gcc` and
`arm-none-eabi-newlib`.

### Rust toolchain

A working Rust toolchain matching this repository's
`rust-toolchain.toml` (stable, with `rustfmt`, `clippy`, `rust-src`,
and `llvm-tools`). If you use `rustup`, simply running any `cargo`
command in the repo will install the pinned toolchain automatically.

## 4. Step 1 -- Flash cardem firmware to SIMtrace2

The board ships with the `trace` (passive sniffer) firmware. You need
the `cardem` firmware instead.

### 4.1 Pre-built firmware (path of least resistance)

Download from the Osmocom binary mirror:
[ftp.osmocom.org/binaries/simtrace2/](http://ftp.osmocom.org/binaries/simtrace2/).
Pick the latest `simtrace-cardem-dfu.bin`.

A caveat from a well-documented field report on the OnePlus 6T
([kkohls.org/guides_cardem.html](https://kkohls.org/guides_cardem.html)):
pre-built firmware has caused "Invalid SIM" errors on some phones,
traced back to the ATR the firmware advertises before the host has a
chance to override it. If you hit that, the documented fix is to
build cardem from source at
[github.com/osmocom/simtrace2](https://github.com/osmocom/simtrace2)
with one of:

```bash
make APP=cardem BOARD=qmod
make APP=cardem BOARD=simtrace
```

(Pick `BOARD=qmod` for the dual-modem qmod board, `BOARD=simtrace`
for the standard SIMtrace2 kit.)

### 4.2 Enter DFU mode

Hold the **DFU button** on the board while plugging in USB. The
bootloader exposes USB ID `1d50:60e2`. Verify:

```bash
lsusb | grep 1d50
```

You should see `1d50:60e2`.

### 4.3 Flash

```bash
dfu-util --device 1d50:60e3 --cfg 1 --alt 1 --reset \
         --download path/to/simtrace-cardem-dfu.bin
```

If the board is currently in DFU mode it advertises VID:PID
`1d50:60e2` (not `1d50:60e3`); in that case use `--device 1d50:60e2`
instead. The flash output will end with a `Done!` line and the board
will renumerate. (`--alt 1` selects the application partition on the
SIMtrace2's SAM3 bootloader; if the board reports a different alt
mapping, list alternates first with `dfu-util --list` -- unverified,
please report errata.)

### 4.4 Verify

Unplug, replug normally (without holding DFU), then:

```bash
lsusb | grep 1d50
```

You should now see `1d50:60e3 OpenMoko, Inc. SIMtrace2`.

### 4.5 udev rules

Grant your user access to both the runtime and DFU USB IDs.

```bash
sudo tee /etc/udev/rules.d/99-simtrace2.rules <<'EOF'
SUBSYSTEM=="usb", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="60e3", MODE="0660", GROUP="plugdev"
SUBSYSTEM=="usb", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="60e2", MODE="0660", GROUP="plugdev"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger
```

Make sure your user is in the `plugdev` group:

```bash
sudo usermod -aG plugdev $USER
```

Log out and back in for the group change to take effect.

## 5. Step 2 -- Build `simtrace2-cardem-pcsc` from source

```bash
git clone https://github.com/osmocom/simtrace2.git
cd simtrace2/host
make
```

The binary lands at `host/src/simtrace2-cardem-pcsc`.

Naming note: this tool used to be called `simtrace2-remsim`. If you
find older walkthroughs referencing that name, it is the same tool;
the rename is documented in the upstream
[gerrit log](https://www.mail-archive.com/gerrit-log@lists.osmocom.org/msg88751.html).

## 6. Step 3 -- Configure pcscd with the vsmartcard reader

The `vsmartcard-vpcd` driver registers a virtual PC/SC reader that
proxies APDUs over TCP. `pcscd` needs to be told about it via a file
in `/etc/reader.conf.d/`.

Depending on distro the package may install a default config at
either `/etc/reader.conf.d/vsmartcard` or
`/etc/reader.conf.d/0-vsmartcard.conf`. If neither exists, create it.

Sample contents:

```
FRIENDLYNAME      "Virtual PCD"
DEVICENAME        /dev/null:0x8C7B
LIBPATH           /usr/lib/pcsc/drivers/serial/libifdhandler.so
CHANNELID         0x8C7B
```

The `LIBPATH` location varies by distro. Two known-good values:

- Debian / Ubuntu:
  `/usr/lib/x86_64-linux-gnu/pcsc/drivers/serial/libifdhandler.so`
- Arch:
  `/usr/lib/pcsc/drivers/serial/libifdhandler.so`

Confirm the actual location:

```bash
find /usr -name libifdhandler.so 2>/dev/null
```

Restart pcscd:

```bash
sudo systemctl restart pcscd
```

Verify in another terminal:

```bash
pcsc_scan
```

Within ~10 seconds you should see a line like
`Reader 0: Virtual PCD 00 00`. The reader status will read
`Card not powered` until `simrs-vpcd` is also running. That is the
expected state at this point.

## 7. Step 4 -- Start `simrs-vpcd`

From the simrs repo root:

```bash
cargo run --release -p simrs-vpcd -- --port 35963
```

You should see a log line indicating it is listening on `35963`
(exact wording depends on the `tracing` log format -- unverified,
please report errata). `pcscd` will connect immediately, and
`pcsc_scan` will now show the ATR for the virtual reader instead of
`Card not powered`.

Once WS-2 lands (runtime-configurable subscriber credentials), point
the binary at the test-network AuC record with:

```bash
cargo run --release -p simrs-vpcd -- \
    --port 35963 \
    --imsi 001010000000001 \
    --ki  <32-hex-chars> \
    --k   <32-hex-chars> \
    --opc <32-hex-chars> \
    --iccid <20-digit>
```

For first bring-up, the built-in defaults are sufficient -- they will
not authenticate against a real network, but they will let you confirm
that the bridge is delivering APDUs.

## 8. Step 5 -- Run `simtrace2-cardem-pcsc`

```bash
./simtrace2-cardem-pcsc -r "Virtual PCD 00 00"
```

Use whatever exact reader name `pcsc_scan` reported. The tool will
sit waiting for the phone to assert VCC.

If you need to override the ATR from the host side, pass
`-t <hex bytes>`. Once WS-1 lands, the `simrs-vpcd` ATR is already
well-formed and `-t` is not required.

## 9. Step 6 -- Connect the phone

1. Power the phone off.
2. Eject its SIM tray.
3. Place the FPC contact pad into the tray, **chip-side matching the
   tray's contact orientation** -- the cut corner on the FPC indicates
   pin 1. The ribbon should exit the side of the tray that will not
   bind on closure (this varies by phone; dry-fit before powering up).
4. Slide the tray back into the phone with the ribbon trailing out.
   Some phones require a small amount of force to seat the tray over
   the ribbon; if it does not seat flush, stop and check orientation
   before forcing it.
5. Connect the FPC to the SIMtrace2 board (the connector latch is
   small and finicky -- pinch, do not pry).
6. Power the phone on.

Watch `simrs-vpcd`'s logs. You should see a `PowerOn` event, then a
`Reset`, then `SELECT` (MF and ADF_USIM), `READ BINARY` of EF_DIR /
EF_ICCID / EF_IMSI, and so on. If `simtrace2-cardem-pcsc` is verbose
enough to log status flag transitions, you should also see
`VCC_PRESENT` and `RESET_ACTIVE` flips around the right moments.

## 10. Troubleshooting

### "Invalid SIM" on the phone, but APDUs are flowing in the logs

Almost always an ATR issue. The phone is talking to the SIM but the
ATR it received did not satisfy its baseband.

- Confirm WS-1 has landed (a well-formed, T=0-only ATR shared across
  the simrs binaries). Check the ATR `pcsc_scan` reports against the
  T=0-only / USIM-realistic shapes documented in the workstreams doc.
- If that does not resolve it, rebuild the cardem firmware from source
  per step 4.1; some pre-built firmware variants advertise an ATR
  during the brief window before the host overrides it that strict
  basebands then latch onto.

### Phone shows "No SIM" and no APDUs arrive

Electrical, not protocol.

- FPC orientation: pin 1 is the cut corner. If the cable is flipped,
  the SIM contacts short or float and the phone never asserts VCC.
- VCC LED on the SIMtrace2 board: should illuminate when the phone
  powers on. If it does not, the phone is not driving VCC and the FPC
  contact is the suspect.
- USB stability: long, cheap USB extension cables and powered hubs
  with marginal voltage cause sporadic enumeration failures. Try a
  direct connection to a known-good port.

### APDUs flow but AUTHENTICATE fails (`9862`, `6300`, or similar)

The K / OPc the SIM is using does not match the network's AuC entry
for this IMSI.

- Use `simrs-auth` from `crates/simrs-auth-cli/` to feed the same
  RAND and AUTN the network sent and confirm the RES `simrs` produces
  matches what the AuC expects.
- Double-check ICCID and IMSI as well -- a mismatch in IMSI sends the
  network to the wrong AuC record before authentication even starts.

### pcscd does not see the virtual reader

- Confirm the `vsmartcard-vpcd` package is installed.
- Confirm the `/etc/reader.conf.d/` entry exists and `LIBPATH` points
  at an actual file.
- Watch the daemon while restarting it: `journalctl -u pcscd -f`
  surfaces driver-load errors (missing library, wrong architecture)
  that are otherwise silent.

### `Permission denied` opening the USB device

- udev rules from step 4.5 not applied -- re-run `udevadm control
  --reload-rules && udevadm trigger`, then unplug/replug.
- User not in `plugdev` (or whatever group the rule names). Verify
  with `id`; if missing, `sudo usermod -aG plugdev $USER` and log out
  and back in.

### `dfu-util` says "Cannot open DFU device"

- Board is not in DFU mode. Unplug, hold the DFU button, replug while
  holding. Confirm with `lsusb` that `1d50:60e2` appears.
- VID/PID in the `--device` flag does not match the current mode.
  Pre-flash use `--device 1d50:60e2`; post-flash use `--device
  1d50:60e3`.

## 11. Validating without a phone (pre-bringup smoke test)

The whole bridge except for `simtrace2-cardem-pcsc` and the SIMtrace2
hardware itself is exercisable without ever connecting a phone. This
is the recommended checkpoint before going to hardware.

With `pcscd` and `simrs-vpcd` running (steps 6 and 7 above, but skip
8 and 9), either of these should succeed:

```bash
pcsc_scan
```

You should see the virtual reader present an ATR.

```bash
opensc-tool --reader "Virtual PCD 00 00" --list-files
```

Or, more thoroughly, drive the file system from pySim-shell:

```bash
pySim-shell --pcsc-slot 0
# at the prompt:
select_adf usim
tree
```

(The exact `pySim-shell` flag spelling varies across versions; if
`--pcsc-slot` is rejected, check `pySim-shell --help` for the current
reader-selection option -- unverified, please report errata.)

If all of these succeed against `simrs-vpcd` alone, the bridge from
PC/SC down through `simrs` is healthy and any subsequent problem can
be localised to the SIMtrace2 USB / phone-FPC side.

## 12. References

Curated bibliography. URLs cited inline above are reproduced here for
convenience, alongside a few additional pointers.

- [SIMtrace2 cardem wiki](https://projects.osmocom.org/projects/simtrace2/wiki/Cardem)
  (Anubis-protected -- may need a browser session rather than a plain `curl`).
- [SIMtrace2 firmware README](https://github.com/osmocom/simtrace2/blob/master/firmware/README.txt).
- [SIMtrace2 tutorial -- laforge, OsmoDevCall 2022](https://media.ccc.de/v/osmodevcall-20221019-laforge-simtrace2-tutorial).
- [simtrace2 source](https://github.com/osmocom/simtrace2) -- firmware and host tools.
- [Onomondo softsim @ OsmoDevCon 2024](https://media.ccc.de/v/osmodevcon2024-180-onomondo-softsim-a-software-usim-implementation)
  and the [onomondo-uicc reference implementation](https://github.com/onomondo/onomondo-uicc).
- [OnePlus 6T cardem walkthrough (kkohls.org)](https://kkohls.org/guides_cardem.html).
- [pre-built firmware ATR field report](https://www.mail-archive.com/simtrace@lists.osmocom.org/msg00389.html).
- [vsmartcard project](https://github.com/frankmorgner/vsmartcard).
- [sysmocom SIMtrace2 shop entry](https://shop.sysmocom.de/SIMtrace2-Hardware-Kit/simtrace2-kit).
- [sysmocom SIM-adapter FPC range](https://shop.sysmocom.de/SIM/Adapters/).
- [Osmocom binary mirror -- prebuilt SIMtrace2 firmware](http://ftp.osmocom.org/binaries/simtrace2/).
- [simtrace2-remsim -> simtrace2-cardem-pcsc rename log](https://www.mail-archive.com/gerrit-log@lists.osmocom.org/msg88751.html).
- [T=0-only firmware constraint (osmocom issue 5600)](https://osmocom.org/issues/5600).
