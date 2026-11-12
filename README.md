# oti2208_net: Linux driver for the OTi-2208 USB host-to-host cable

A Linux network driver for the **OTi-2208 "EasySuite USB Host-to-Host Data Bridge"**. That is the
USB "data link" cable with a box in the middle (USB ID `0ea0:2108`, sold e.g. as "GO! Suite").
Its vendor software exists only for Windows. With this driver, each PC gets an Ethernet interface
and the cable becomes a point-to-point network link.

**Status:** works on hardware. Measured with iperf3 (both cable ends on one PC, one end in a
network namespace): **177 Mbit/s and 188 Mbit/s** in the two directions, 0 retransmits,
ping ≈17 ms. The chip's own limit is ≈218 Mbit/s of raw data, half-duplex. The driver has
not yet been tested between two separate machines.

## Build

```sh
cd driver
make                       # against the running kernel
make KDIR=/path/to/build   # or against another kernel tree
```

## Bind it to the cable

The cable presents itself as a USB mass-storage device, so `usb-storage` claims it first.
Either:

```sh
# a) per plug, by hand (the interface name is under /sys/bus/usb/devices, e.g. 3-1:1.0)
sudo insmod oti2208_net.ko
echo 3-1:1.0 | sudo tee /sys/bus/usb/drivers/usb-storage/unbind
echo 3-1:1.0 | sudo tee /sys/bus/usb/drivers/oti2208_net/bind

# b) permanently: let usb-storage ignore the cable, install the module, replug
echo 'options usb-storage quirks=0ea0:2108:i' | sudo tee /etc/modprobe.d/oti2208.conf
sudo make -C /lib/modules/$(uname -r)/build M=$PWD modules_install && sudo depmod
```

Before binding, probe sends the 2208 identify command and refuses other devices with the same
USB ID. udev names the interface `enx<MAC>`; the kernel name is `ezlink%d`. The MAC is
locally administered and derived from the USB serial number, so each cable end keeps its
name and MAC across replugs. NetworkManager will try to manage the interface; to stop that,
run `nmcli device set <if> managed no`.

Do the same on the other PC, then configure IP addresses as for any Ethernet link.

## Tuning

The driver has no module parameters. The loop constants (`OTI_RX_WAIT` 2,
`OTI_BURST` 32, `OTI_RX_STREAK` 64, `OTI_MAX_RETRIES` 50) are `#define`s at the
top of `oti2208_net.c`; the values are the measured best and need no changing
in normal use.

## How it works

* **Transport:** each cable end is a USB Bulk-Only mass-storage device with one CD-ROM LUN.
  The driver claims the interface and speaks BOT itself: a 31-byte CBW with a 16-byte vendor
  CDB (ending in `'O','T'`), then the data stage and a 13-byte CSW. A failed command is followed
  by REQUEST SENSE. Transport errors are recovered with a BOT reset and clear-halt.
* **Vendor commands used:** `F0 00` identify; `D8 01` register writes (reg 4 = keep-alive,
  reg 5 = 0x7F "host present"); `D8 01 0B` receive flush; `D9 2A FF` / `D9 28 <wait>` write /
  read one block. The firmware-update commands (`F0 10`, `F0 11`, `F0 1B`) are never sent.
* **Status codes** (sense key 09h):

  | code | meaning |
  |---|---|
  | 83 / 84 | idle read |
  | 85 | nobody read the write (≈1.3 s) |
  | 86 | the other end holds the slot (≈7 ms) |
  | 80 / 81 | other end offline |
* **The channel is half-duplex with one slot.** A 64 KiB write waits until the other end reads
  it. A write while the other end is writing is refused. Every transfer must be exactly 64 KiB.
* **Block format (version 2):** a 20-byte header (magic `OTEN`, sequence number, frame count,
  version, flags, payload length), repeated at the end of the block to catch torn blocks.
  It is followed by `[u16 len][frame]...`. There is no payload checksum: USB has a per-packet
  CRC-16 and TCP/IP have their own.
* **Turn taking:** a sender sends up to `OTI_BURST` blocks back to back and sets the "more" flag
  while more follow; the receiver keeps reading as long as it sees "more". After its burst a
  side reads, so the other end's turn starts at once. One kernel thread per interface runs
  this loop while the interface is up. Received frames go to threaded NAPI with GRO, so TCP
  receive work overlaps the next USB transfer.
* Carrier goes up on the first answer from the chip and down when the chip reports the other
  end offline. On ifdown the driver logs counters (collisions, idle reads, bad blocks).

## Known gaps

* Suspend/resume and USB reset hooks are not implemented. A USB reset rebinds the driver.
* No ethtool ops.
* The "DATA LINK" light in the middle of the cable is not driven by this driver; no command
  for it is known.

## License

GPL-2.0 (SPDX headers in the sources). Not affiliated with OTi or any cable vendor.
