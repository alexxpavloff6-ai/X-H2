Tested the `x-h2` branch (`b7fd0aa`, built locally on Windows 11 with nightly Rust + CUE v0.17.1, WPD transport) on my X-H2, firmware 5.30, **without `--emulate`**. Everything works.

| Command | Result |
|---|---|
| `device list`, `device info` | OK. Detected as `FUJIFILM X-H2` in every run |
| `backup export` | OK. 70 524 bytes, byte-identical (SHA-256) to a backup taken with my own PTP tool |
| `simulation list`, `simulation get c1..c7` | OK. All 7 slots, output identical to the earlier `--emulate 04cb:02fc` runs |
| `simulation set c7 --custom-setting-name <same name>` | OK. All writes accepted, slot unchanged |
| `image render --draft` / full | OK. 3888×2592 / 7728×5152 |
| `image render --draft --slot c5` | OK. Output MakerNote shows the C5 recipe applied (WB Daylight, fine-tune R+4/B−5, CCE Weak, tones 0, color 0, sharpness −1) |
| `backup import` | Not tested, on purpose |

The camera's full backup was byte-identical before and after all of the above.

Logs follow below, with the serial replaced by `<serial>` and the 256 KiB transfer chunks collapsed.

<details><summary><code>fujicli -vvv device info</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::53 - Found supported camera: FUJIFILM X-H2
DEBUG fujicore::ptp::transport::wpd::96 - Opened WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33}
DEBUG fujicore::ptp::44 - Retrieving device info
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDeviceInfo, params=[]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 365 bytes (365 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd16e
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53614]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd36b
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[54123]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 15 bytes (15 total)
DEBUG fujicore::features::base::51 - Raw battery string: 99,0,0
Manufacturer: FUJIFILM
Model: X-H2
Version: 5.30
Serial Number: <serial>
Mode: Raw Conversion
Battery: 99%
```

</details>

<details><summary><code>fujicli -vvv backup export backup.bin</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::53 - Found supported camera: FUJIFILM X-H2
DEBUG fujicore::ptp::transport::wpd::96 - Opened WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33}
DEBUG fujicore::features::backup::manager::19 - Starting backup export
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetObjectInfo, params=[0]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 56 bytes (56 total)
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetObject, params=[0]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 70524 bytes (70524 total)
DEBUG fujicore::features::backup::manager::22 - Backup export completed
```

</details>

<details><summary><code>fujicli -vvv simulation get c7</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::53 - Found supported camera: FUJIFILM X-H2
DEBUG fujicore::ptp::transport::wpd::96 - Opened WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33}
DEBUG fujicore::ptp::58 - Setting device prop: 0xd18c
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53644]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd18d
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53645]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 39 bytes (39 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd18f
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53647]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd192
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53650]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd195
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53653]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd196
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53654]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd197
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53655]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd199
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53657]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19a
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53658]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19b
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53659]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19f
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53663]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a0
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53664]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a1
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53665]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a2
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53666]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a3
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53667]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a4
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53668]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd191
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53649]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19d
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53661]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19e
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53662]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd190
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53648]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd198
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53656]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
Custom Setting Name: Velvia City Nights
Image Quality: RAW
Film Simulation: Velvia
Grain Effect: Off
Color Chrome Effect: Strong
Color Chrome FX Blue: Weak
White Balance: Incandescent
White Balance Shift Red: 2
White Balance Shift Blue: -3
Highlight Tone: 0
Shadow Tone: 1
Color: -4
Sharpness: 0
High ISO Noise Reduction: -4
Clarity: -1
Lens Modulation Optimizer: On
Color Space: Adobe RGB
Dynamic Range: HDR200
Dynamic Range Priority: Off
Smooth Skin Effect: Off
```

</details>

<details><summary><code>fujicli -vvv simulation set c7 --custom-setting-name "Velvia City Nights"</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::53 - Found supported camera: FUJIFILM X-H2
DEBUG fujicore::ptp::transport::wpd::96 - Opened WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33}
DEBUG fujicore::ptp::58 - Setting device prop: 0xd18c
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53644]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd18d
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53645]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 39 bytes (39 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd18f
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53647]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd192
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53650]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd195
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53653]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd196
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53654]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd197
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53655]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd199
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53657]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19a
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53658]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19b
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53659]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19f
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53663]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a0
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53664]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a1
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53665]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a2
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53666]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a3
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53667]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a4
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53668]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd191
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53649]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19d
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53661]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19e
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53662]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd190
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53648]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd198
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53656]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd18d
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53645]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 39 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd18f
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53647]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd192
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53650]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd195
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53653]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd196
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53654]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd197
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53655]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd199
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53657]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd19a
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53658]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd19b
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53659]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd19f
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53663]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd1a0
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53664]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd1a1
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53665]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd1a2
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53666]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd1a3
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53667]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd1a4
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53668]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd191
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53649]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd19d
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53661]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd19e
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53662]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd190
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53648]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::58 - Setting device prop: 0xd198
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53656]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
```

</details>

<details><summary><code>fujicli -vvv image render --draft --slot c5 DSCF0324.RAF out.jpg</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::53 - Found supported camera: FUJIFILM X-H2
DEBUG fujicore::ptp::transport::wpd::96 - Opened WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33}
DEBUG fujicore::ptp::58 - Setting device prop: 0xd18c
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53644]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd18d
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53645]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 51 bytes (51 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd18f
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53647]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd192
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53650]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd195
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53653]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd196
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53654]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd197
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53655]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd199
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53657]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19a
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53658]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19b
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53659]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19f
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53663]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a0
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53664]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a1
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53665]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a2
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53666]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a3
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53667]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd1a4
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53668]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd191
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53649]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19d
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53661]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd19e
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53662]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd190
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53648]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::ptp::52 - Getting device prop: 0xd198
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53656]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicore::features::render::manager::19 - Sending image to camera
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=FujiSendObjectInfo, params=[0, 0, 0]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 82 bytes (0 left)
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=FujiSendObject, params=[]
... 189 identical 256 KiB transfer chunks omitted ...
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 95424 bytes (0 left)
DEBUG fujicore::features::render::manager::38 - Sent image to camera
DEBUG fujicore::ptp::52 - Getting device prop: 0xd185
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53637]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 625 bytes (625 total)
DEBUG fujicore::generated::renders::6593 - Profile as shot: ConversionProfile { code: ExactString("FF179501"), fields: XH2RenderProfile { file_type: Jpeg, image_size: L3_2, image_quality: Fine, exposure_offset: Zero, dynamic_range: Some(Hdr100), dynamic_range_priority: Off, film_simulation: ClassicChrome, grain_effect: Off, color_chrome_effect: Strong, white_balance_as_shot: 1, white_balance: AsShot, white_balance_shift_red: WhiteBalanceShiftRed(0), white_balance_shift_blue: WhiteBalanceShiftBlue(-4), white_balance_temperature: None, highlight_tone: Some(HighlightTone(-10)), shadow_tone: Some(ShadowTone(-10)), color: Some(Color(20)), sharpness: Sharpness(0), noise_reduction: Minus4, lens_modulation_optimizer: On, color_space: Srgb, monochromatic_color_temperature: None, smooth_skin_effect: Off, color_chrome_fx_blue: Weak, monochromatic_color_tint: None, clarity: Clarity(0), teleconverter: Off } }
DEBUG fujicore::generated::renders::6605 - Profile to apply: ConversionProfile { code: ExactString("FF179501"), fields: XH2RenderProfile { file_type: Jpeg, image_size: L3_2, image_quality: Fine, exposure_offset: Zero, dynamic_range: Some(Hdr100), dynamic_range_priority: Off, film_simulation: ClassicChrome, grain_effect: Off, color_chrome_effect: Weak, white_balance_as_shot: 2, white_balance: Daylight, white_balance_shift_red: WhiteBalanceShiftRed(4), white_balance_shift_blue: WhiteBalanceShiftBlue(-5), white_balance_temperature: None, highlight_tone: Some(HighlightTone(0)), shadow_tone: Some(ShadowTone(0)), color: Some(Color(0)), sharpness: Sharpness(-10), noise_reduction: Minus4, lens_modulation_optimizer: On, color_space: Srgb, monochromatic_color_temperature: None, smooth_skin_effect: Off, color_chrome_fx_blue: Weak, monochromatic_color_tint: None, clarity: Clarity(0), teleconverter: Off } }
DEBUG fujicore::ptp::58 - Setting device prop: 0xd185
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53637]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 629 bytes (0 left)
DEBUG fujicore::features::render::manager::48 - Starting image render
DEBUG fujicore::ptp::58 - Setting device prop: 0xd183
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=SetDevicePropValue, params=[53635]
TRACE fujicore::ptp::transport::wpd::224 - WPD write: 2 bytes (0 left)
DEBUG fujicore::features::render::manager::53 - Fetching rendered object handles
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetObjectHandles, params=[4294967295, 0, 0]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 4 bytes (4 total)
DEBUG fujicore::features::render::manager::53 - Fetching rendered object handles
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetObjectHandles, params=[4294967295, 0, 0]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 4 bytes (4 total)
DEBUG fujicore::features::render::manager::53 - Fetching rendered object handles
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetObjectHandles, params=[4294967295, 0, 0]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 4 bytes (4 total)
DEBUG fujicore::features::render::manager::53 - Fetching rendered object handles
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetObjectHandles, params=[4294967295, 0, 0]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 8 bytes (8 total)
DEBUG fujicore::features::render::manager::65 - Fetching rendered image
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetObject, params=[4]
... 15 identical 256 KiB transfer chunks omitted ...
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 141654 bytes (4073814 total)
DEBUG fujicore::features::render::manager::67 - Fetched rendered image
DEBUG fujicore::features::render::manager::69 - Cleaning up rendered image on camera
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=DeleteObject, params=[4]
DEBUG fujicore::features::render::manager::71 - Cleaned up rendered image on camera
```

</details>

_Tested by the camera owner, with the help of Claude Code._
