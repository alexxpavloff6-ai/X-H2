Thanks for fujicli! I tested it on my X-H2. Short version: with `--emulate 04cb:02fc` (X-T5), everything I tried works, apart from the grain-code quirk below. I didn't try `backup import`, on purpose.

**Camera:** FUJIFILM X-H2, firmware **5.30**, USB `04cb:02f2`, USB mode RAW CONV./BACKUP RESTORE
**Host:** Windows 11 (WPD transport), fujicli **0.4.0**, release binary `release-27d3a6b`
**Sample:** a RAF shot on this camera, lossless compressed, Classic Chrome

## Results

| Command | Result |
|---|---|
| `device list`, `device info` | OK (no emulation needed): model X-H2, version 5.30, mode Raw Conversion, battery |
| `-d <serial> device reverse info` | OK. D184 `FF179501,FA179501`, D186 = D187 = `X-H2_0200` |
| `device reverse backup export` and `--emulate 04cb:02fc backup export` | OK. 70 524 bytes, identical (SHA-256) to a backup taken with my own PTP tool |
| `--emulate 04cb:02fc simulation list` / `get c1..c7` | OK. All 7 slots decode with the X-T5 tables. Every value matches my independent decoding of the same slots, done earlier with my own PTP tool |
| `--emulate 04cb:02fc simulation set c7 --custom-setting-name <same name>` | OK. All 20 writes accepted. The slot reads back unchanged, and the full backup is byte-identical before and after |
| `--emulate 04cb:02fc image render [--draft]` | OK. Draft gives 3888×2592 (4.3 MB), full gives 7728×5152 (21 MB) |
| `image render --draft --slot c5` | OK. MakerNote of the output shows the C5 recipe: WB Daylight, fine-tune R+4/B−5, CCE Weak, tones 0, color 0, sharpness −1 |
| `image render --draft --slot c7` | Refused by fujicli's rule "Dynamic Range cannot exceed the value the image was shot with" (C7 is DR200, the RAF was shot at DR100). Expected behaviour |
| `backup import` | Not tested, on purpose |

Before the runs and after all of them (including `simulation set`), the camera's backup was byte-identical.

## Notes that may help when adding the X-H2

1. **D185 on the X-H2 is 625 bytes:** the i16 count, the 0x1FF code region, then only **28** i32 fields. The count still says 29. Your 29th field (`portrait_enhancer`) isn't there. The 629-byte profile fujicli writes is accepted: the camera drops the extra field and reads back 625 bytes. Its JPEG matches the one rendered from the camera's native 625-byte profile. Field positions match your `profile.cue` order with no offset: `exposure_offset` at position 4 = +1000 gives the expected +1 EV. The last field (position 27) reads `2`, which fits `teleconverter = off`.
2. **Grain effect (D195):** the camera reads back `0x06`/`0x07` for Off (Off plus the remembered size), as in #2. Writing `0x06` back is **rejected with 0x201C** (Invalid_DeviceProp_Value). Writing `0x01` is accepted, and the camera keeps reporting `0x06`, so the remembered size isn't lost. fujicli already writes `0x01`, so `set`/`import` work as they are. A tool that copies raw property bytes slot to slot will fail on this property.
3. **Extra property D1A5:** the X-H2 also answers `GetDevicePropValue(0xD1A5)`, right after Color Space. It reads `7` in all 7 slots. It isn't in the FML. My guess is file type (JPEG = 7, as in your render `file_type`), but I haven't verified it.
4. Every value in my 7 slots decoded with the X-T5 tables and stayed within the X-T5 pins. That covers 3 film simulations (Classic Chrome, Classic Negative, Velvia), 4 WB modes incl. `0x8007` + Kelvin, DR 100/200/400/Auto, the NR table, grain, CCE, FX Blue, tones, color, sharpness, clarity and color space. So an `x_h2` entry copying the X-T5 features (7 slots, backup, render) looks like a good starting point. I'm happy to test a build before release.

Serial numbers are replaced with `<serial>`, and the repeated 256 KiB transfer-chunk lines are collapsed.

<details><summary><code>fujicli device list</code></summary>

```text
- FUJIFILM X-H2 (04cb:02f2) (serial <serial>)
```

</details>

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
DEBUG fujicore::features::base::51 - Raw battery string: 90,0,0
Manufacturer: FUJIFILM
Model: X-H2
Version: 5.30
Serial Number: <serial>
Mode: Raw Conversion
Battery: 90%
```

</details>

<details><summary><code>fujicli -vvv -d <serial> device reverse info</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::ptp::transport::wpd::96 - Opened WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33}
DEBUG fujicore::ptp::44 - Retrieving device info
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDeviceInfo, params=[]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 365 bytes (365 total)
DEBUG fujicli::cli::device::reverse::117 - camera.ptp.get_info(): DeviceInfo { version: 100, vendor_ex_id: 6, vendor_ex_version: 100, vendor_extension_desc: "fujifilm.co.jp: 1.0; ", functional_mode: 0, operations_supported: [4097, 4098, 4099, 4100, 4101, 4102, 4103, 4104, 4105, 4106, 4107, 4116, 4117, 4118, 4119, 36876, 36877, 36893, 4108, 4109], events_supported: [], device_properties_supported: [20485, 20501, 53249, 53255, 53256, 53258, 53259, 53260, 53271, 53272, 53276, 53283, 53289, 53294, 53296, 53297, 53298, 53508, 53614, 53627, 53635, 53636, 53637, 53638, 53639, 53641, 53644, 53645, 53646, 53647, 53648, 53649, 53650, 53651, 53652, 53653, 53654, 53655, 53656, 53657, 53658, 53659, 53660, 53661, 53662, 53663, 53664, 53665, 53666, 53667, 53668, 53669, 53768, 53771, 53778, 53788, 54048, 54049, 54093, 54122, 54123], capture_formats: [14337, 14354, 14336, 45315, 14349], image_formats: [14337, 14354, 20480, 63490, 14336, 45315, 14349], manufacturer: "FUJIFILM", model: "X-H2", device_version: "5.30", serial_number: "<serial>" }
DEBUG fujicore::ptp::52 - Getting device prop: 0xd16e
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53614]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 2 bytes (2 total)
DEBUG fujicli::cli::device::reverse::118 - camera.ptp.get_prop_raw(UsbMode::prop_code()): [6, 0]
DEBUG fujicore::ptp::52 - Getting device prop: 0xd36b
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[54123]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 15 bytes (15 total)
DEBUG fujicli::cli::device::reverse::119 - camera.ptp.get_prop_raw(DevicePropCode::FujiBatteryInfo2): [7, 57, 0, 48, 0, 44, 0, 48, 0, 44, 0, 48, 0, 0, 0]
DEBUG fujicore::ptp::52 - Getting device prop: 0xd184
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53636]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 37 bytes (37 total)
DEBUG fujicli::cli::device::reverse::126 - camera.ptp.get_prop::<String>(code): "FF179501,FA179501"
DEBUG fujicore::ptp::52 - Getting device prop: 0xd186
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53638]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 21 bytes (21 total)
DEBUG fujicli::cli::device::reverse::126 - camera.ptp.get_prop::<String>(code): "X-H2_0200"
DEBUG fujicore::ptp::52 - Getting device prop: 0xd187
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetDevicePropValue, params=[53639]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 21 bytes (21 total)
DEBUG fujicli::cli::device::reverse::126 - camera.ptp.get_prop::<String>(code): "X-H2_0200"
```

</details>

<details><summary><code>fujicli -vvv --emulate 04cb:02fc backup export backup.bin</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::53 - Found supported camera: FUJIFILM X-T5
DEBUG fujicore::ptp::transport::wpd::96 - Opened WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33}
DEBUG fujicore::features::backup::manager::19 - Starting backup export
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetObjectInfo, params=[0]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 56 bytes (56 total)
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetObject, params=[0]
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 70524 bytes (70524 total)
DEBUG fujicore::features::backup::manager::22 - Backup export completed
```

</details>

<details><summary><code>fujicli -vvv --emulate 04cb:02fc simulation get c7</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::53 - Found supported camera: FUJIFILM X-T5
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

<details><summary><code>fujicli -vvv --emulate 04cb:02fc simulation set c7 --custom-setting-name "Velvia City Nights"</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::53 - Found supported camera: FUJIFILM X-T5
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

<details><summary><code>fujicli -vvv --emulate 04cb:02fc image render --draft DSCF0324.RAF out.jpg</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::53 - Found supported camera: FUJIFILM X-T5
DEBUG fujicore::ptp::transport::wpd::96 - Opened WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33}
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
DEBUG fujicore::generated::renders::6593 - Profile as shot: ConversionProfile { code: ExactString("FF179501"), fields: XT5RenderProfile { file_type: Jpeg, image_size: L3_2, image_quality: Fine, exposure_offset: Zero, dynamic_range: Some(Hdr100), dynamic_range_priority: Off, film_simulation: ClassicChrome, grain_effect: Off, color_chrome_effect: Strong, white_balance_as_shot: 1, white_balance: AsShot, white_balance_shift_red: WhiteBalanceShiftRed(0), white_balance_shift_blue: WhiteBalanceShiftBlue(-4), white_balance_temperature: None, highlight_tone: Some(HighlightTone(-10)), shadow_tone: Some(ShadowTone(-10)), color: Some(Color(20)), sharpness: Sharpness(0), noise_reduction: Minus4, lens_modulation_optimizer: On, color_space: Srgb, monochromatic_color_temperature: None, smooth_skin_effect: Off, color_chrome_fx_blue: Weak, monochromatic_color_tint: None, clarity: Clarity(0), teleconverter: Off } }
DEBUG fujicore::generated::renders::6605 - Profile to apply: ConversionProfile { code: ExactString("FF179501"), fields: XT5RenderProfile { file_type: Jpeg, image_size: L3_2, image_quality: Fine, exposure_offset: Zero, dynamic_range: Some(Hdr100), dynamic_range_priority: Off, film_simulation: ClassicChrome, grain_effect: Off, color_chrome_effect: Strong, white_balance_as_shot: 1, white_balance: AsShot, white_balance_shift_red: WhiteBalanceShiftRed(0), white_balance_shift_blue: WhiteBalanceShiftBlue(-4), white_balance_temperature: None, highlight_tone: Some(HighlightTone(-10)), shadow_tone: Some(ShadowTone(-10)), color: Some(Color(20)), sharpness: Sharpness(0), noise_reduction: Minus4, lens_modulation_optimizer: On, color_space: Srgb, monochromatic_color_temperature: None, smooth_skin_effect: Off, color_chrome_fx_blue: Weak, monochromatic_color_tint: None, clarity: Clarity(0), teleconverter: Off } }
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
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetObject, params=[6]
... 16 identical 256 KiB transfer chunks omitted ...
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 148330 bytes (4342634 total)
DEBUG fujicore::features::render::manager::67 - Fetched rendered image
DEBUG fujicore::features::render::manager::69 - Cleaning up rendered image on camera
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=DeleteObject, params=[6]
DEBUG fujicore::features::render::manager::71 - Cleaned up rendered image on camera
```

</details>

<details><summary><code>fujicli -vvv --emulate 04cb:02fc image render --draft --slot c5 DSCF0324.RAF out.jpg</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::53 - Found supported camera: FUJIFILM X-T5
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
DEBUG fujicore::generated::renders::6593 - Profile as shot: ConversionProfile { code: ExactString("FF179501"), fields: XT5RenderProfile { file_type: Jpeg, image_size: L3_2, image_quality: Fine, exposure_offset: Zero, dynamic_range: Some(Hdr100), dynamic_range_priority: Off, film_simulation: ClassicChrome, grain_effect: Off, color_chrome_effect: Strong, white_balance_as_shot: 1, white_balance: AsShot, white_balance_shift_red: WhiteBalanceShiftRed(0), white_balance_shift_blue: WhiteBalanceShiftBlue(-4), white_balance_temperature: None, highlight_tone: Some(HighlightTone(-10)), shadow_tone: Some(ShadowTone(-10)), color: Some(Color(20)), sharpness: Sharpness(0), noise_reduction: Minus4, lens_modulation_optimizer: On, color_space: Srgb, monochromatic_color_temperature: None, smooth_skin_effect: Off, color_chrome_fx_blue: Weak, monochromatic_color_tint: None, clarity: Clarity(0), teleconverter: Off } }
DEBUG fujicore::generated::renders::6605 - Profile to apply: ConversionProfile { code: ExactString("FF179501"), fields: XT5RenderProfile { file_type: Jpeg, image_size: L3_2, image_quality: Fine, exposure_offset: Zero, dynamic_range: Some(Hdr100), dynamic_range_priority: Off, film_simulation: ClassicChrome, grain_effect: Off, color_chrome_effect: Weak, white_balance_as_shot: 2, white_balance: Daylight, white_balance_shift_red: WhiteBalanceShiftRed(4), white_balance_shift_blue: WhiteBalanceShiftBlue(-5), white_balance_temperature: None, highlight_tone: Some(HighlightTone(0)), shadow_tone: Some(ShadowTone(0)), color: Some(Color(0)), sharpness: Sharpness(-10), noise_reduction: Minus4, lens_modulation_optimizer: On, color_space: Srgb, monochromatic_color_temperature: None, smooth_skin_effect: Off, color_chrome_fx_blue: Weak, monochromatic_color_tint: None, clarity: Clarity(0), teleconverter: Off } }
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
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=GetObject, params=[13]
... 15 identical 256 KiB transfer chunks omitted ...
TRACE fujicore::ptp::transport::wpd::194 - WPD read: 141983 bytes (4074143 total)
DEBUG fujicore::features::render::manager::67 - Fetched rendered image
DEBUG fujicore::features::render::manager::69 - Cleaning up rendered image on camera
TRACE fujicore::ptp::transport::wpd::252 - WPD transaction: code=DeleteObject, params=[13]
DEBUG fujicore::features::render::manager::71 - Cleaned up rendered image on camera
```

</details>

<details><summary><code>fujicli -vvv --emulate 04cb:02fc image render --draft --slot c7 DSCF0324.RAF out.jpg</code></summary>

```text
TRACE fujicore::ptp::transport::wpd::52 - Found WPD device \\?\usb#vid_04cb&pid_02f2#<serial>#{6ac27878-a6fa-4155-ba85-f98f491d4f33} (04cb:02f2, serial Some("<serial>"))
DEBUG fujicore::53 - Found supported camera: FUJIFILM X-T5
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
DEBUG fujicore::generated::renders::6593 - Profile as shot: ConversionProfile { code: ExactString("FF179501"), fields: XT5RenderProfile { file_type: Jpeg, image_size: L3_2, image_quality: Fine, exposure_offset: Zero, dynamic_range: Some(Hdr100), dynamic_range_priority: Off, film_simulation: ClassicChrome, grain_effect: Off, color_chrome_effect: Strong, white_balance_as_shot: 1, white_balance: AsShot, white_balance_shift_red: WhiteBalanceShiftRed(0), white_balance_shift_blue: WhiteBalanceShiftBlue(-4), white_balance_temperature: None, highlight_tone: Some(HighlightTone(-10)), shadow_tone: Some(ShadowTone(-10)), color: Some(Color(20)), sharpness: Sharpness(0), noise_reduction: Minus4, lens_modulation_optimizer: On, color_space: Srgb, monochromatic_color_temperature: None, smooth_skin_effect: Off, color_chrome_fx_blue: Weak, monochromatic_color_tint: None, clarity: Clarity(0), teleconverter: Off } }
Error: applying conversion profile

Caused by:
    invalid simulation: Dynamic Range cannot exceed the value the image was shot with.
```

</details>

_Tested by the camera owner. The runs and this write-up were done with the help of Claude Code._
