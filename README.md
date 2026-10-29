# AwoX EPIR_Zm — firmware reverse engineering

Analysis of the firmware of the **AwoX EPIR_Zm**, a battery-powered PIR motion
+ light sensor with Zigbee 3.0 and Bluetooth LE (Telink TLSR8258, TC32 CPU).

The repository contains the original firmware image, a corrected TC32→Thumb
translation used for static analysis, and a fully annotated Ghidra project.
The findings below explain how the device works and why some behaviours
(missing lux updates, no battery reporting in Zigbee) occur.

## Contents

| Path                                                                | Description                                                                                                               |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `EPIR_Zm_jing_xun_4.64_SMLZigbeeBle_master_3.0.2_1610_c8b45a04.bin` | Original firmware image (TC32 machine code, 202,852 bytes).                                                               |
| `EPIR_3_0_2_thumb_fixed.bin`                                        | Same image with TC32 code translated to ARM Thumb so standard tools can disassemble it. Analysis only — **do not flash**. |
| `ghidra/EPIR_Zm.gpr`, `ghidra/EPIR_Zm.rep/`                         | Ghidra project (program `EPIR_3_0_2`), memory map set up, ~130 functions and ~25 globals named and commented.             |
| `ghidra/EPIR_3_0_2.gzf`                                             | The same program as a portable Ghidra packed file (*File → Import* in any Ghidra project).                                |

Created with Ghidra 12.1.4. The program uses language `ARM:LE:32:v4t`.

---

## 1. Firmware identification

| Item                                     | Value                                                           |
| ---------------------------------------- | --------------------------------------------------------------- |
| File name                                | `EPIR_Zm_jing_xun_4.64_SMLZigbeeBle_master_3.0.2_1610_c8b45a04` |
| Firmware version                         | `3.0.2_1610` (string in flash and BLE Device Information)       |
| Hardware revision                        | `4.64`                                                          |
| Manufacturer / model (Zigbee Basic, BLE) | `AwoX` / `EPIR_Zm`                                              |
| Zigbee manufacturer code                 | 4417 (0x1141, Telink)                                           |
| SoC                                      | Telink TLSR8258, TC32 CPU                                       |
| SDK                                      | Telink Zigbee SDK + BLE stack (multiprotocol "SMLZigbeeBle")    |

Image header (Telink format):

| Offset | Content                                                                      |
| ------ | ---------------------------------------------------------------------------- |
| 0x00   | Reset vector (`b 0xa6`)                                                      |
| 0x08   | Magic `KNLT`                                                                 |
| 0x0C   | `0x00880300`: low 16 bits × 16 = 0x3000 bytes copied by the boot ROM to SRAM |
| 0x10   | IRQ vector (`b 0x1a0`)                                                       |
| 0x18   | Image size 0x31864                                                           |

The last 4 bytes (file offset 0x31860) hold the image CRC:
`~crc32(file[0:0x31860])`, little-endian (`74 D9 73 6C` in this image). Any
patch to the image must update it.

## 2. TC32 → Thumb translation

TC32 is ARMv4T Thumb-1 with the top 5 bits of each 16-bit instruction
remapped (low 11 bits unchanged). Translation:

```
thumb = (TOP[hw >> 11] << 11) | (hw & 0x7FF)
TOP = [0x08,0x09,0x0a,0x0b,0x10,0x11,0x12,0x13,0x0e,0x0f,0x0c,0x0d,
       0x16,0x17,0x14,0x15,0x1c,0x1d,0x1e,0x1f,0x04,0x05,0x06,0x07,
       0x1a,0x1b,0x18,0x19,0x02,0x03,0x00,0x01]
```

The table and verification come from
[goyamamoto/tc32-devtools](https://github.com/goyamamoto/tc32-devtools). Only
halfwords that are code must be translated; data must be kept.

`EPIR_3_0_2_thumb_fixed.bin` is the result after correcting a first,
flow-following translation:

* **9,325 halfwords restored to the original bytes.** The first pass had
  walked into data from file offset ~0x2ba6c to the end (strings, GATT/ZCL
  tables, padding) and at 0x8a14, 0x14f90, 0x168f4, 0x1fffe, corrupting it
  (e.g. `"DevName"` had become garbage).
* **3,279 halfwords newly translated.** Case bodies of 14 jump-table
  `switch` statements (reached only through `ldr; ldr [rT, rI]; mov pc, rT`)
  had been left as TC32. They include the BLE command handler, ZCL and NWK
  code. Halfwords that did not decode to code were left as original bytes.
* SHA-256: `854875c75aff644aa183dbdd12f544e5a6b1a2d67ebe05f40c43bd332c7cc711`

TC32-only instructions have no Thumb equivalent and are left as raw TC32
halfwords; Ghidra shows them as wrong Thumb, each carries an EOL comment:

| Address          | TC32 | Meaning                                      |
| ---------------- | ---- | -------------------------------------------- |
| 0x0b8, 0x0c0     | 6bc0 | `tmcsr r0` (CPSR ← r0), stack setup per mode |
| 0x1a4            | 6bd8 | `tmrss r0` (r0 ← SPSR), IRQ entry            |
| 0x1c2            | 6bd0 | `tmssr r0` (SPSR ← r0), IRQ exit             |
| 0x1c6            | 6900 | `treti` (return from IRQ)                    |
| 0x6cf70          | 6bcb | `tmrcs r3` (r3 ← CPSR), IRQ disable          |
| 0x6cf78, 0x6cf9c | 6bc3 | `tmcsr r3`, IRQ restore                      |

(Register/operation decoding of 0x6BC0–0x6BDF is inferred from opcode range and usage.)

## 3. Memory map

The image is **not** linked at a single base:

| Ghidra block   | Address range     | Source             | Notes                                                                                                      |
| -------------- | ----------------- | ------------------ | ---------------------------------------------------------------------------------------------------------- |
| `ramcode`      | 0x000000–0x002f5f | file 0x0000–0x2f5f | Boot ROM copies file[0:0x3000] to SRAM and executes it at 0x0 (vectors, startup, IRQ, time-critical code). |
| `flash`        | 0x06cf60–0x09b863 | file 0x2f60–end    | Flash code/data runs at **file offset + 0x6a000**.                                                         |
| `regs`         | 0x800000–0x80ffff | —                  | Peripheral registers (`REG_ADDR8(x)` = 0x800000 + x), volatile.                                            |
| `sram_ramcode` | 0x840000–0x842fff | file 0x0000–0x2fff | Data-bus view of the ramcode copy (non-executable).                                                        |
| `sram`         | 0x843000–0x84ffff | —                  | `.data` initialised from flash 0x96c40 → 0x843a00–0x843f53; `.bss`, stacks.                                |

Evidence for the 0x6a000 flash base:

* 521 `bl` instructions only resolve (to ramcode functions) with this layout;
  with base 0 they point outside the image.
* 232 data words equal *function entry + 1* (Thumb bit) at this base, 4 at base 0.
* `.data` load address 0x96c40 lands in the data area after the code.

## 4. Hardware architecture

The device has **two microcontrollers**:

* **Telink TLSR8258** — Zigbee + BLE radio, application logic.
* **Sensor MCU** — handles the PIR and the light sensor. It is the bus
  master of a slave buffer on the Telink side (registers 0x8000e0/0x8000e4,
  64-byte buffers) and pushes events to the Telink.

GPIO usage found in `app_gpioInit`:

| Pin      | Use                                                                    |
| -------- | ---------------------------------------------------------------------- |
| PD2      | Push button (active low), deep-sleep wake source                       |
| PB4      | Deep-sleep wake source (sensor MCU)                                    |
| PC4      | "Attention" output to the sensor MCU (pulsed when a command is queued) |
| PC3, PB6 | Configured, role not identified                                        |

### 4.1 Sensor link protocol

Frames from the sensor MCU (`app_sensorLinkIrqHandler`, first byte = type):

| Type   | Payload            | Effect                                                                     |
| ------ | ------------------ | -------------------------------------------------------------------------- |
| `0x11` | PIR event code     | Occupancy logic (`app_handleSensorEvent`)                                  |
| `0x15` | Light level 1–6    | Converted through `luxLevelTable` and written to Illuminance MeasuredValue |
| `0x16` | Configuration byte | Stored, compared with local configuration                                  |

Frames to the sensor MCU (`app_sensorSendCmd`), placed in the response
buffer and signalled on PC4, retried every 200 ms up to 3 times:
`{0x10, a, 0x12, b, 0x13, c, 0x14, d}`. Commands are queued in an 8-slot
queue (`app_sensorCmdEnqueue`). Command 1 carries configuration; commands 2
and 3 (with 0xFF arguments) are sent on network/BLE state changes — their
meaning on the sensor side is unknown. **The Telink side never requests a
light measurement**: the sensor MCU decides when to send `0x15` frames.

### 4.2 Light measurement

The sensor MCU reports only a coarse level. `app_luxLevelToMeasuredValue`
maps it with `luxLevelTable` (ZCL value = 10000·log10(lx)+1):

| Level | ZCL MeasuredValue | ≈ lux   |
| ----- | ----------------- | ------- |
| 1     | 3011              | 2       |
| 2     | 10001             | 10      |
| 3     | 13980             | 25      |
| 4     | 16022             | 40      |
| 5     | 18752             | 75      |
| 6     | 30001             | 1000    |
| other | 0xFFFF            | invalid |

## 5. Zigbee

### 5.1 Endpoints

| EP  | Profile     | Device                  | In clusters                              | Out clusters                                   | Handler                      |
| --- | ----------- | ----------------------- | ---------------------------------------- | ---------------------------------------------- | ---------------------------- |
| 1   | 0x0104 HA   | 0x0107 Occupancy sensor | 0000, 0003, 0004, 1000                   | 0000, 0003, 0004, 0005, 0006, 0008, 0300, 1000 | ZCL                          |
| 3   | 0x128f AwoX | 0x0107                  | ff50, ff51                               | ff50, ff51                                     | raw AF (`awox_ep3RxHandler`) |
| 4   | 0x0104 HA   | 0x0107 Occupancy sensor | 0000, 0003, 0004, 0020, 0400, 0406, 1000 | 0000, 0003, 0004, 0400, 0406, 1000             | ZCL                          |

The device is a sleepy end device (`mac_capability_flags` 0x80, receiver off when idle).

### 5.2 Attributes

| Cluster            | Attribute                  | Type    | Access           | Storage                               |
| ------------------ | -------------------------- | ------- | ---------------- | ------------------------------------- |
| 0x0400 Illuminance | 0x0000 MeasuredValue       | uint16  | read, reportable | `g_illuminanceMeasuredValue` 0x843a50 |
| 0x0400             | 0x0001/0x0002 Min/Max      | uint16  | read             |                                       |
| 0x0400             | 0x0004 LightSensorType     | enum8   | read             |                                       |
| 0x0406 Occupancy   | 0x0000 Occupancy           | bitmap8 | read, reportable | `g_occupancy` 0x8448cc                |
| 0x0406             | 0x0001 OccupancySensorType | enum8   | read             |                                       |

Occupancy attributes 0x0010/0x0011 (PIR delays) are **not** implemented
(UNSUPPORTED_ATTRIBUTE). There is **no Power Configuration (0x0001) cluster**.

The firmware has a second, application-level read handler that sends a
non-standard duplicate of each read response as a cluster-specific command 0x01
(e.g. `19 4d 01 00 c3 0b`); coordinators ignore it.

### 5.3 Attribute reporting

* Telink's reporting engine (`reportAttrs`, `reportAttrTimerCb`) with a
  **4-entry** table (`reportingTab`, 0x25 bytes per entry). Configure
  Reporting for a 5th attribute returns `INSUFFICIENT_SPACE` (0x89).
* **No default reporting**: `bdb_defaultReportingCfg` exists but is never
  called. Attributes are reported only if the coordinator binds the cluster
  and sends Configure Reporting.
* Reports go to bound destinations.
* Analog change check (`reportableChangeValueChk`): report if
  `|current − previous| > reportableChange` (strictly greater).
* The reporting timer ticks once per second **while awake** (see §6): min/max
  intervals therefore count *awake seconds*, not wall-clock time.

### 5.4 Behaviour on detection

On PIR events the device drives bound lights directly from endpoint 1
(`app_actionSendTask`, `app_sendLightOnCmds`): On/Off, Level and Color
Control (command 0x0A Move to Color Temperature, 0x06 Move to Hue and
Saturation), with level and colour from stored settings; Off when occupancy
times out. **No lux value is sent with a detection**: the illuminance
attribute only changes when a `0x15` frame arrives and is only reported by
the reporting engine.

### 5.5 Occupancy clearing and the stuck-occupancy bug

Occupancy is set by a PIR event (`app_handleSensorEvent`: occupied flag
`g_occState` bit 0, start time `g_occStartTime`, attribute → 1) and cleared in
a single place, `app_occupancyTimeoutCheck`. That check runs only while the
occupied flag is set and the timeout `g_occTimeout` is non-zero; when the
timeout expires it sets the attribute to 0 (reported) and switches bound
lights off. Factory default (`app_settingsFactoryDefaults`): `g_occTimeout` = 2
units of 290,000 slow-timer ticks ≈ **18 s** after the last motion. While the
occupied flag is set, `app_enterSleep` also adds a timer wake source so the
device can wake to clear occupancy.

**Bug:** `app_sensorSendCmd` (0x71132–0x71144) also clears the occupied flag
whenever it sends **command 1 (configuration)** to the sensor MCU, but does
not reset the Occupancy attribute. Configuration is sent by
`app_sensorSendConfig` at boot, after a settings change, and when a `0x16`
frame from the sensor MCU reports a configuration that differs from the
stored one. If this happens during an occupied period:

1. the attribute stays at 1;
2. `app_occupancyTimeoutCheck` no longer runs (flag cleared);
3. the sleep code no longer arms the timer wake.

Occupancy then stays *detected* until the next motion re-arms the flag (and
the timeout clears it ~18 s later) or the device reboots. Whether it occurs
depends on the timing of the configuration exchange relative to motion,
which makes it look like a race condition.

Patch (not applied to the files in this repository):

| File offset | Original (TC32) | Patched | Effect |
|---|---|---|---|
| 0x7134 | `01 C0` (`beq 0x7113a`) | `FF C0` (branch to the next instruction) | Command 1 no longer clears the occupied flag; the timeout always clears occupancy |
| 0x31860 | `74 D9 73 6C` | recomputed | Image CRC (see §1) |

## 6. Power management

* Main loop: `main` → `while (1) { stack/BLE/app tasks; app_pmTask(); }`.
* `app_sleepDecide` puts the chip to sleep once the stack is idle, no sensor
  activity for 5 s and 1 s of quiet. Otherwise it busy-waits 32 ms.
* Sleep call (only one): `drv_pm_sleep(mode 2 = deep sleep with retention,
  wake source = 1 (GPIO pad), 0)` at 0x71b8c–0x71b92. The timer wake source
  is added **only** while an occupancy timeout is pending (one-shot wake to
  report "unoccupied").
* Wake sources: PD2 (button) and PB4 (sensor MCU). After any wake the device
  stays awake at least ~5–6 s.
* **No periodic wake and no watchdog.** Without motion or button presses the
  device sleeps indefinitely: no parent poll, no Poll Control check-in, no
  periodic reports, no battery measurement.

Consequences for reporting:

| Coordinator setting | Effect on this device                                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------- |
| min interval > 0    | A change is reported only after *min* awake seconds have accumulated, often several wake-ups later. |
| min interval = 0    | Change reported immediately by `reportAttrs` while awake.                                           |
| max interval *N*    | Reported after *N* awake seconds (e.g. 3600 ≈ hundreds of wake-ups, effectively never).             |

Patch note: changing the wake source at file offset **0x7b8e** (TC32
`01 A1` = `mov r1,#1`) to `03 A1` would enable timer wake, but `drv_pm_sleep`
clamps the sleep to the next software timer — the 1 s reporting timer when
reporting is configured — so the device would wake about every second. A
useful periodic wake needs a real code change.

## 7. Battery

`app_batteryAdcSample` runs every 10 s while awake: ADC → mV
(`g_batteryMv`) → percent (`g_batteryPercent`; ≤3400 mV → 1 %, linear,
≥4385 mV → 100 %). The value is published **only over BLE**: GATT Battery
Service (0x180F, Battery Level 0x2A19) and one byte of the BLE advertising
data (`ble_advData`). It is not exposed over Zigbee.

## 8. Button

`app_buttonPoll` (PD2) blinks the LED once per second while held and acts on
release:

| Held   | Action                                                                                                                                            |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| < 2 s  | LED blink; immediate data poll of the parent, repeated every 500 ms while the stack is busy (delivers messages queued by the coordinator)         |
| 2–5 s  | Commissioning mode 4: starts a task that is most likely Touchlink (inferred) and keeps the device awake for 25 s                                  |
| 5–10 s | Pairing: Zigbee network steering, retried ~every 10 s up to 7 times (only if not provisioned through the AwoX app), plus BLE advertising for 60 s |
| ≥ 10 s | Leave network and factory reset (erase flash 0xcf000, 0xd0000, 0xd1000, reset NV, reboot)                                                         |

Thresholds in code: 32,000,000 / 80,000,000 / 160,000,000 system-timer ticks
(16 ticks/µs). LED patterns come from `led_patternTable` (`led_play(n)`).

## 9. Bluetooth LE

BLE runs alongside Zigbee (BLE link-layer loop called from the main loop).

### 9.1 GATT table (`gatt_attribute_table`, 35 entries)

| Service                                | Characteristics                                                                                                                                                                                                                                                 |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0x1800 GAP                             | Device Name `EPIR_Zm`, Appearance                                                                                                                                                                                                                               |
| 0x180A Device Information              | FW `3.0.2_1610`, Manufacturer `AwoX`, Model `EPIR_Zm`, HW `4.64`                                                                                                                                                                                                |
| `00010203-0405-0607-0809-0a0b0c0d1910` | `…1911` "Status" (1 B, write)<br>`…1912` "Command" (16 B, write) → `ble_cmdWrite`<br>`…1913` "OTA" (8 B, read/write)<br>`…1915` "FOTA" (9 B, read/write) → `ble_fotaWrite`/`ble_fotaRead`<br>`…1914` "Pair" (16 B, read/write) → `ble_pairWrite`/`ble_pairRead` |
| 0x180F Battery                         | Battery Level → `g_batteryPercent`                                                                                                                                                                                                                              |

### 9.2 Pairing / login (Telink-mesh style)

* Write op `0x0C` with 8-byte random + 8-byte proof (AES with a key derived
  from stored credentials). Read returns `0x0D` + device random (session
  established), `0x07` (done) or `0x0E` (failure).
* After login, ops `0x04`/`0x05` set new credentials (encrypted).

### 9.3 Commands (`ble_cmdWrite`)

Packets must decrypt/authenticate (`ble_cmdDecryptAuth`). Type 0/1 commands
go to a stub (`ble_cmdType01_stub`, always returns 0 — feature disabled).
Type 2 dispatches on a sub-command 0x00–0x13; identified ones:

| Sub-cmd | Action                                                                                       |
| ------- | -------------------------------------------------------------------------------------------- |
| 0x01    | Request leave + factory reset (same as button ≥10 s); also relays AwoX ep3 command 3 replies |
| 0x06    | Reply with Zigbee network information (NIB attribute + two 8-byte identifiers)               |
| 0x0B    | Reply with the Zigbee short address                                                          |
| 0x0C    | Set a 16-bit stack parameter (only if addressed to own short address or 0)                   |
| 0x0F    | Set a 16-bit value and save the AwoX configuration block (flash 0xd0000)                     |
| others  | Flags/replies, not identified                                                                |

The advertising data contains the Zigbee short address, a provisioning
state byte and the battery level; the scan response carries the 8-byte AwoX
ecosystem ID.

## 10. AwoX private Zigbee profile (endpoint 3)

Endpoint 3 (profile 0x128f) bypasses ZCL. Only cluster **0xff50** is
handled; 0xff51 is declared but unused. Frames use a ZCL-like header:

```
byte 0  frame control (0x01 request, 0x09 response; manufacturer-specific frames ignored)
byte 1  sequence number
byte 2  command
byte 3+ payload
```

Sent ep3 → ep3, profile 0x128f, cluster 0xff50 (`awox_ff50Send`).

| Cmd  | Direction | Behaviour                                                                                                                                                                                   |
| ---- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1, 2 | request   | Call hook pointers that are never set (dead in this build)                                                                                                                                  |
| 3    | request   | Reply cmd 3 / status 0, then leave the network and factory reset if no longer joined (`app_leaveAndResetTask`)                                                                              |
| 3    | response  | Relayed to the BLE client as status reply                                                                                                                                                   |
| 4    | request   | Provisioning: payload = u16 + 8-byte AwoX ID. Stores the ID, derives a 16-byte key, saves to flash 0xd0000, sets state 4, updates BLE scan response/advertising (`awox_cmd4StoreProvision`) |

After joining a network, an unprovisioned device **broadcasts cmd 4 to
0xFFFF** at 0, 8 and 15 s (`app_bdbCommissioningCb`,
`awox_broadcastProvision`), so AwoX devices on one network share the same
ecosystem ID.

Key derivation (`awox_deriveDeviceKey`):
`SHA-256( reverse(MAC[6]) || 56 e8 50 ed cf dd 8b 99 || 00 00 )[0:16]`.

## 11. Security observations

* AwoX ep3 command 3 (leave + factory reset) is accepted from any node on
  the Zigbee network without further authentication.
* The per-device key is derived from the MAC address (broadcast over BLE)
  and a constant salt in the firmware; its use was not fully traced.
* The standard Zigbee default trust-center link key string
  `ZigBeeAlliance09` is present (normal for Zigbee 3.0 devices).

## 12. Home Assistant (ZHA) notes

The device works with ZHA's generic occupancy and illuminance entities, but
because of §5.3 and §6:

* Lux is updated only when the sensor MCU sends a new level *and* reporting
  is configured with **min interval 0** and a small max interval.
* Reconfiguration must happen while the device is awake: short-press the
  button (< 2 s) right after starting *Reconfigure*, and repeat until it
  finishes.
* No battery entity is possible over Zigbee.

A ZHA custom quirk forcing the illuminance reporting configuration
(`custom_quirks_path` in `configuration.yaml`):

```python
import logging

from zigpy.quirks import CustomCluster
from zigpy.quirks.v2 import QuirkBuilder
from zigpy.zcl import foundation
from zigpy.zcl.clusters.measurement import IlluminanceMeasurement

_LOGGER = logging.getLogger(__name__)

LUX_REPORTING = (0, 5, 1)   # min (awake s), max (awake s), reportable change


class EpirIlluminance(CustomCluster, IlluminanceMeasurement):
    """Rewrite the outgoing Configure Reporting record for measured_value."""

    async def request(self, general, command_id, schema, *args, **kwargs):
        if general and command_id == foundation.GeneralCommand.Configure_Reporting:
            records = args[0] if args else kwargs.get("config_records", [])
            for rec in records:
                if rec.attrid == 0x0000 and rec.direction == foundation.ReportingDirection.SendReports:
                    rec.min_interval, rec.max_interval, rec.reportable_change = LUX_REPORTING
                    _LOGGER.warning("EPIR_Zm: measured_value reporting forced to %s", LUX_REPORTING)
        return await super().request(general, command_id, schema, *args, **kwargs)


(
    QuirkBuilder("AwoX", "EPIR_Zm")
    .replaces(EpirIlluminance, endpoint_id=4)
    .add_to_registry()
)
```

Max interval 5 makes the device send the lux value about once per wake-up
(i.e. with each detection), at the cost of one extra frame.

**Stuck occupancy (§5.5).** Without patching the firmware, a possible
workaround is to apply the same reporting override to the Occupancy Sensing
cluster (add a second class based on `OccupancySensing` and a second
`.replaces(..., endpoint_id=4)`), so that the device re-reports occupancy on
every wake-up during real presence, and to filter the entity in Home
Assistant so that it turns off when no fresh report arrives (untested):

```yaml
template:
  - binary_sensor:
      - name: "EPIR occupancy (filtered)"
        device_class: occupancy
        state: >
          {{ is_state('binary_sensor.awox_epir_zm_occupancy', 'on')
             and (now() - states.binary_sensor.awox_epir_zm_occupancy.last_reported).total_seconds() < 60 }}
```

Bindings to lights made directly on the device are not covered by this
workaround.

## 13. Using the Ghidra project

* Open `ghidra/EPIR_Zm.gpr` with Ghidra 12.1.4 or later, or import
  `ghidra/EPIR_3_0_2.gzf` into any project (*File → Import File*).
* Memory map, Thumb mode (TMode = 1) and `.data` initial values are already
  set up. Re-running auto-analysis is not required; if it is run, Ghidra's
  ARM processor definition re-creates exception-vector functions
  (`UndefinedInstruction` at 0x4, `NotUsed` at 0x14) on the image header —
  delete them.
* Function pointers in data carry the Thumb bit (value = entry + 1); the
  relevant references point at the even entry address.
* Names marked *inferred* in their function comments (e.g.
  `bdb_touchlinkStart`, `bdb_networkSteerStart`, `zb_pollParentNow`,
  `kb_scan_key`, `tl_schedule_task`, `bls_ll_setScanRspData`,
  `zb_leaveNetworkReq`, `sys_reboot`) are deduced from behaviour, not
  confirmed against SDK sources.

### Key functions

| Address | Name                          | Role                            |
| ------- | ----------------------------- | ------------------------------- |
| 0x00a6  | `__reset`                     | Startup (copy/clear, stacks)    |
| 0x01a0  | `__irq`                       | IRQ entry                       |
| 0x2a80  | `sleep_us`                    | Busy wait on system timer       |
| 0x72584 | `main`                        | Init and main loop              |
| 0x708b8 | `app_mainLoop`                | `app_task` + reporting handler  |
| 0x71c3c | `app_task`                    | Application task                |
| 0x701bc | `app_pmTask`                  | Power manager                   |
| 0x71b34 | `app_sleepDecide`             | Sleep decision and entry        |
| 0x70fd8 | `app_sensorLinkIrqHandler`    | Sensor MCU frames               |
| 0x71654 | `app_handleSensorEvent`       | Occupancy / lux / config events |
| 0x71734 | `app_occupancyTimeoutCheck`   | Only place that clears occupancy |
| 0x710e0 | `app_sensorSendCmd`           | Command to sensor MCU (contains the occupancy bug) |
| 0x70fa0 | `app_sensorSendConfig`        | Queues configuration command 1  |
| 0x70de8 | `app_settingsFactoryDefaults` | Default settings (timeout ≈ 18 s) |
| 0x6e884 | `app_luxLevelToMeasuredValue` | Level → ZCL lux                 |
| 0x7154c | `app_actionSendTask`          | Light commands to bound devices |
| 0x71bb4 | `app_batteryAdcSample`        | Battery measurement             |
| 0x71a3c | `app_buttonPoll`              | Button timing                   |
| 0x6e9cc | `app_buttonActions`           | Button actions                  |
| 0x6ec00 | `app_factoryReset`            | Erase configuration and reboot  |
| 0x8d9d0 | `reportAttrs`                 | Report-on-change                |
| 0x8d748 | `reportAttrTimerCb`           | Reporting interval tick         |
| 0x87e4c | `zcl_configReportingRecord`   | Configure Reporting handler     |
| 0x81700 | `bdb_defaultReportingCfg`     | Never called                    |
| 0x728a0 | `ble_cmdWrite`                | BLE command dispatcher          |
| 0x720ac | `ble_pairWrite`               | BLE pairing/login               |
| 0x6f534 | `awox_ep3RxHandler`           | AwoX profile handler            |
| 0x6fb9c | `awox_deriveDeviceKey`        | MAC-based key derivation        |
| 0x72acc | `drv_pm_sleep`                | Telink sleep driver             |

### Key data

| Address           | Name                                        |
| ----------------- | ------------------------------------------- |
| 0x95dec           | `luxLevelTable`                             |
| 0x95dc4 / 0x95fc4 | `illuminance_attrTbl` / `occupancy_attrTbl` |
| 0x95f50           | `sensor_clusterList`                        |
| 0x95f34           | `sensor_simpleDesc` (endpoint 4)            |
| 0x96038           | `gatt_attribute_table`                      |
| 0x846a81          | `reportingTab`                              |
| 0x844b04          | `g_awoxCfg` (persisted at flash 0xd0000)    |
| 0x843a00          | `led_patternTable`                          |
| 0x843ad4          | `g_settings` (0x42 bytes, flash 0xd1000)    |
| 0x843ad7          | `g_occTimeout`                              |
| 0x843ade / 0x843adf | `g_cfgFlags` / `g_occState`               |
| 0x843ae0          | `g_occStartTime`                            |

## 14. Open questions

* Meaning of sensor-MCU commands 2/3 and of the `0x16` configuration byte.
* Full layout of the `g_settings` record (light level/colour fields) and how
  the AwoX app writes it.
* How often the sensor MCU sends `0x16` configuration frames, i.e. how often
  the stuck-occupancy bug (§5.5) can trigger.
* Remaining BLE sub-commands and the OTA/FOTA protocol details.
* Exact Touchlink role of the 2–5 s button press.
