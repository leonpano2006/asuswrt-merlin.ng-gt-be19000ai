BCM4916 native read-only hwmon module

Status: source prepared; not built, loaded or runtime-verified by this agent.
Requires the exact current kernel11 build headers/configuration and the stock
Linux 4.19 hwmon core as a separate module. Root agent selects the build strategy.

Exports name=bcm4916 and four 0444 sysfs attributes:
  temp1_input  CPU package BAC PVT sensor, millidegrees Celsius
  temp1_label  CPU Package
  freq1_input  live BIU PLL channel 0 frequency, Hz
  freq1_label  CPU Cluster

No per-core readings, CPU frequency scaling, thermal policy or cooling changes.
No writes, module parameters, proc/sysfs parsing, userspace helper or periodic
polling thread. Frequency uses the existing exported PLL getter, not select10's
PMU timing probe. GetPVT is deliberately not used because it may enable PVTMON
hardware in a non-DQM mode and returns the rail/die sensor rather than CPU BAC.

Load gate: UtilGetChipId() must report 0x4916. The enabled brcm,therm DT node must
contain the named bac_cpu_therm_temp register at 0x8106037c with size exactly 4.
This DT match must be confirmed on the live device before loading. The module
maps only that validated existing register and shares it read-only with the
existing Broadcom thermal driver. An invalid sample returns EAGAIN, not zero.

Linux 4.19 lacks a frequency-channel enum in its hwmon API. Explicit attribute
groups expose freq1_input without extending or changing any kernel structures;
libsensors 3.6.2 supports this frequency feature. No PWM/fan attribute is misused.

Cleanup removes hwmon callbacks first, then the independent root parent, then
unmaps the register. All partial initialization failures release acquired state.
