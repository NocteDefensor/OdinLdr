# OdinLdr

![Draugr](img/odin.png)

Cobaltstrike UDRL for beacon and post-ex tools.

Use NtApi call with synthetic stackframe to confuse EDR based on stackframe detection.

# Beacon

Use BeaconUserData structure to give memory information to beacon and allocate memory for BOF & Sleepmask.

This UDRL allocate memory region in RW for beacon, copy virtual beacon and patch IAT/reloc then correct memory protection is set for each section.

All virtual beacon section is set to TRUE for MASK_TRUE in ALLOCATED_MEMORY structure (BeaconUserData).

# Post-Ex

Somes post-ex tools of cobaltstrike (powerpick, execute-assembly, mimikatz, ...) is reflective dll and need custom reflective loader to be more opsec. 

The loader is same to beacon at the exception to the rdata section is in RW and not read only.

# Be careful

- Is not because you have an post-ex UDRL that all you're postex can pass, the behaviours is also present and you need a custom injection (process-inject kit, you can use synthetic stackframe easly with Draugr).

- Also, the UDRL have just an impact on mapping of DLL not the execution.

- No sleep encryption, but with BeaconUserData present on this UDRL it's sleepmask kit friendly

- If you powershell or assembly with ```amsi_disable``` a true, cobaltstrike patch AMSI and it's an IoC, you can add HWBP hooking on AmsiScanBuffer for ```powershell.dll``` and ```invokeassembly.dll``` (name of postex dll in cobaltstrike).

# Opsec feature

- Use synthetic stackframe (same code for Draugr) for NtApi call
- Set memory information in BeaconUserData structure

# Credit

- Sektor7 : https://institute.sektor7.net/
- Cobaltstrike : https://www.cobaltstrike.com/