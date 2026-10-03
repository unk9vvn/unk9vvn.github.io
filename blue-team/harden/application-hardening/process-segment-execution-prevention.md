# Process Segment Execution Prevention

## Check List

* [ ] Verify that DEP/NX or XD is enabled.
* [ ] Configure DEP as `AlwaysOn` or the equivalent for sensitive processes.
* [ ] Monitor `RW → RX/RWX` permission changes.
* [ ] Investigate the `Allocate → Write → Change Permission → Execute` sequence.
* [ ] Detect code execution from the stack, heap, or private memory.
* [ ] Distinguish legitimate JIT, runtime, packer, and instrumentation behavior.
* [ ] Analyze execute access violations with crash dumps and call stacks.
* [ ] Combine DEP with ASLR, CFG/CFI, CET, and W^X.
* [ ] On Linux, review `PT_GNU_STACK`, `mmap`, `mprotect`, and `PROT_EXEC` mappings.
* [ ] Do not treat a single event as conclusive proof of exploitation or malware.

## Cheat Sheet

### Windows

#### Activate DEP via Control Panel

1. Open the Control Panel.
2. Click System and Security > System
3. in the About page, find Advanced System Settings.
4. Once you are on the Advanced tab, click Settings under Performance section.
5. Click the Data Execution Prevention tab.
6. Select Turn on DEP for essential Windows programs and services only.
7. Click OK. Make sure to restart your system in order to enable the change.

#### Activate DEP via CMD

1. Open cmd (run as Administrator)
2. Check current status:

```bash
bcdedit /enum {current} | findstr nx
```

values:

* OptIn: On for Windows components only (default) — Safest for compatibility. Most legacy/old apps won’t break. Weakest protection.
* OptOut: On for all, user can exclude apps (recommended) — Strong protection. Rare chance some old apps crash. You can whitelist them via System Properties → Performance Settings → DEP tab.
* AlwaysOn: On for everything, no exceptions — Maximum protection. No way to exclude apps. Some old software may permanently break.
* AlwaysOff: Fully disabled — No protection at all. Only use this for specific debugging/testing scenarios. Not recommended for daily use.

3. To enable it for Windows components only

```bash
bcdedit /set {current} nx  OptIn
```

To enable it for all with exceptions:

```bash
bcdedit /set {current} nx OptOut
```

To enable it for everything with no exceptions:

```bash
bcdedit /set {current} nx  AlwaysOn
```

Check activation of hardware-enforced DEP

```bash
wmic OS Get DataExecutionPrevention_Available
```

#### Check DEP activation in Windows Security

1. Settings > Privacy & Security > Windows Security
2. Click App & browser Control > Exploit protection settings below Exploit protection section
3. Under Data Execution Prevention (DEP) section, choose On by default. Use default (On) is also acceptable

#### Windows Native APIs

Monitor these APIs:

* VirtualAlloc
* VirtualProtect
* NtAllocateVirtualMemory
* NtProtectVirtualMemory
* WriteProcessMemory
* CreateRemoteThread

### Linux

#### [Dmesg](https://man7.org/linux/man-pages/man1/dmesg.1.html)

{% hint style="info" %}
Check NX bit activation
{% endhint %}

```bash
dmesg | grep -i "nx\|execute"
```

#### [Gcc](https://gcc.gnu.org/) & [Clang](https://clang.llvm.org/docs/ClangTools.html)

{% hint style="info" %}
Compile with NX bit
{% endhint %}

```bash
gcc -z noexecstack -o [program name] [program name].c 
```

```bash
clang -z,noexecstack -o [program name] [program name].c 
```

{% hint style="info" %}
Check NX bit presence in a binary (the output should be RW)
{% endhint %}

```bash
readelf -W -l $PATH | grep GNU_STACK 
```

#### Linux Native APIs

Monitor these APIs:

* mmap
* mprotect
* ptrace
* process\_vm\_writev
