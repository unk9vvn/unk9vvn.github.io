# Segment Address Offset Randomization

## Check List

* [ ] Confirm that ASLR is enabled at the operating-system level.
* [ ] Verify that the executable supports ASLR.
* [ ] Verify that loaded libraries and modules support relocation.
* [ ] Confirm that the main executable supports position-independent loading where required.
* [ ] Check whether memory regions receive different base addresses across separate executions.
* [ ] Review the stack, heap, shared libraries, and main executable independently.
* [ ] Confirm that 64-bit high-entropy address randomization is supported where applicable.
* [ ] Check for modules that use fixed or predictable addresses.
* [ ] Identify address disclosures that could reduce ASLR effectiveness.
* [ ] Confirm that ASLR is combined with DEP/NX and control-flow protections.
* [ ] Record exceptions, unsupported modules, and observed limitations.
* [ ] Reassess ASLR after application, library, operating-system, or configuration changes.

## Cheat Sheet

### Windows

#### Activate ASLR via Control Panel

1. Search for Virus and threat protection in the Search bar and open it.
2. Click on App & browser control.
3. Click on Exploit protection settings.
4. In System settings tab, under Force randomization for images (Mandatory ASLR), choose On by default.
5. In System settings tab, under Randomize memory allocations (Bottom-up ASLR), choose On by default. Use default (On) is also acceptable.
6. In System settings tab, under High-entropy ASLR, choose On by default. Use default (On) is also acceptable.

#### Activate ASLR via Powershell

1. Open Powershell (run as Administrator)
2. Check current status:

```bash
Get-ProcessMitigation -System | Select-Object -ExpandProperty Aslr
```

Values:

* OverrideForceRelocateImages: Forces the system Mandatory ASLR setting over per-app settings.
  * False: Use normal system/app behavior — Best compatibility. Recommended.
  * True: Force the system setting over app-specific settings — Stronger enforcement, possible app issues.
* OverrideBottomUp: Forces the system bottom-up ASLR setting over per-app settings.
  * False: Use normal system/app behavior — Recommended.
  * True: Force bottom-up ASLR over app-specific settings — Slightly stricter, possible compatibility issues.
* OverrideHighEntropy: Forces the system high-entropy ASLR setting over per-app settings.
  * False: Use normal system/app behavior — Recommended.
  * True: Force high-entropy ASLR over app-specific settings — Stricter, mainly matters for 64-bit apps.
* ForceRelocateImages: Randomizes EXE/DLL load addresses even if they were not built with ASLR.
  * ON: Force EXEs/DLLs to load at randomized addresses even if not built for ASLR — Stronger protection. Recommended.
  * OFF: Only ASLR-aware images are randomized — Better compatibility, weaker protection.
* RequireInfo: Requires relocation info in binaries for forced relocation to work.
  * ON: Require relocation info in binaries — Stronger enforcement, old apps may fail to load.
  * OFF: Don’t require relocation info — Better compatibility. Recommended.
* BottomUp: Randomizes memory allocation addresses like heaps, stacks, and VirtualAlloc.
  * ON: Randomize heaps, stacks, and memory allocations — Stronger protection. Recommended.
  * OFF: More predictable memory layout — Weaker protection.
* HighEntropy: Uses more address-space randomness, mainly for 64-bit processes.
  * ON: Use more randomness for 64-bit address space — Stronger protection. Recommended on 64-bit Windows.
  * OFF: Use less randomness — Weaker protection.

3. To enable the recommended settings:

```bash
Set-ProcessMitigation -System -Enable BottomUp,HighEntropy,ForceRelocateImages -Disable RequireInfo
```

### Linux

#### Check ASLR activation

{% hint style="info" %}
Check ASLR activation (0 = inactive, 1 = partial ASRL, 2 = full ASLR)
{% endhint %}

```bash
cat /proc/sys/kernel/randomize_va_space
```

#### [Gcc](https://gcc.gnu.org/) & [Clang](https://clang.llvm.org/docs/ClangTools.html)

{% hint style="info" %}
Compile a program in Position-Independent format
{% endhint %}

```bash
gcc -pie -fPIE -o [program name] [program name].c 
```

```bash
clang -pie -fPIE -o [program name] [program name].c
```

{% hint style="info" %}
MSVC (Windows):
{% endhint %}

```bash
cl /DYNAMICBASE source.c
```

{% hint style="info" %}
golang:
{% endhint %}

```bash
go build -buildmode=pie -o [program name] .
```

#### [File](https://man7.org/linux/man-pages/man1/file.1.html) & [Checksec](https://github.com/slimm609/checksec)

{% hint style="info" %}
Check PIE flag in a binary
{% endhint %}

```bash
file mybinary | grep pie
```

```bash
checksec –file=mybinary | grep "PIE enabled"
```
