# Exception Handler Pointer Validation

## Check List

* [ ] `/SAFESEH` applies to x86 images. SEHOP validates the exception-handler chain at runtime; SafeSEH restricts handlers to those recorded in the image’s SafeSEH table.

## Cheat Sheet

#### [MSVC](https://learn.microsoft.com/en-us/cpp/build/reference/compiling-a-c-cpp-program?view=msvc-170)

1. In Visual Studio with C++, click on Tools -> Command Line -> Developer Command Prompt
2. for C:

```bat
cl /nologo /O2 /W4 /EHsc /GS $APP.c /link /SAFESEH
```

For C++:

```batch
cl /nologo /O2 /W4 /EHsc /GS hello.cpp /link /SAFESEH
```

Or Project -> $PROJECT Properties → Linker → Advanced → Image Has Safe Exception Handlers → Enter: Yes (/SAFESEH)

### [Dumpbin](https://learn.microsoft.com/en-us/cpp/build/reference/dumpbin-reference?view=msvc-170)

{% hint style="info" %}
Check Whether an x86 PE Binary Has a SafeSEH Table
{% endhint %}

```bat
dumpbin /loadconfig $APP.exe | findstr /i "Safe Exception Handler"
```

### Powershell

{% hint style="info" %}
Check SEHOP Settings for a Windows Process
{% endhint %}

```powershell
Get-ProcessMitigation -Name "$PROCESS"
```

{% hint style="info" %}
Check SEHOP Settings for a Windows Process using Process ID
{% endhint %}

```powershell
Get-ProcessMitigation -Id "$PID"
```

{% hint style="info" %}
Check System-Wide Process Mitigation Settings
{% endhint %}

```powershell
Get-ProcessMitigation -System
```

{% hint style="info" %}
Enable SEHOP for a Windows Process
{% endhint %}

```powershell
Set-ProcessMitigation -Name "$PROCESS" -Enable SEHOP
```

{% hint style="info" %}
Enable SEHOP for a Windows Process using Process ID
{% endhint %}

```powershell
Set-ProcessMitigation -Id "$PID" -Enable SEHOP
```

{% hint style="info" %}
Enable SEHOP System-Wide
{% endhint %}

```powershell
Set-ProcessMitigation -System -Enable SEHOP
```

### Windows Settings

Setting -> Privacy & Security -> Windows Security -> App & browser control -> Exploit protection -> Validate exception chains (SEHOP) -> set it to 'On by default'
