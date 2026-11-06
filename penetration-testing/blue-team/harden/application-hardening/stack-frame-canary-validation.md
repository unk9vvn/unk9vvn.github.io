# Stack Frame Canary Validation

## Check List

* [ ] `-fstack-protector-strong` is generally a practical baseline for GCC and Clang.
* [ ] `-fstack-protector-all` provides broader coverage with potentially higher performance and code-size overhead.
* [ ] `/GS` enables Microsoft Visual C++ stack-based buffer security checks.
* [ ] A canary check does not protect every function, every stack object, or every type of memory corruption.
* [ ] The presence of `__stack_chk_fail` or `__security_check_cookie` is useful evidence, but does not prove that every function is protected.
* [ ] Use this control together with ASLR, NX/DEP, CFI/CFG, Shadow Stack/CET, sanitizers, fuzzing, and secure input handling.

## Cheat Sheet

### [GCC](https://gcc.gnu.org/)

{% hint style="info" %}
Compile with the default stack protector
{% endhint %}

```bash
gcc -O2 -fstack-protector "$SOURCE.c" -o "$OUTPUT"
```

{% hint style="info" %}
Compile with the stronger stack protector
{% endhint %}

```bash
gcc -O2 -fstack-protector-strong "$SOURCE.c" -o "$OUTPUT"
```

{% hint style="info" %}
Protect all functions
{% endhint %}

```bash
gcc -O2 -fstack-protector-all "$SOURCE.c" -o "$OUTPUT"
```

{% hint style="info" %}
Enable explicit stack protection only for annotated functions
{% endhint %}

```bash
gcc -O2 -fstack-protector-explicit "$SOURCE.c" -o "$OUTPUT"
```

{% hint style="info" %}
Compile with stack-protector diagnostics (`-Wstack-protector` warns about functions that cannot be protected when a stack-protector option is enabled.)
{% endhint %}

```bash
gcc -O2 -fstack-protector-strong -Wstack-protector "$SOURCE.c" -o "$OUTPUT"
```

{% hint style="info" %}
Disable stack-protector instrumentation for a specific build
{% endhint %}

```bash
gcc -O2 -fno-stack-protector "$SOURCE.c" -o "$OUTPUT"
```



### [Clang](https://clang.llvm.org/docs/ClangTools.html)

{% hint style="info" %}
Compile with the stronger stack protector
{% endhint %}

```bash
clang -O2 -fstack-protector-strong "$SOURCE.c" -o "$OUTPUT"
```

{% hint style="info" %}
Protect all functions
{% endhint %}

```bash
clang -O2 -fstack-protector-all "$SOURCE.c" -o "$OUTPUT"
```

{% hint style="info" %}
Disable stack-protector instrumentation for a specific build
{% endhint %}

```bash
clang -O2 -fno-stack-protector "$SOURCE.c" -o "$OUTPUT"
```

### [Readelf](https://man7.org/linux/man-pages/man1/readelf.1.html)

{% hint style="info" %}
Check for stack-checking symbols
{% endhint %}

```bash
readelf -Ws "$BINARY" | grep -E '__stack_chk_fail|__stack_chk_guard'
```

{% hint style="info" %}
Check dynamic symbols
{% endhint %}

```bash
readelf --dyn-syms "$BINARY" | grep -E '__stack_chk_fail|__stack_chk_guard'
```

{% hint style="info" %}
Check ELF security properties in an ARM64 ELF binary
{% endhint %}

```bash
readelf -W -l "$BINARY" | grep -E 'GNU_STACK|GNU_RELRO'
```

### [Objdump](https://man7.org/linux/man-pages/man1/objdump.1.html)

{% hint style="info" %}
Check the dynamic symbol table
{% endhint %}

```bash
objdump -T "$BINARY" | grep -E '__stack_chk_fail|__stack_chk_guard'
```

{% hint style="info" %}
Inspect function disassembly with Intel syntax
{% endhint %}

```bash
objdump -d -M intel "$BINARY" | less
```

{% hint style="info" %}
Search x86-64 disassembly for common canary access patterns
{% endhint %}

```bash
objdump -d -M intel "$BINARY" | grep -E 'fs:0x28|__stack_chk_fail'
```

### [Strings](https://man7.org/linux/man-pages/man1/strings.1.html)

{% hint style="info" %}
Search all strings for stack-protector indicators
{% endhint %}

```bash
strings -a "$BINARY" | grep -E '__stack_chk_fail|stack smashing detected'
```

{% hint style="info" %}
The presence of `__stack_chk_fail` is a strong indication that at least some code was compiled with stack-protector instrumentation. It does not prove complete function coverage. The exact instruction sequence depends on the compiler, optimization level, architecture, ABI, and linker.
{% endhint %}

### [Checksec](https://github.com/slimm609/checksec)

{% hint style="info" %}
Check the binary
{% endhint %}

```bash
checksec --file="$BINARY"
```

{% hint style="info" %}
Check a process image
{% endhint %}

```bash
checksec --pid="$PID"
```

### [MSVC](https://learn.microsoft.com/en-us/cpp/build/reference/compiling-a-c-cpp-program?view=msvc-170)

{% hint style="info" %}
Open the Developer Command Prompt
{% endhint %}

```bat
Start Menu -> Visual Studio -> Developer Command Prompt
```

{% hint style="info" %}
Compile a C source file with `/GS`
{% endhint %}

```bat
cl /nologo /O2 /W4 /GS "$SOURCE.c" /Fe:"$OUTPUT.exe"
```

{% hint style="info" %}
Compile a C++ source file with `/GS`
{% endhint %}

```bat
cl /nologo /O2 /W4 /EHsc /GS "$SOURCE.cpp" /Fe:"$OUTPUT.exe"
```

{% hint style="info" %}
Enable `/GS` explicitly
{% endhint %}

```bat
cl /nologo /O2 /GS "$SOURCE.c" /link /DYNAMICBASE /NXCOMPAT
```

{% hint style="info" %}
Disable `/GS` for a controlled comparison build (Use `/GS-` only for controlled testing. It disables an important compiler mitigation.)
{% endhint %}

```bat
cl /nologo /O2 /GS- "$SOURCE.c" /Fe:"$OUTPUT-no-gs.exe"
```

{% hint style="info" %}
Disable `/GS` for one function
{% endhint %}

```c
#pragma strict_gs_check(push, off)

__declspec(safebuffers)
void "$FUNCTION"(const char *input)
{
    char buffer[32];
    /* Function implementation */
}

#pragma strict_gs_check(pop)
```

{% hint style="info" %}
`__declspec(safebuffers)` disables compiler buffer-security checks for the specified function. Avoid using it unless the function has been reviewed and the exception is justified.
{% endhint %}

### [Dumpbin](https://learn.microsoft.com/en-us/cpp/build/reference/dumpbin-reference?view=msvc-170)

{% hint style="info" %}
Search for the Microsoft security cookie
{% endhint %}

```bat
dumpbin /symbols "$OUTPUT.exe" | findstr /i "__security_cookie"
```

{% hint style="info" %}
Search for the security-cookie validation routine
{% endhint %}

```bat
dumpbin /symbols "$OUTPUT.exe" | findstr /i "__security_check_cookie"
```

{% hint style="info" %}
Inspect imported symbols
{% endhint %}

```bat
dumpbin /imports "$OUTPUT.exe" | findstr /i "security_cookie security_check_cookie"
```

{% hint style="info" %}
Disassemble with Visual Studio tools
{% endhint %}

```bat
dumpbin /disasm "$OUTPUT.exe" > "$OUTPUT.disasm.txt"
```

{% hint style="info" %}
Search for common MSVC cookie routines
{% endhint %}

```bat
findstr /i "__security_cookie __security_check_cookie" "$OUTPUT.disasm.txt"
```

### PowerShell

{% hint style="info" %}
Search a PE binary for common stack-cookie strings
{% endhint %}

```powershell
$Path = ".\$BINARY.exe"

Select-String -Path $Path -Pattern `
    "__security_cookie",
    "__security_check_cookie"
```

### Cross-Compilation

{% hint style="info" %}
Build an ARM64 Linux binary with GCC stack protection
{% endhint %}

```bash
aarch64-linux-gnu-gcc -O2 -fstack-protector-strong "$SOURCE.c" -o "$OUTPUT"
```

{% hint style="info" %}
Inspect the ARM64 binary for stack-checking symbols
{% endhint %}

```bash
aarch64-linux-gnu-readelf -Ws "$BINARY" | grep -E '__stack_chk_fail|__stack_chk_guard'
```
