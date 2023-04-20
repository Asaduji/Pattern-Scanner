# Pattern-Scan-Example
Example of pattern scanner in c++

This will find an IDA like pattern in the specified module.

Supports patterns between memory regions and ignores the ones without read permissions

Works for both x86 and x64

Example of usage:

```c++
find_pattern(GetModuleHandleW(0), "55 8B EC 6A ? 68 ? ? ? ? 64");
```
