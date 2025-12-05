# Function Dumper

A tiny tool that **dumps all the functions in a binary as `typedef`s**. It works by parsing exports and sections, so you get a neat map of everything you can hook or reference.

## Why This Exists

I wanted a tool to dump function typedefs for easy hooking. this is not great for large binaries but is nice for simple stuff you need to dump quickly.

## Features

* Parses both **exports** and **sections**.
* Generates clean `typedef`s for every function it finds.
* Compilable with **g++** or **MSVC**.

## Getting Started

**Compile it:**

* With g++:

```bash
g++ -o dumper.exe dumper.cpp
```

* With MSVC:

```bash
cl dumper.cpp
```

**Run it:**

```bash
./dumper target_binary.exe <exe_or_dll> <output.h>
```

## Notes
* Only functions with proper exports or identifiable sections will show up neatly.
## COMING SOON:
- PDB parser so you can get function names as well.
- More methods of finding functions.
- Dynamic type dumping.
- Faster for large binaries.
### Example Dump
<img width="1920" height="1032" alt="image" src="https://github.com/user-attachments/assets/1634f1bf-bd99-46a2-bb13-eef1e7e2fd6c" />
