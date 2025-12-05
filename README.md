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
./dumper target_binary.exe
```

## Notes

* Works best with binaries you have permission to read.
* Only functions with proper exports or identifiable sections will show up neatly.

If you want, I can also **make it sound even slicker**, like a dev-tool landing page with a “why it’s cool” section. That usually grabs attention on GitHub. Do you want me to do that version too?
