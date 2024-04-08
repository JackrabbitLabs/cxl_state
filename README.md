# Overview

This is a C library that provides a software representation of the state of a 
CXL switch and attached devices. 

# Supported Operating System Versions

- Ubuntu 23.10
- Fedora 38, 39

# Building

1. Install OS libraries

Install the following build packages to compile the software on the following
operating systems.

**Ubuntu:**

```bash
apt install build-essential libpci-dev
```

**Fedora:**

```bash
```

2. Build Dependencies

This library is dependent upon the following projects. 

- [array_utils](https://github.com/JackrabbitLabs/array_utils)
- [pci_utils](https://github.com/JackrabbitLabs/pci_utils)
- [fmapi](https://github.com/JackrabbitLabs/fmapi)

For each of these repositories, in the order listed, clone and execute: 

```bash 
make install
```

This will install a library (.a) and header file to the standard os location 
(e.g. /usr/local/include, /usr/local/lib)

3. Build

After building the required dependencies run:

```bash
make
```

