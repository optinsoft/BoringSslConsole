# BoringSslConsole

A deliberately small proof-of-concept console application that connects to
`https://tls.peet.ws/api/all` using BoringSSL, while BoringSSL reads and
writes through a managed .NET `NetworkStream` via a custom BIO.

The purpose of this first version is **not** to imitate Chrome. It is only to
prove that the architecture works:

```text
TcpClient
   |
NetworkStream
   |
custom BoringSSL BIO
   |
BoringSSL
   |
HTTPS
```

`TrackMe - fingerprinting API` reports the TLS protocol, cipher suites, extensions,
JA3 and JA4, so it is useful for comparing the first BoringSSL ClientHello with
a normal browser later. See https://tls.peet.ws/api/all

## Prerequisites (Windows)

- .NET 8 SDK
- Visual Studio 2022 with C++ tools
- CMake 3.22+
- Ninja
- Git
- NASM
- Go

BoringSSL documents its current build requirements in BUILDING.md:
https://github.com/google/boringssl/blob/main/BUILDING.md

## Directory layout

This project incorporates BoringSSL as a Git submodule to ensure consistent builds:

```text
BoringSslConsole/
  BoringSslConsole/
  Native/
  boringssl/       <-- Git submodule
```

To clone this repository along with the BoringSSL dependency, run:

```powershell
git clone --recursive <BoringSslConsole-Repository-Url>
```

The project deliberately builds its own copy of BoringSSL because BoringSSL does not promise a stable API/ABI for third-party consumers.

## Build

Open a **Visual Studio Developer PowerShell** for x64 and run:

```powershell
cd Native
Remove-Item -Recurse -Force build  
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Then:

```powershell
cd ..
dotnet run --project BoringSslConsole
```

The native DLL is copied to the .NET output directory automatically.

## What the program does

1. Opens a normal TCP connection to `tls.peet.ws:443`.
2. Creates a BoringSSL `SSL*` object.
3. Gives BoringSSL a custom BIO.
4. The BIO callbacks call the managed `NetworkStream`.
5. Performs `SSL_connect()`.
6. Sends a simple HTTP/1.1 request for `/api/all`.
7. Prints the HTTP response.

Certificate verification is intentionally disabled in this first experiment.
This is **not** suitable for production until certificate validation is added.

The native layer also reports the negotiated TLS version and cipher.

## Next step

Once this works, capture the ClientHello in Wireshark and compare it with
Chrome. Only then modify BoringSSL's TLS configuration/ClientHello generation.
