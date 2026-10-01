# BoringSslConsole

A deliberately small proof-of-concept console application that connects to HTTPS servers using a custom .NET wrapper around BoringSSL. 

The wrapper routes all BoringSSL native read/write operations through a managed .NET `NetworkStream` via custom BIO callbacks.

```text
TcpClient
   |
NetworkStream
   |
custom BoringSSL BIO
   |
BoringSSL (Thread-Safe Wrappers)
   |
HTTPS (Full-Duplex + X509 Validation)
```

## Key Features

- **Full-Duplex Architecture:** The native `_sslLock` has been refactored into independent read/write and network synchronization locks (`_readLock`, `_writeLock`, `_networkReadLock`, `_networkWriteLock`). This allows the .NET application to read and write over TLS concurrently without risking memory corruption or race conditions within the native OpenSSL/BoringSSL `SSL*` state machine.
- **Production-Grade Certificate Validation:** Built-in cryptographic chain validation (`X509Chain`) utilizing the host operating system's trusted root certificate store. It natively enforces online revocation checks (`X509RevocationMode.Online`).
- **Secure Hostname & Wildcard Matching:** Uses modern .NET 8 API (`certificate.MatchesHostname`) to safely validate Server Alternative Names (SAN) and Common Names (CN), including strict adherence to RFC 6125 wildcard rules (preventing sub-domain bypasses).
- **Flawless Chrome JA4 Fingerprinting:** Achieves a 100% perfect JA4 match with Google Chrome. The C++ native layer and C# presets coordinate to replicate browser features seamlessly, including GREASE orchestration, dynamic ALPN/ALPS context slicing, precise `status_request` padding, post-quantum ML-KEM/ML-DSA groups, and extension permutation.

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

This project incorporates BoringSSL and Google Brotli as Git submodules to ensure consistent, standalone compilation:

```text
BoringSslConsole/
  BoringSslConsole/ (Managed C# Project)
  Native/           (Native C++ Wrapper & CMake configuration)
  boringssl/        <-- Git submodule
  brotli/           <-- Git submodule (Required for certificate compression)
```

To clone this repository along with the BoringSSL dependency, run:

```powershell
git clone --recursive <BoringSslConsole-Repository-Url>
```

The project builds its own copy of BoringSSL and links the Brotli decoder/encoder components statically into a single, fully autonomous `proxymap_boringssl.dll` to prevent runtime `DllNotFoundException` errors.

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

1. Opens a standard TCP connection to the target server (e.g., `tls.peet.ws:443`).
2. Creates a BoringSSL `SSL*` object and configures context parameters passed dynamically from C# (Cipher list, ALPN, ALPS protocols, Signature Algorithms, and GREASE flags).
3. Connects the TLS state machine to custom, memory-isolated static read and write BIOs (`BIO_s_mem`).
4. Performs `SSL_connect()` via asynchronous native callbacks.
5. **Validates the Server Certificate:** Immediately after a successful TLS handshake, it extracts the server's DER-encoded X509 certificate via the native wrapper. It runs a full OS-level chain validation and matches the connection hostname.
6. Prints the negotiated TLS version and cipher suite name.
7. Sends an HTTP/1.1 `GET` request using asynchronous full-duplex stream writes.
8. Streams the HTTP response, simultaneously printing it to the console and saving it into the `./output/` directory.

## Testing Certificate Validation

The `Program.cs` file includes a set of pre-configured, commented-out test hosts from the **badssl.com** project to verify secure error-handling:

- `tls.peet.ws` / `badssl.com` - **Standard Verification:** Connection should succeed.
- `expired.badssl.com` - **Expiration Failure:** Handshake must fail during `X509Chain` building.
- `untrusted-root.badssl.com` - **Trust Failure:** Handshake must fail due to an unknown root authority.
- `revoked.badssl.com` - **Revocation Failure:** Handshake must fail because the certificate was revoked by the CA.

## Current Status

The underlying architecture is fully complete, completely thread-safe, and passes advanced fingerprinting verifications (JA3/JA4/JA5 engines). The client appears identical to an official Google Chrome browser build to edge infrastructure (Cloudflare, Akamai, etc.).
