namespace BoringSslConsole;

using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

public sealed class BoringSslStream : Stream
{
    private const string ChromeCipherSuitePreset = 
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" +
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" +
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:" +
        "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:" +
        "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
    private const int ChromeEnableGreasePreset = 1;
    private const int ChromeEnableEchGreasePreset = 1;
    private const string ChromeAlpnPreset = "h2:http/1.1";
    private const string ChromeAlpsPreset = "h2";
    private const string ChromeTrustAnchorsPreset = 
        "0582df1302010582df1302060582df13020d0582df13020e0582df1302" +
        "0f0582df1302120582df1302130582df13021408839a648c9b2d010708" +
        "839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a" +
        "648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c" +
        "9b2d011208839a648c9b2d011304d679090104d679090404d679090504" +
        "d679090604d679090704d679090804d679090a04d679090b04d679090c" +
        "04d679090d04d679090f";
    public const string ChromeSignatureAlgorithmsPreset = 
        "ML-DSA-44:ML-DSA-65:ML-DSA-87:" +
        "ECDSA-SECP256R1-SHA256:RSA-PSS-RSAE-SHA256:RSA-PKCS1-SHA256:" +
        "ECDSA-SECP384R1-SHA384:RSA-PSS-RSAE-SHA384:RSA-PKCS1-SHA384:" +
        "RSA-PSS-RSAE-SHA512:RSA-PKCS1-SHA512";
    private const int ChromeEnableSignedCertTimestampsPreset = 1;
    private const int ChromeSetOcspStatusTypePreset = 1;
    private const int ChromeEnableBrotliPreset = 1;

    private const int NetworkBufferSize = 16 * 1024;

    private readonly Stream _innerStream;
    private readonly string _hostname;
    private readonly bool _leaveOpen;
    private readonly IntPtr _connection;

    // SSL* is not accessed concurrently.
    private readonly SemaphoreSlim _readLock = new(1, 1);
    private readonly SemaphoreSlim _writeLock = new(1, 1);

     private readonly SemaphoreSlim _networkWriteLock = new(1, 1);
     private readonly SemaphoreSlim _networkReadLock = new(1, 1);

    private bool _authenticated;
    private bool _disposed;

    /// <summary>
    /// Optional replacement for the built-in server certificate validation
    /// (X509Chain + hostname match). Intended for tests that use self-signed
    /// certificates. Leave null in production code.
    /// </summary>
    public Func<X509Certificate2, bool>? RemoteCertificateValidationCallback { get; set; }

    public BoringSslStream(
        Stream innerStream,
        string hostname,
        string cipherList = ChromeCipherSuitePreset,
        int enableGrease = ChromeEnableGreasePreset,
        int enableEchGrease = ChromeEnableEchGreasePreset,        
        string alpnProtos = ChromeAlpnPreset,
        string alpsProtos = ChromeAlpsPreset,
        string trustAnchors = ChromeTrustAnchorsPreset,
        string sigAlgs = ChromeSignatureAlgorithmsPreset,
        int enableSignedCertTimestamps = ChromeEnableSignedCertTimestampsPreset,
        int setOcspStatusType = ChromeSetOcspStatusTypePreset,
        int enableBrotli = ChromeEnableBrotliPreset,
        bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(innerStream);
        ArgumentException.ThrowIfNullOrWhiteSpace(hostname);

        _innerStream = innerStream;
        _hostname = hostname;
        _leaveOpen = leaveOpen;

        _connection = Native.pms_ssl_create(
            hostname,
            cipherList,
            enableGrease,
            enableEchGrease,
            alpnProtos,
            alpsProtos,
            trustAnchors,
            sigAlgs,
            enableSignedCertTimestamps,
            setOcspStatusType,
            enableBrotli);

        if (_connection == IntPtr.Zero)
        {
            throw new IOException(
                $"Failed to create BoringSSL connection: " +
                $"{GetNativeError()}");
        }
    }

    public string ProtocolVersion
    {
        get
        {
            ThrowIfDisposed();

            return Marshal.PtrToStringUTF8(
                       Native.pms_ssl_get_protocol_version(
                           _connection))
                   ?? string.Empty;
        }
    }

    public string CipherName
    {
        get
        {
            ThrowIfDisposed();

            return Marshal.PtrToStringUTF8(
                       Native.pms_ssl_get_cipher_name(
                           _connection))
                   ?? string.Empty;
        }
    }

    public string AlpnSelected
    {
        get
        {
            ThrowIfDisposed();

            return Marshal.PtrToStringAnsi(
                       Native.pms_ssl_get_alpn_selected(
                           _connection)) 
                   ?? string.Empty;
        }
    }

    public async ValueTask AuthenticateAsClientAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        await _readLock.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        try
        {
            await _writeLock.WaitAsync(cancellationToken)
                .ConfigureAwait(false);
                
            try
            {

                if (_authenticated)
                    return;

                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    int result =
                        Native.pms_ssl_connect(_connection);

                    await FlushWriteBioAsync(
                            cancellationToken)
                        .ConfigureAwait(false);

                    switch (result)
                    {
                        case Native.PMS_SSL_OK:
                            ValidateServerCertificate(_hostname);
                            _authenticated = true;
                            return;

                        case Native.PMS_SSL_WANT_READ:
                            await ReadFromNetworkAsync(
                                    cancellationToken)
                                .ConfigureAwait(false);
                            break;

                        case Native.PMS_SSL_WANT_WRITE:
                            // Output has already been flushed.
                            break;

                        case Native.PMS_SSL_ZERO_RETURN:
                            throw new IOException(
                                "BoringSSL handshake was closed " +
                                "by the peer.");

                        default:
                            throw CreateSslException(
                                "BoringSSL handshake failed");
                    }
                }
            }
            finally
            {
                _writeLock.Release();
            }
        }
        finally
        {
            _readLock.Release();
        }
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (buffer.Length == 0)
            return 0;

        await _readLock.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        try
        {
            EnsureAuthenticated();

            using MemoryHandle handle = buffer.Pin();

            IntPtr pointer = GetHandlePointer(handle);

            return await ReadCoreAsync(
                    pointer,
                    buffer.Length,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _readLock.Release();
        }
    }

    private async ValueTask<int> ReadCoreAsync(
        IntPtr buffer,
        int length,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int result = Native.pms_ssl_read(
                _connection,
                buffer,
                length);

            // SSL_read can generate TLS output itself.
            await FlushWriteBioAsync(
                    cancellationToken)
                .ConfigureAwait(false);

            switch (result)
            {
                case > 0:
                    return result;

                case Native.PMS_SSL_ZERO_RETURN:
                    return 0;

                case Native.PMS_SSL_WANT_READ:
                    await ReadFromNetworkAsync(
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;

                case Native.PMS_SSL_WANT_WRITE:
                    // Output was flushed above.
                    break;

                default:
                    throw CreateSslException(
                        "BoringSSL read failed");
            }
        }
    }

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (buffer.Length == 0)
            return;

        await _writeLock.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        try
        {
            EnsureAuthenticated();

            using MemoryHandle handle = buffer.Pin();

            IntPtr pointer = GetHandlePointer(handle);

            await WriteCoreAsync(
                    pointer,
                    buffer.Length,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async ValueTask WriteCoreAsync(
        IntPtr buffer,
        int length,
        CancellationToken cancellationToken)
    {
        int offset = 0;

        while (offset < length)
        {
            cancellationToken.ThrowIfCancellationRequested();

            IntPtr current =
                IntPtr.Add(buffer, offset);

            int result = Native.pms_ssl_write(
                _connection,
                current,
                length - offset);

            await FlushWriteBioAsync(
                    cancellationToken)
                .ConfigureAwait(false);

            switch (result)
            {
                case > 0:
                    offset += result;
                    break;

                case Native.PMS_SSL_WANT_READ:
                    await ReadFromNetworkAsync(
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;

                case Native.PMS_SSL_WANT_WRITE:
                    // Output was flushed above.
                    break;

                case Native.PMS_SSL_ZERO_RETURN:
                    throw new IOException(
                        "BoringSSL connection was closed " +
                        "by the peer.");

                default:
                    throw CreateSslException(
                        "BoringSSL write failed");
            }
        }
    }

    private async ValueTask ReadFromNetworkAsync(
        CancellationToken cancellationToken)
    {
        await _networkReadLock.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        byte[] buffer =
            ArrayPool<byte>.Shared.Rent(
                NetworkBufferSize);

        try
        {
            Memory<byte> memory =
                buffer.AsMemory(
                    0,
                    NetworkBufferSize);

            int read = await _innerStream.ReadAsync(
                    memory,
                    cancellationToken)
                .ConfigureAwait(false);

            if (read == 0)
            {
                throw new EndOfStreamException(
                    "Underlying stream was closed.");
            }

            using MemoryHandle handle =
                memory[..read].Pin();

            IntPtr pointer = GetHandlePointer(handle);

            int accepted =
                Native.pms_ssl_feed_read(
                    _connection,
                    pointer,
                    read);

            if (accepted != read)
            {
                throw CreateSslException(
                    $"BoringSSL accepted {accepted} " +
                    $"of {read} bytes");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            _networkReadLock.Release();
        }
    }

    private async ValueTask FlushWriteBioAsync(
        CancellationToken cancellationToken)
    {
        await _networkWriteLock.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        byte[] buffer =
            ArrayPool<byte>.Shared.Rent(
                NetworkBufferSize);

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int pending =
                    Native.pms_ssl_pending_write(
                        _connection);

                if (pending < 0)
                {
                    throw CreateSslException(
                        "Failed to inspect BoringSSL write BIO");
                }

                if (pending == 0)
                    return;

                int size = Math.Min(
                    pending,
                    buffer.Length);

                Memory<byte> memory =
                    buffer.AsMemory(0, size);

                using MemoryHandle handle =
                    memory.Pin();

                IntPtr pointer = GetHandlePointer(handle);

                int read =
                    Native.pms_ssl_take_write(
                        _connection,
                        pointer,
                        size);

                if (read < 0)
                {
                    throw CreateSslException(
                        "Failed to read BoringSSL write BIO");
                }

                if (read == 0)
                    return;

                await _innerStream.WriteAsync(
                        memory[..read],
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            _networkWriteLock.Release();
        }
    }

    private void EnsureAuthenticated()
    {
        if (!_authenticated)
        {
            throw new InvalidOperationException(
                "Call AuthenticateAsClientAsync() first.");
        }
    }

    private static IOException CreateSslException(
        string message)
    {
        string error = GetNativeError();

        return new IOException(
            string.IsNullOrWhiteSpace(error)
                ? message
                : $"{message}: {error}");
    }

    private static string GetNativeError()
    {
        IntPtr pointer =
            Native.pms_ssl_get_last_error();

        if (pointer == IntPtr.Zero)
            return "unknown native error";

        return Marshal.PtrToStringUTF8(pointer)
            ?? "unknown native error";
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(
            _disposed,
            this);
    }

    private static unsafe IntPtr GetHandlePointer(
        MemoryHandle handle)
    {
        return (IntPtr)handle.Pointer;
    }

    // ------------------------------------------------------------
    // Stream
    // ------------------------------------------------------------

    public override bool CanRead =>
        !_disposed;

    public override bool CanSeek =>
        false;

    public override bool CanWrite =>
        !_disposed;

    public override long Length =>
        throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
        ThrowIfDisposed();

        FlushAsync(CancellationToken.None)
            .GetAwaiter()
            .GetResult();
    }

    public override Task FlushAsync(
        CancellationToken cancellationToken)
    {
        return FlushAsyncCore(
            cancellationToken);
    }

    private async Task FlushAsyncCore(
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        await _writeLock.WaitAsync(
                cancellationToken)
            .ConfigureAwait(false);

        try
        {
            await FlushWriteBioAsync(
                    cancellationToken)
                .ConfigureAwait(false);

            await _innerStream.FlushAsync(
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public override int Read(
        byte[] buffer,
        int offset,
        int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        ValidateBufferArguments(
            buffer,
            offset,
            count);

        ValueTask<int> readTask = ReadAsync(
            buffer.AsMemory(offset, count),
            CancellationToken.None);

        if (readTask.IsCompleted)
        {
            return readTask
                .GetAwaiter()
                .GetResult();
        }
        else
        {
            return readTask
                .AsTask()
                .GetAwaiter()
                .GetResult();
        }
    }

    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        ValidateBufferArguments(
            buffer,
            offset,
            count);

        return ReadAsync(
                buffer.AsMemory(offset, count),
                cancellationToken)
            .AsTask();
    }

    public override void Write(
        byte[] buffer,
        int offset,
        int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        ValidateBufferArguments(
            buffer,
            offset,
            count);

        ValueTask writeTask = WriteAsync(
            buffer.AsMemory(offset, count), 
            CancellationToken.None);

        if (writeTask.IsCompleted)
        {
            writeTask
                .GetAwaiter()
                .GetResult();
        }
        else
        {
            writeTask
                .AsTask()
                .GetAwaiter()
                .GetResult();
        }
    }

    public override Task WriteAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        ValidateBufferArguments(
            buffer,
            offset,
            count);

        return WriteAsync(
                buffer.AsMemory(offset, count),
                cancellationToken)
            .AsTask();
    }

    private static new void ValidateBufferArguments(
        byte[] buffer,
        int offset,
        int count)
    {
        if ((uint)offset > (uint)buffer.Length ||
            (uint)count > (uint)(buffer.Length - offset))
        {
            throw new ArgumentOutOfRangeException();
        }
    }

    public override long Seek(
        long offset,
        SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        _disposed = true;

        Native.pms_ssl_free(
            _connection);

        if (disposing)
        {
            _readLock.Dispose();
            _writeLock.Dispose();
            _networkWriteLock.Dispose();
            _networkReadLock.Dispose();

            if (!_leaveOpen)
                _innerStream.Dispose();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        _disposed = true;

        Native.pms_ssl_free(
            _connection);

        _readLock.Dispose();
        _writeLock.Dispose();
        _networkWriteLock.Dispose();
        _networkReadLock.Dispose();

        if (!_leaveOpen)
        {
            await _innerStream
                .DisposeAsync()
                .ConfigureAwait(false);
        }

        GC.SuppressFinalize(this);
    }

    // ------------------------------------------------------------
    // Native API
    // ------------------------------------------------------------

    private static class Native
    {
        internal const int PMS_SSL_OK = 1;
        internal const int PMS_SSL_ZERO_RETURN = 0;
        internal const int PMS_SSL_ERROR = -1;
        internal const int PMS_SSL_WANT_READ = -2;
        internal const int PMS_SSL_WANT_WRITE = -3;

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_create")]
        internal static extern IntPtr pms_ssl_create(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string hostname,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string cipherList,
            int enableGrease,
            int enableEchGrease,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string alpnProtos,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string alpsProtos,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string trustAnchors,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string sigAlgs,
            int enableSignedCertTimestamps,
            int setOcspStatusType,
            int enableBrotli);

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_connect")]
        internal static extern int pms_ssl_connect(
            IntPtr connection);

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_feed_read")]
        internal static extern int pms_ssl_feed_read(
            IntPtr connection,
            IntPtr buffer,
            int length);

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_take_write")]
        internal static extern int pms_ssl_take_write(
            IntPtr connection,
            IntPtr buffer,
            int length);

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_pending_write")]
        internal static extern int pms_ssl_pending_write(
            IntPtr connection);

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_read")]
        internal static extern int pms_ssl_read(
            IntPtr connection,
            IntPtr buffer,
            int length);

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_write")]
        internal static extern int pms_ssl_write(
            IntPtr connection,
            IntPtr buffer,
            int length);

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_get_protocol_version")]
        internal static extern IntPtr pms_ssl_get_protocol_version(
            IntPtr connection);

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_get_cipher_name")]
        internal static extern IntPtr pms_ssl_get_cipher_name(
            IntPtr connection);

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_get_alpn_selected")]
        internal static extern IntPtr pms_ssl_get_alpn_selected(
            IntPtr connection);

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_get_last_error")]
        internal static extern IntPtr pms_ssl_get_last_error();

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_free")]
        internal static extern void pms_ssl_free(
            IntPtr connection);

        [DllImport(
            "proxymap_boringssl",
            CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "pms_ssl_get_peer_certificate")]
        internal static extern int pms_ssl_get_peer_certificate(
            IntPtr connection,
            IntPtr buffer,
            int maxLength);
    }

    // ------------------------------------------------------------
    // Validate Server Certificate
    // ------------------------------------------------------------

    private void ValidateServerCertificate(string hostname)
    {
        int certLen = Native.pms_ssl_get_peer_certificate(_connection, IntPtr.Zero, 0);
        if (certLen < 0)
        {
            throw CreateSslException("Failed to get server certificate size");
        }
        if (certLen == 0)
        {
            throw new AuthenticationException("The server did not provide an SSL certificate.");
        }

        byte[] rentBuffer = ArrayPool<byte>.Shared.Rent(certLen);
        try
        {
            Memory<byte> memory = rentBuffer.AsMemory(0, certLen);
            using (MemoryHandle handle = memory.Pin())
            {
                IntPtr pointer = GetHandlePointer(handle);
                int readBytes = Native.pms_ssl_get_peer_certificate(
                    _connection,
                    pointer,
                    certLen);

                if (readBytes != certLen)
                {
                    throw CreateSslException("Failed to read complete server certificate");
                }
            }

            using var certificate = new X509Certificate2(memory.Span);

            if (RemoteCertificateValidationCallback is { } validate)
            {
                if (!validate(certificate))
                {
                    throw new AuthenticationException(
                        "The server certificate was rejected by RemoteCertificateValidationCallback.");
                }
                return;
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

            chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1")); // Server Auth

            if (!chain.Build(certificate))
            {
                var errors = string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()));
                throw new AuthenticationException($"Certificate chain validation failed: {errors}");
            }

            if (!certificate.MatchesHostname(hostname))
            {
                throw new AuthenticationException($"The hostname '{hostname}' does not match the server certificate.");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentBuffer);
        }
    }
}