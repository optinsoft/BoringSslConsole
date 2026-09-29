using System.Runtime.InteropServices;

public sealed class BoringSslStream : Stream
{
    private readonly Stream _innerStream;
    private readonly GCHandle _streamHandle;
    private readonly nint _connection;
    private bool _disposed;

    public BoringSslStream(Stream innerStream, string hostname)
    {
        _innerStream = innerStream;

        _streamHandle = GCHandle.Alloc(innerStream);

        _connection = NativeMethods.Create(
            GCHandle.ToIntPtr(_streamHandle),
            ReadCallback,
            WriteCallback,
            hostname);

        if (_connection == 0)
        {
            _streamHandle.Free();
            throw new InvalidOperationException(
                "Failed to create BoringSSL connection.");
        }
    }

    public void AuthenticateAsClient()
    {
        ThrowIfDisposed();

        int result = NativeMethods.Connect(_connection);

        if (result != 1)
        {
            var error = Marshal.PtrToStringAnsi(
                NativeMethods.GetLastError());

            throw new IOException(
                $"BoringSSL handshake failed: {error}");
        }
    }

    public string ProtocolVersion
    {
        get
        {
            ThrowIfDisposed();

            return Marshal.PtrToStringAnsi(
                NativeMethods.GetProtocolVersion(_connection))
                ?? string.Empty;
        }
    }

    public string CipherName
    {
        get
        {
            ThrowIfDisposed();

            return Marshal.PtrToStringAnsi(
                NativeMethods.GetCipherName(_connection))
                ?? string.Empty;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ThrowIfDisposed();

        return NativeMethods.Read(
            _connection,
            buffer,
            offset,
            count);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        ThrowIfDisposed();

        int written = NativeMethods.Write(
            _connection,
            buffer,
            offset,
            count);

        if (written < 0)
        {
            var error = Marshal.PtrToStringAnsi(
                NativeMethods.GetLastError());

            throw new IOException(
                $"BoringSSL write failed: {error}");
        }

        if (written != count)
        {
            throw new IOException(
                $"BoringSSL wrote only {written} of {count} bytes.");
        }
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;

    public override long Length =>
        throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
        // Nothing to flush.
    }

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException();

    public override void SetLength(long value) =>
        throw new NotSupportedException();

    private static int ReadCallback(
        nint userData,
        nint buffer,
        int length)
    {
        try
        {
            var handle = GCHandle.FromIntPtr(userData);
            var stream = (Stream)handle.Target!;

            var managedBuffer = new byte[length];

            int read = stream.Read(
                managedBuffer,
                0,
                managedBuffer.Length);

            if (read > 0)
            {
                Marshal.Copy(
                    managedBuffer,
                    0,
                    buffer,
                    read);
            }

            return read;
        }
        catch
        {
            return -1;
        }
    }

    private static int WriteCallback(
        nint userData,
        nint buffer,
        int length)
    {
        try
        {
            var handle = GCHandle.FromIntPtr(userData);
            var stream = (Stream)handle.Target!;

            var managedBuffer = new byte[length];

            Marshal.Copy(
                buffer,
                managedBuffer,
                0,
                length);

            stream.Write(
                managedBuffer,
                0,
                length);

            return length;
        }
        catch
        {
            return -1;
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        _disposed = true;

        if (_connection != 0)
        {
            NativeMethods.Free(_connection);
        }

        if (_streamHandle.IsAllocated)
        {
            _streamHandle.Free();
        }

        base.Dispose(disposing);
    }
}