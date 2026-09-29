using System.Runtime.InteropServices;

public static class NativeMethods
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int ReadCallback(
        nint userData,
        nint buffer,
        int length);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int WriteCallback(
        nint userData,
        nint buffer,
        int length);

    [DllImport(
        "proxymap_boringssl",
        CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "pms_ssl_create")]
    public static extern nint Create(
        nint userData,
        ReadCallback readCallback,
        WriteCallback writeCallback,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string hostname);

    [DllImport(
        "proxymap_boringssl",
        CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "pms_ssl_connect")]
    public static extern int Connect(
        nint connection);

    [DllImport(
        "proxymap_boringssl",
        CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "pms_ssl_read")]
    public static extern int Read(
        nint connection,
        [Out] byte[] buffer,
        int offset,
        int length);

    [DllImport(
        "proxymap_boringssl",
        CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "pms_ssl_write")]
    public static extern int Write(
        nint connection,
        byte[] buffer,
        int offset,
        int length);

    [DllImport(
        "proxymap_boringssl",
        CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "pms_ssl_get_protocol_version")]
    public static extern nint GetProtocolVersion(
        nint connection);

    [DllImport(
        "proxymap_boringssl",
        CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "pms_ssl_get_cipher_name")]
    public static extern nint GetCipherName(
        nint connection);

    [DllImport(
        "proxymap_boringssl",
        CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "pms_ssl_get_last_error")]
    public static extern nint GetLastError();

    public static string LastError =>
        Marshal.PtrToStringAnsi(GetLastError()) ?? "unknown error";

    [DllImport(
        "proxymap_boringssl",
        CallingConvention = CallingConvention.Cdecl,
        EntryPoint = "pms_ssl_free")]
    public static extern void Free(
        nint connection);
}
