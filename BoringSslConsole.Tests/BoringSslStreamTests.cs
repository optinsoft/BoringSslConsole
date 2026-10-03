using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Text;
using BoringSslConsole;
using Xunit;

namespace BoringSslConsole.Tests;

public sealed class BoringSslStreamTests
{
    private const string Host = "localhost";

    [Fact]
    public async Task ConcurrentReadAndWrite_ShouldWork()
    {
        using var timeout =
            new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var certificate = CreateCertificate();

        var listener = new TcpListener(
            IPAddress.Loopback,
            0);

        listener.Start();

        int port =
            ((IPEndPoint)listener.LocalEndpoint).Port;

        const int totalBytes = 64 * 1024 * 1024;

        try
        {
            Task serverTask = RunEchoServerAsync(
                listener,
                certificate,
                totalBytes,
                timeout.Token);

            using var client = new TcpClient();

            await client.ConnectAsync(
                IPAddress.Loopback,
                port,
                timeout.Token);

            await using NetworkStream networkStream =
                client.GetStream();

            using var sslStream =
                new BoringSslStream(
                    networkStream,
                    Host,
                    leaveOpen: true)
                {
                    RemoteCertificateValidationCallback = _ => true
                };

            Console.WriteLine("Authenticating...");

            await sslStream.AuthenticateAsClientAsync(
                timeout.Token);

            Console.WriteLine(
                $"Authenticated: {sslStream.ProtocolVersion}, " +
                $"{sslStream.CipherName}");

            byte[] sent = new byte[totalBytes];

            RandomNumberGenerator.Fill(sent);

            byte[] received = new byte[totalBytes];

            Console.WriteLine("Starting concurrent read/write...");

            Task writeTask = Task.Run(
                () => RequestTunnelAsync(
                    sslStream,
                    sent,
                    timeout.Token));

            Task readTask = Task.Run(
                () => ResponseTunnelAsync(
                    sslStream,
                    received,
                    timeout.Token));

            await Task.WhenAll(
                writeTask,
                readTask);

            Console.WriteLine(
                "Client read/write tasks completed.");

            await serverTask;

            Console.WriteLine(
                "Server task completed.");

            Assert.Equal(sent, received);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task DisposeWhileConcurrentReadWriteIsRunning_ShouldCompleteWithoutDeadlock()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var certificate = CreateCertificate();

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Console.WriteLine($"Listening on {port}");

        var serverTask = Task.Run(async () =>
        {
            using var tcpClient = await listener.AcceptTcpClientAsync(cts.Token);

            Console.WriteLine("SERVER: TCP connected");

            await using var networkStream = tcpClient.GetStream();

            using var sslStream = new SslStream(
                networkStream,
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);

            await sslStream.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,
                    EnabledSslProtocols = SslProtocols.Tls13
                },
                cts.Token);

            Console.WriteLine("SERVER: TLS authenticated");

            // Read one request from the client.
            var buffer = new byte[8192];

            int read = await sslStream.ReadAsync(
                buffer,
                cts.Token);

            Console.WriteLine($"SERVER: READ {read} bytes");

            // Send a small response.
            byte[] response = Encoding.ASCII.GetBytes("response");

            await sslStream.WriteAsync(
                response,
                cts.Token);

            await sslStream.FlushAsync(cts.Token);

            Console.WriteLine("SERVER: RESPONSE SENT");

            // Close the TLS connection.
            Console.WriteLine("SERVER: closing connection");
        }, cts.Token);

        using var client = new TcpClient();

        await client.ConnectAsync(
            IPAddress.Loopback,
            port,
            cts.Token);

        Console.WriteLine("CLIENT: TCP connected");

        await using var network = client.GetStream();

        await using var ssl = new BoringSslStream(
            network,
            "localhost",
            leaveOpen: true)
        {
            RemoteCertificateValidationCallback = _ => true
        };

        Console.WriteLine("CLIENT: authenticating");

        await ssl.AuthenticateAsClientAsync(
            cts.Token);

        Console.WriteLine("CLIENT: TLS authenticated");

        // Start a read which will wait for the server response.
        var readBuffer = new byte[8192];

        Task<int> readTask = ssl.ReadAsync(
            readBuffer,
            cts.Token).AsTask();

        Console.WriteLine("CLIENT: ReadAsync started");

        // Give the read operation a chance to enter BoringSSL/network wait.
        await Task.Delay(50, cts.Token);

        // Start a concurrent write.
        byte[] request = Encoding.ASCII.GetBytes("request");

        Task writeTask = ssl.WriteAsync(
            request,
            cts.Token).AsTask();

        Console.WriteLine("CLIENT: WriteAsync started");

        // Wait until the server has processed the request and closed.
        await serverTask.WaitAsync(cts.Token);

        Console.WriteLine("SERVER: task completed");

        // The read should have received the response.
        int bytesRead = await readTask.WaitAsync(cts.Token);

        Console.WriteLine($"CLIENT: ReadAsync completed: {bytesRead}");

        Assert.Equal(
            "response",
            Encoding.ASCII.GetString(readBuffer, 0, bytesRead));

        // The write must also have completed.
        await writeTask.WaitAsync(cts.Token);

        Console.WriteLine("CLIENT: WriteAsync completed");

        // This is the important part:
        // Dispose while the stream has just finished a concurrent
        // read/write lifecycle.
        Console.WriteLine("CLIENT: disposing BoringSslStream");

        await ssl.DisposeAsync();

        Console.WriteLine("CLIENT: disposed");
    }

    private static async Task RequestTunnelAsync(
        Stream stream,
        byte[] data,
        CancellationToken cancellationToken)
    {
        const int chunkSize = 8192;

        int offset = 0;

        int chunkNum = 0;

        while (offset < data.Length)
        {
            int count = Math.Min(
                chunkSize,
                data.Length - offset);

            chunkNum += 1;

            Console.WriteLine(
                $"CLIENT WRITING: {count}, chunk={chunkNum}...");

            await stream.WriteAsync(
                data.AsMemory(offset, count),
                cancellationToken);

            offset += count;

            Console.WriteLine(
                $"CLIENT WROTE: {count}, total={offset}");            
        }

        Console.WriteLine("CLIENT WRITE DONE");
    }

    private static async Task ResponseTunnelAsync(
        Stream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        int offset = 0;

        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(
                buffer.AsMemory(offset),
                cancellationToken);

            if (read == 0)
                throw new EndOfStreamException();

            offset += read;

            Console.WriteLine(
                $"CLIENT READ: {read}, total={offset}");
        }

        Console.WriteLine("CLIENT READ DONE");
    }

    private static async Task RunEchoServerAsync(
        TcpListener listener,
        X509Certificate2 certificate,
        int expectedBytes,
        CancellationToken cancellationToken)
    {
        Console.WriteLine("Server waiting for connection...");

        using TcpClient client =
            await listener.AcceptTcpClientAsync(
                cancellationToken);

        Console.WriteLine("Server TCP connected.");

        await using NetworkStream networkStream =
            client.GetStream();

        await using var sslStream =
            new SslStream(
                networkStream,
                leaveInnerStreamOpen: true);

        await sslStream.AuthenticateAsServerAsync(
            new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate
            },
            cancellationToken);

        Console.WriteLine("Server TLS authenticated.");

        byte[] buffer = new byte[16 * 1024];

        int totalRead = 0;
        int totalWritten = 0;

        while (totalRead < expectedBytes)
        {
            int read = await sslStream.ReadAsync(
                buffer.AsMemory(
                    0,
                    Math.Min(
                        buffer.Length,
                        expectedBytes - totalRead)),
                cancellationToken);

            if (read == 0)
                throw new EndOfStreamException();

            totalRead += read;

            Console.WriteLine(
                $"SERVER READ: {read}, total={totalRead}");

            await sslStream.WriteAsync(
                buffer.AsMemory(0, read),
                cancellationToken);

            totalWritten += read;

            Console.WriteLine(
                $"SERVER WROTE: {read}, total={totalWritten}");
        }

        await sslStream.FlushAsync(cancellationToken);

        Console.WriteLine("SERVER DONE");
    }
 
    private static X509Certificate2 CreateCertificate()
    {
        using RSA rsa = RSA.Create(2048);

        var request = new CertificateRequest(
            "CN=localhost",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature |
                X509KeyUsageFlags.KeyEncipherment,
                critical: true));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new("1.3.6.1.5.5.7.3.1")
                },
                critical: true));

        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(Host);

        request.CertificateExtensions.Add(
            san.Build());

        using X509Certificate2 certificate =
            request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddHours(1));

        return X509CertificateLoader.LoadPkcs12(
            certificate.Export(X509ContentType.Pfx),
            password: null);
    }
}