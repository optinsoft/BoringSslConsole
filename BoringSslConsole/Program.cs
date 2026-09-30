using System.IO.Enumeration;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

const string host = "tls.peet.ws";
//const string host = "kittens.sh";
const string document = "/api/tls";
const int port = 443;

using var client = new TcpClient();

Console.WriteLine($"Connecting to {host}:{port}...");

await client.ConnectAsync(host, port);

Console.WriteLine("TCP connected.");

await using NetworkStream networkStream = client.GetStream();

using var sslStream = new BoringSslStream(networkStream, host);

Console.WriteLine("Starting BoringSSL handshake...");

await sslStream.AuthenticateAsClientAsync();

Console.WriteLine($"TLS version: {sslStream.ProtocolVersion}");
Console.WriteLine($"Cipher:      {sslStream.CipherName}");

Console.WriteLine();

const string request =
    $"GET {document} HTTP/1.1\r\n" +
    $"Host: {host}\r\n" +
    "User-Agent: BoringSslConsole/1.0\r\n" +
    "Accept: text/html,application/xhtml+xml\r\n" +
    "Connection: close\r\n" +
    "\r\n";

var requestBytes = Encoding.ASCII.GetBytes(request);

await sslStream.WriteAsync(
    requestBytes.AsMemory(
        0, requestBytes.Length));

const string output_dir = "./output/";
if (!Directory.Exists(output_dir))
{
    Directory.CreateDirectory(output_dir);
}

const string filename = $"{output_dir}{host}.txt";

using var file = File.Create(filename);

const int bufferSize = 16 * 1024;

var buffer = new byte[bufferSize];
while (true)
{
    int read = await sslStream.ReadAsync(buffer.AsMemory(0, bufferSize));
    if (read == 0)
        break;

    file.Write(buffer, 0, read);

    Console.Write(Encoding.UTF8.GetString(buffer, 0, read));
}

Console.WriteLine($"\r\n\r\nSaved response to {filename}");
