// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable enable

using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel((context, options) =>
{
    // Port configured for WebTransport
    options.Listen(IPAddress.Any, 5007, listenOptions =>
    {
        listenOptions.UseHttps(GenerateManualCertificate());
        listenOptions.UseConnectionLogging();
        listenOptions.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
    });
});
var host = builder.Build();
host.Run(async (context) =>
{
    var feature = context.Features.GetRequiredFeature<IHttpWebTransportFeature>();
    if (!feature.IsWebTransportRequest)
    {
        return;
    }

    var session = await feature.AcceptAsync(CancellationToken.None);
    ConnectionContext? stream = null;
    IStreamDirectionFeature? direction = null;
    while (true)
    {
        // wait until we get a stream
        stream = await session.AcceptStreamAsync(CancellationToken.None);
        if (stream is not null)
        {
            // check that the stream is bidirectional. If yes, keep going, otherwise
            // dispose its resources and keep waiting.
            direction = stream.Features.GetRequiredFeature<IStreamDirectionFeature>();
            if (direction.CanRead && direction.CanWrite)
            {
                break;
            }
            else
            {
                await stream.DisposeAsync();
            }
        }
        else
        {
            // if a stream is null, this means that the session failed to get the next one.
            // Thus, the session has ended or some other issue has occurred. We end the
            // connection in this case.
            return;
        }
    }
    var inputPipe = stream!.Transport.Input;
    var outputPipe = stream!.Transport.Output;

    // read some data from the stream into the memory
    var memory = new Memory<byte>(new byte[4096]);
    var length = await inputPipe.AsStream().ReadAsync(memory);

    // slice to only keep the relevant parts of the memory
    var outputMemory = memory[..length];

    // do some operations on the contents of the data
    outputMemory.Span.Reverse();

    // write back the data to the stream
    await outputPipe.WriteAsync(outputMemory);
});

await host.RunAsync();






/* JS client side
let CERTIFICATE = "dCoAeRVMaJw44nC5eIwipNq8kpFnZ6pN9j4qEvNCAFc=";

let transport = new WebTransport("https://127.0.0.1:5007", {
    serverCertificateHashes:[
      {
            algorithm: "sha-256",
            value: Uint8Array.from(atob(CERTIFICATE), c => c.charCodeAt(0))
        }]
    })

await transport.ready;
let stream = await transport.createBidirectionalStream();
let writer = stream.writable.getWriter();
let reader = stream.readable.getReader();

let messageIn = "WebTransport is awesome!";
let messageInBytes = messageIn.split("").map(x => (x).charCodeAt(0));

console.log("SENDING TO SERVER:\n" + messageIn);

await writer.write(Uint8Array.from(messageInBytes));
let {value, done} = await reader.read();

let messageOut = "";
value.forEach(x => messageOut += String.fromCharCode(x));
console.log("RECEIVED FROM SERVER:\n" + messageOut);

writer.close();
reader.cancel();
transport.close();
 */

















static X509Certificate2 GenerateManualCertificate()
{
    X509Certificate2 cert = null;
    var store = new X509Store("KestrelWebTransportCertificates", StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadWrite);
    if (store.Certificates.Count > 0)
    {
        cert = store.Certificates[^1];
        // rotate key after it expires
        if (DateTime.Parse(cert.GetExpirationDateString(), null) < DateTimeOffset.UtcNow)
        {
            cert = null;
        }
    }
    if (cert == null)
    {
        // generate a new cert
        var now = DateTimeOffset.UtcNow;
        SubjectAlternativeNameBuilder sanBuilder = new();
        sanBuilder.AddDnsName("localhost");
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest req = new("CN=localhost", ec, HashAlgorithmName.SHA256);
        // Adds purpose
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
        {
            new("1.3.6.1.5.5.7.3.1") // serverAuth
        }, false));
        // Adds usage
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        // Adds subject alternate names
        req.CertificateExtensions.Add(sanBuilder.Build());
        // Sign
        using var crt = req.CreateSelfSigned(now, now.AddDays(14)); // 14 days is the max duration of a certificate for this
        cert = new(crt.Export(X509ContentType.Pfx));
        // Save
        store.Add(cert);
    }
    store.Close();
    var hash = SHA256.HashData(cert.RawData);
    var certStr = Convert.ToBase64String(hash);
    Console.WriteLine($"\n\n\n\n\nCertificate: {certStr}\n\n\n\n"); // <-- you will need to put this output into the JS API call to allow the connection
    return cert;
}
