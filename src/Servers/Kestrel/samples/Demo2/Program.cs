// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable enable

using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

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
    // open a new stream from the server to the client
    var stream = await session.OpenUnidirectionalStreamAsync(CancellationToken.None);

    if (stream is null)
    {
        // in this case the session ended so we can just stop here
        return;
    }

    // write data to the stream
    var outputPipe = stream.Transport.Output;
    await outputPipe.WriteAsync(new Memory<byte>(new byte[] { 65, 66, 67, 68, 69 }), CancellationToken.None);
    await outputPipe.FlushAsync(CancellationToken.None);
});

await host.RunAsync();






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
