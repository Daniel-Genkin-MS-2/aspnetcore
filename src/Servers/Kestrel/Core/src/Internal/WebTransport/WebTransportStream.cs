// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.ComponentModel;
using System.IO.Pipelines;
using System.Net.Http;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Internal;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http3;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure;

namespace Microsoft.AspNetCore.Server.Kestrel.Core.WebTransport;

/// <summary>
/// Represents a base WebTransport stream. Do not use directly as it does not
/// contain logic for handling data.
/// </summary>
[RequiresPreviewFeatures("WebTransport is a preview feature")]
internal class WebTransportStream : Stream, IHttp3Stream
{
    private volatile bool _isClosed;

    private PipeReader Input => _context.Transport.Input;
    private PipeWriter Output => _context.Transport.Output;

    internal readonly Http3StreamContext _context;
    internal readonly IStreamIdFeature _streamIdFeature = default!;
    internal readonly IStreamAbortFeature _streamAbortFeature = default!;
    internal readonly IProtocolErrorCodeFeature _errorCodeFeature = default!;
    internal readonly WebTransportStreamType _type;

    internal KestrelTrace Log => _context.ServiceContext.Log;

    long IHttp3Stream.StreamId => _streamIdFeature.StreamId;

    private WebTransportStream(Http3StreamContext context, WebTransportStreamType type)
    {
        _type = type;
        _isClosed = false;
        _context = context;
        _streamIdFeature = context.ConnectionFeatures.GetRequiredFeature<IStreamIdFeature>();
        _streamAbortFeature = context.ConnectionFeatures.GetRequiredFeature<IStreamAbortFeature>();
        _errorCodeFeature = context.ConnectionFeatures.GetRequiredFeature<IProtocolErrorCodeFeature>();

        context.StreamContext.ConnectionClosed.Register(state =>
        {
            var stream = (WebTransportStream)state!;
            stream._context.WebTransportSession.TryRemoveStream(stream._streamIdFeature.StreamId);
        }, this);
    }

    internal static async ValueTask<WebTransportStream> CreateWebTransportStream(Http3StreamContext context, WebTransportStreamType type)
    {
        var stream = new WebTransportStream(context, type);

        // skip the first 3 bytes which correspond the the strem header
        // as the application does not need to see them
        _ = await stream.ReadAsyncInternal(new Memory<byte>(new byte[3]), CancellationToken.None);

        return stream;
    }

    internal virtual void AbortCore(ConnectionAbortedException abortReason, Http3ErrorCode errorCode)
    {
        _isClosed = true;

        Log.Http3StreamAbort(_context.ConnectionId, errorCode, abortReason);

        _errorCodeFeature.Error = (long)errorCode;

        _streamAbortFeature.AbortRead((long)errorCode, abortReason);

        Input.Complete(abortReason);
    }

    void IHttp3Stream.Abort(ConnectionAbortedException abortReason, Http3ErrorCode errorCode)
    {
        AbortCore(abortReason, errorCode);
    }

    private async Task<int> ReadAsyncInternal(Memory<byte> destination, CancellationToken cancellationToken)
    {
        while (true)
        {
            var result = await Input.ReadAsync(cancellationToken);

            if (result.IsCanceled)
            {
                throw new OperationCanceledException("The read was canceled");
            }

            var buffer = result.Buffer;
            var length = buffer.Length;

            var consumed = buffer.End;
            try
            {
                if (length != 0)
                {
                    var actual = (int)Math.Min(length, destination.Length);

                    var slice = actual == length ? buffer : buffer.Slice(0, actual);
                    consumed = slice.End;
                    slice.CopyTo(destination.Span);

                    return actual;
                }

                if (result.IsCompleted)
                {
                    return 0;
                }
            }
            finally
            {
                Input.AdvanceTo(consumed);
            }
        }
    }

    /// <summary>
    /// Hard abort the stream and cancel data transmission.
    /// </summary>
    /// <param name="abortReason"></param>
    public void Abort(ConnectionAbortedException abortReason)
    {
        AbortCore(abortReason, Http3ErrorCode.InternalError);
    }

    /// <summary>
    /// True if data can be read from this stream. False otherwise.
    /// </summary>
    public override bool CanRead => _type != WebTransportStreamType.Output && !_isClosed;

    /// <summary>
    /// Seeking is not supported by WebTransport.
    /// </summary>
    public override bool CanSeek => false;

    /// <summary>
    /// True if data can be written from this stream. False otherwise.
    /// </summary>
    public override bool CanWrite => _type != WebTransportStreamType.Input && !_isClosed;

    public override void Flush()
    {
        if (!CanWrite)
        {
            throw new NotSupportedException();
        }

        FlushAsync(default).GetAwaiter().GetResult();
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        if (!CanWrite)
        {
            throw new NotSupportedException();
        }

        return Output.FlushAsync(cancellationToken).GetAsTask();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (!CanRead)
        {
            throw new NotSupportedException();
        }

        // since there is no seeking we ignore the offset and count parameters
        return ReadAsyncInternal(new(buffer), default).GetAwaiter().GetResult();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (!CanWrite)
        {
            throw new NotSupportedException();
        }

        WriteAsync(buffer, offset, count, default).GetAwaiter().GetResult();
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        if (!CanWrite)
        {
            throw new NotSupportedException();
        }

        return Output.WriteAsync(new Memory<byte>(buffer, offset, count), cancellationToken).GetAsTask();
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        if (!CanWrite)
        {
            throw new NotSupportedException();
        }

        return Output.WriteAsync(buffer, cancellationToken).GetAsValueTask();
    }

    #region Unsupported stream functionality
    /// <summary>
    /// WebTransport streams don't have a fixed length.
    /// So this field should not be used.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override long Length => throw new NotSupportedException();

    /// <summary>
    /// WebTransport streams can't seek. So this field should not be used
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <summary>
    /// Don't use. Seeking is not supported
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Don't use. Length is not defined
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }
    #endregion

    #region Unsupported IHttp3Stream functionality
    /// <summary>
    /// Not applicable to WebTransport. Don't use
    /// </summary>
    /// <exception cref="NotSupportedException"></exception>
    bool IHttp3Stream.IsReceivingHeader => throw new NotSupportedException();

    /// <summary>
    /// Not applicable to WebTransport. Don't use
    /// </summary>
    /// <exception cref="NotSupportedException"></exception>
    bool IHttp3Stream.IsDraining => throw new NotSupportedException();

    /// <summary>
    /// Not applicable to WebTransport. Don't use
    /// </summary>
    /// <exception cref="NotSupportedException"></exception>
    bool IHttp3Stream.IsRequestStream => throw new NotSupportedException();

    /// <summary>
    /// Not applicable to WebTransport. Don't use
    /// </summary>
    /// <exception cref="NotSupportedException"></exception>
    string IHttp3Stream.TraceIdentifier => throw new NotSupportedException();

    /// <summary>
    /// Not applicable to WebTransport. Don't use
    /// </summary>
    /// <exception cref="NotSupportedException"></exception>
    long IHttp3Stream.StreamTimeoutTicks
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }
    #endregion
}
