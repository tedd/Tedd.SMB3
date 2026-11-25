using Microsoft.Win32.SafeHandles;
using System.Net;
using System.Runtime.InteropServices;

namespace Tedd.SMB3;

/// <summary>Reliable connected RDMA SEND/RECEIVE using Windows Network Direct v2.</summary>
internal sealed class WindowsRdmaQueue(WindowsRdmaQueue.ConnectionHandle handle, byte[] slots) : IAcceptedRdmaQueue
{
    // Matches the registered slots preposted by the native provider.
    private const int Capacity = 65536, Depth = 8;
    public int ReceiveDepth => Depth;
    public Memory<byte> SendBuffer => slots.AsMemory((Depth + 1) * Capacity, Capacity);
    private const string Library = "Tedd.SMB3.NetworkDirect";

    internal sealed class ConnectionHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
    {
        internal GCHandle Pin;
        protected override bool ReleaseHandle()
        {
            smbd_close(handle);
            if (Pin.IsAllocated) Pin.Free();
            return true;
        }
    }

    internal sealed class ListenerHandle() : SafeHandleZeroOrMinusOneIsInvalid(true), IRdmaListener
    {
        public async Task<IAcceptedRdmaQueue> AcceptAsync(CancellationToken ct) =>
            await WindowsRdmaQueue.AcceptAsync(this, ct).ConfigureAwait(false);
        protected override bool ReleaseHandle() { smbd_stop(handle); return true; }
    }

    [DllImport(Library, ExactSpelling = true)]
    private static extern int smbd_connect(byte[] address, int size, IntPtr slots, int bytes, SafeWaitHandle cancel, out ConnectionHandle connection);
    [DllImport(Library, ExactSpelling = true)]
    private static extern int smbd_listen(byte[] address, int size, int backlog, out ushort port, out ListenerHandle listener);
    [DllImport(Library, ExactSpelling = true)]
    private static extern int smbd_accept(ListenerHandle listener, IntPtr slots, int bytes, SafeWaitHandle cancel, out ConnectionHandle connection);
    [DllImport(Library, ExactSpelling = true)]
    private static extern int smbd_finish_accept(ConnectionHandle connection, SafeWaitHandle cancel);
    [DllImport(Library, ExactSpelling = true)]
    private static extern int smbd_send(ConnectionHandle connection, int length, SafeWaitHandle cancel);
    [DllImport(Library, ExactSpelling = true)]
    private static extern int smbd_receive(ConnectionHandle connection, SafeWaitHandle cancel, out int offset, out int length);
    [DllImport(Library, ExactSpelling = true)]
    private static extern void smbd_close(IntPtr connection);
    [DllImport(Library, ExactSpelling = true)]
    private static extern void smbd_stop(IntPtr listener);

    private static byte[] Address(IPEndPoint ep)
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
            throw new PlatformNotSupportedException("The Network Direct provider requires Windows x64.");
        var address = ep.Serialize();
        return address.Buffer.Span[..address.Size].ToArray();
    }

    private static void Check(int status, CancellationToken ct)
    {
        if (status >= 0) return;
        ct.ThrowIfCancellationRequested();
        throw new IOException($"Network Direct failed with status 0x{status:X8}.");
    }

    internal static ListenerHandle Listen(IPEndPoint endpoint, int backlog, out IPEndPoint bound)
    {
        var bytes = Address(endpoint);
        Check(smbd_listen(bytes, bytes.Length, backlog, out ushort port, out var listener), default);
        bound = new(endpoint.Address, port);
        return listener;
    }

    private delegate int Open(IntPtr buffers, int bytes, SafeWaitHandle cancel, out ConnectionHandle connection);

    private static Task<WindowsRdmaQueue> OpenAsync(Open open, CancellationToken ct) => Task.Run(() =>
    {
        var buffers = GC.AllocateArray<byte>((Depth + 2) * Capacity, pinned: true);
        var pin = GCHandle.Alloc(buffers, GCHandleType.Pinned);
        try
        {
            Check(open(pin.AddrOfPinnedObject(), buffers.Length, ct.WaitHandle.SafeWaitHandle, out var connection), ct);
            connection.Pin = pin;
            pin = default;
            return new WindowsRdmaQueue(connection, buffers);
        }
        finally { if (pin.IsAllocated) pin.Free(); }
    }, ct);

    internal static Task<WindowsRdmaQueue> AcceptAsync(ListenerHandle listener, CancellationToken ct) =>
        OpenAsync((IntPtr p, int n, SafeWaitHandle cancel, out ConnectionHandle c) => smbd_accept(listener, p, n, cancel, out c), ct);

    public Task FinishAcceptAsync(CancellationToken ct) => Task.Run(() => Check(smbd_finish_accept(handle, ct.WaitHandle.SafeWaitHandle), ct), ct);

    internal static async Task<IRdmaQueue> ConnectAsync(string host, int port, CancellationToken ct)
    {
        var addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        IOException? last = null;
        foreach (var ip in addresses)
        {
            var bytes = Address(new(ip, port));
            try
            {
                return await OpenAsync((IntPtr p, int n, SafeWaitHandle cancel, out ConnectionHandle c) =>
                    smbd_connect(bytes, bytes.Length, p, n, cancel, out c), ct).ConfigureAwait(false);
            }
            catch (IOException error) { last = error; }
        }
        throw last ?? new IOException("No address resolved for the RDMA endpoint.");
    }

    public ValueTask SendAsync(int length, CancellationToken ct) => new(Task.Run(() =>
        Check(smbd_send(handle, length, ct.WaitHandle.SafeWaitHandle), ct), ct));

    public ValueTask<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken ct) => new(Task.Run<ReadOnlyMemory<byte>>(() =>
    {
        Check(smbd_receive(handle, ct.WaitHandle.SafeWaitHandle, out int offset, out int received), ct);
        return slots.AsMemory(offset, received);
    }, ct));

    public void Dispose() => handle.Dispose();
}
