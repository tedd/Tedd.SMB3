using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace Tedd.SMB3;

/// <summary>In-band SMB Direct over a Linux rdma-core reliable connected queue pair.</summary>
internal sealed class LinuxRdmaQueue : IAcceptedRdmaQueue
{
    private const string Library = "Tedd.SMB3.LinuxRdma";
    private const int Depth = 8, Capacity = 65536;
    private readonly byte[] slots;
    private readonly ConnectionHandle handle;

    private LinuxRdmaQueue()
    {
        slots = GC.AllocateUninitializedArray<byte>((Depth + 2) * Capacity, pinned: true);
        var pin = GCHandle.Alloc(slots, GCHandleType.Pinned);
        try
        {
            Check(smbd_linux_create(pin.AddrOfPinnedObject(), slots.Length, out handle), default);
            handle.Pin = pin;
            pin = default;
        }
        finally { if (pin.IsAllocated) pin.Free(); }
    }

    public int ReceiveDepth => Depth;
    public Memory<byte> SendBuffer => slots.AsMemory((Depth + 1) * Capacity, Capacity);

    private sealed class ConnectionHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
    {
        internal GCHandle Pin;

        internal void Cancel()
        {
            bool lease = false;
            try
            {
                DangerousAddRef(ref lease);
                if (!IsInvalid) smbd_linux_cancel(handle);
            }
            catch (ObjectDisposedException) { }
            finally { if (lease) DangerousRelease(); }
        }

        protected override void Dispose(bool disposing)
        {
            Cancel();
            base.Dispose(disposing);
        }

        protected override bool ReleaseHandle()
        {
            smbd_linux_close(handle);
            if (Pin.IsAllocated) Pin.Free();
            return true;
        }
    }

    private sealed class ListenerHandle() : SafeHandleZeroOrMinusOneIsInvalid(true), IRdmaListener
    {
        public async Task<IAcceptedRdmaQueue> AcceptAsync(CancellationToken ct) =>
            await OpenAsync(connection => smbd_linux_accept(this, connection), ct).ConfigureAwait(false);
        protected override bool ReleaseHandle() { smbd_linux_stop(handle); return true; }
    }

    [DllImport(Library)] private static extern int smbd_linux_create(IntPtr slots, int bytes, out ConnectionHandle connection);
    [DllImport(Library)] private static extern int smbd_linux_listen(byte[] address, int bytes, int backlog, out ushort port, out ListenerHandle listener);
    [DllImport(Library)] private static extern int smbd_linux_connect(ConnectionHandle connection, byte[] address, int bytes);
    [DllImport(Library)] private static extern int smbd_linux_accept(ListenerHandle listener, ConnectionHandle connection);
    [DllImport(Library)] private static extern int smbd_linux_finish_accept(ConnectionHandle connection);
    [DllImport(Library)] private static extern int smbd_linux_send(ConnectionHandle connection, int bytes);
    [DllImport(Library)] private static extern int smbd_linux_receive(ConnectionHandle connection, out int offset, out int bytes);
    [DllImport(Library)] private static extern void smbd_linux_cancel(IntPtr connection);
    [DllImport(Library)] private static extern void smbd_linux_close(IntPtr connection);
    [DllImport(Library)] private static extern void smbd_linux_stop(IntPtr listener);

    private static byte[] Address(IPEndPoint endpoint)
    {
        var address = endpoint.Serialize();
        return address.Buffer.Span[..address.Size].ToArray();
    }

    private static void Check(int status, CancellationToken ct)
    {
        if (status == 0) return;
        ct.ThrowIfCancellationRequested();
        var error = new Win32Exception(status);
        throw new IOException($"Linux RDMA failed ({status}): {error.Message}", error);
    }

    internal static IRdmaListener Listen(IPEndPoint endpoint, int backlog, out IPEndPoint bound)
    {
        var bytes = Address(endpoint);
        Check(smbd_linux_listen(bytes, bytes.Length, backlog, out ushort port, out var listener), default);
        bound = new(endpoint.Address, port);
        return listener;
    }

    private CancellationTokenRegistration CancelOn(CancellationToken ct) =>
        ct.UnsafeRegister(static h => ((ConnectionHandle)h!).Cancel(), handle);

    private static Task<LinuxRdmaQueue> OpenAsync(Func<ConnectionHandle, int> open, CancellationToken ct) => Task.Run(() =>
    {
        var queue = new LinuxRdmaQueue();
        try
        {
            using var registration = queue.CancelOn(ct);
            Check(open(queue.handle), ct);
            ct.ThrowIfCancellationRequested();
            return queue;
        }
        catch { queue.Dispose(); throw; }
    }, ct);

    internal static async Task<IRdmaQueue> ConnectAsync(string host, int port, CancellationToken ct)
    {
        var addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        IOException? last = null;
        foreach (var ip in addresses)
        {
            var bytes = Address(new(ip, port));
            try { return await OpenAsync(h => smbd_linux_connect(h, bytes, bytes.Length), ct).ConfigureAwait(false); }
            catch (IOException error) { last = error; }
        }
        throw last ?? new IOException("No address resolved for the RDMA endpoint.");
    }

    public Task FinishAcceptAsync(CancellationToken ct) => Task.Run(() =>
    {
        using var registration = CancelOn(ct);
        Check(smbd_linux_finish_accept(handle), ct);
    }, ct);

    public ValueTask SendAsync(int length, CancellationToken ct) => new(Task.Run(() =>
    {
        using var registration = CancelOn(ct);
        Check(smbd_linux_send(handle, length), ct);
    }, ct));

    public ValueTask<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken ct) => new(Task.Run<ReadOnlyMemory<byte>>(() =>
    {
        using var registration = CancelOn(ct);
        Check(smbd_linux_receive(handle, out int offset, out int length), ct);
        return slots.AsMemory(offset, length);
    }, ct));

    public void Dispose() => handle.Dispose();
}
