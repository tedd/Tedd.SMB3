using System.Net;

namespace Tedd.SMB3;

internal interface IRdmaListener : IDisposable
{
    Task<IAcceptedRdmaQueue> AcceptAsync(CancellationToken ct);
}

internal interface IAcceptedRdmaQueue : IRdmaQueue
{
    Task FinishAcceptAsync(CancellationToken ct);
}

internal static class RdmaProvider
{
    internal static Task<IRdmaQueue> ConnectAsync(string host, int port, CancellationToken ct) =>
        OperatingSystem.IsLinux()
            ? LinuxRdmaQueue.ConnectAsync(host, port, ct)
            : WindowsRdmaQueue.ConnectAsync(host, port, ct);

    internal static IRdmaListener Listen(IPEndPoint endpoint, int backlog, out IPEndPoint bound) =>
        OperatingSystem.IsLinux()
            ? LinuxRdmaQueue.Listen(endpoint, backlog, out bound)
            : WindowsRdmaQueue.Listen(endpoint, backlog, out bound);
}
