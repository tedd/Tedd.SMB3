using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Tedd.SMB3;

/// <summary>Creates independent authentication exchanges for server connections.</summary>
public interface ISmbAuthenticationProvider
{
    ReadOnlyMemory<byte> NegotiateToken { get; }
    ISmbAuthenticationContext CreateContext();
}

/// <summary>An authentication exchange. A completed step transfers ownership of its session key to the server.</summary>
public interface ISmbAuthenticationContext : IDisposable
{
    SmbAuthenticationStep Accept(ReadOnlySpan<byte> token);
}

/// <summary>SessionKey is null while authentication continues. A completed SMB session key contains exactly 16 bytes.</summary>
public sealed record SmbAuthenticationStep(byte[] OutputToken, byte[]? SessionKey, string? Principal = null);

/// <summary>Kerberos authentication using the Windows service identity or a Linux MIT GSSAPI keytab.</summary>
/// <remarks>Linux requires libgssapi_krb5.so.2 and a Kerberos realm configuration. Set KRB5RCACHEDIR
/// to a private writable directory. The service principal is a full cifs/hostname@REALM principal.
/// Windows uses the process identity's inbound credentials. Authentication does not impersonate users.</remarks>
public sealed class SmbKerberosAuthentication : ISmbAuthenticationProvider
{
    private static readonly byte[] Initial = Convert.FromHexString("601B06062B0601050502A011300FA00D300B06092A864886F712010202");
    private readonly string principal;
    private readonly string? keytab;
    public ReadOnlyMemory<byte> NegotiateToken => Initial;

    public SmbKerberosAuthentication(string servicePrincipal, string? keytabPath = null)
    {
        if (string.IsNullOrWhiteSpace(servicePrincipal) || !servicePrincipal.StartsWith("cifs/", StringComparison.OrdinalIgnoreCase) ||
            !servicePrincipal.Contains('@'))
            throw new ArgumentException("Supply cifs/hostname@REALM.", nameof(servicePrincipal));
        principal = servicePrincipal;
        if (OperatingSystem.IsLinux())
        {
            if (keytabPath == null || !File.Exists(keytabPath)) throw new FileNotFoundException("Kerberos keytab is required.", keytabPath);
            if (!NativeLibrary.TryLoad("libgssapi_krb5.so.2", out var library))
                throw new PlatformNotSupportedException("MIT Kerberos GSSAPI is required.");
            NativeLibrary.Free(library);
            keytab = Path.GetFullPath(keytabPath);
        }
        else if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        else if (keytabPath != null) throw new ArgumentException("Windows uses the service account's credentials.", nameof(keytabPath));
    }

    public ISmbAuthenticationContext CreateContext() => OperatingSystem.IsWindows() ? new SspiContext() : new GssContext(principal, keytab!);

    private sealed class GssContext : ISmbAuthenticationContext
    {
        private const string Library = "libgssapi_krb5.so.2";
        private nint credential, context;
        private bool complete;
        [StructLayout(LayoutKind.Sequential)] private struct Buffer { internal nuint Length; internal nint Value; }
        [StructLayout(LayoutKind.Sequential)] private struct Oid { internal uint Length; internal nint Value; }
        [StructLayout(LayoutKind.Sequential)] private struct Store { internal uint Count; internal nint Elements; }
        [StructLayout(LayoutKind.Sequential)] private struct Pair { internal nint Key, Value; }
        [StructLayout(LayoutKind.Sequential)] private struct BufferSet { internal nuint Count; internal nint Elements; }

        internal GssContext(string principal, string keytab)
        {
            nint name = 0, pairMemory = 0;
            nint nameBytes = Marshal.StringToCoTaskMemUTF8(principal), key = Marshal.StringToCoTaskMemUTF8("keytab"), value = Marshal.StringToCoTaskMemUTF8(keytab);
            try
            {
                var buffer = new Buffer { Length = (nuint)System.Text.Encoding.UTF8.GetByteCount(principal), Value = nameBytes };
                Check(gss_import_name(out _, ref buffer, 0, out name));
                pairMemory = Marshal.AllocHGlobal(Marshal.SizeOf<Pair>());
                Marshal.StructureToPtr(new Pair { Key = key, Value = value }, pairMemory, false);
                var store = new Store { Count = 1, Elements = pairMemory };
                Check(gss_acquire_cred_from(out _, name, 0, 0, 2, ref store, out credential, 0, 0));
            }
            catch { Dispose(); throw; }
            finally
            {
                if (name != 0) gss_release_name(out _, ref name);
                Marshal.FreeCoTaskMem(nameBytes); Marshal.FreeCoTaskMem(key); Marshal.FreeCoTaskMem(value);
                if (pairMemory != 0) Marshal.FreeHGlobal(pairMemory);
            }
        }

        public SmbAuthenticationStep Accept(ReadOnlySpan<byte> token)
        {
            if (complete || credential == 0) throw new SmbException(NtStatus.LogonFailure);
            nint inputMemory = Marshal.AllocHGlobal(token.Length), name = 0;
            Buffer output = default;
            try
            {
                Marshal.Copy(token.ToArray(), 0, inputMemory, token.Length);
                var input = new Buffer { Length = (nuint)token.Length, Value = inputMemory };
                uint result = gss_accept_sec_context(out _, ref context, credential, ref input, 0, out name, out var mechanism, out output, out uint flags, out _, 0);
                Check(result);
                byte[] response = Copy(output);
                if ((result & 1) != 0) return new(response, null);
                // SPNEGO can negotiate other installed GSS mechanisms. Accept Kerberos only.
                var oid = Marshal.PtrToStructure<Oid>(mechanism);
                var bytes = new byte[oid.Length]; Marshal.Copy(oid.Value, bytes, 0, bytes.Length);
                if (!bytes.AsSpan().SequenceEqual(Convert.FromHexString("2A864886F712010202")) || (flags & 32) == 0)
                    throw new SmbException(NtStatus.LogonFailure);
                Buffer display = default;
                string? principal = null;
                try
                {
                    Check(gss_display_name(out _, name, out display, 0));
                    principal = System.Text.Encoding.UTF8.GetString(Copy(display));
                }
                finally { if (display.Value != 0) gss_release_buffer(out _, ref display); }
                byte[] sessionKey = SessionKey();
                complete = true;
                return new(response, sessionKey, principal);
            }
            finally
            {
                if (output.Value != 0) gss_release_buffer(out _, ref output);
                if (name != 0) gss_release_name(out _, ref name);
                Marshal.FreeHGlobal(inputMemory);
            }
        }

        private byte[] SessionKey()
        {
            byte[] oidBytes = Convert.FromHexString("2A864886F7120102020505");
            nint oidMemory = Marshal.AllocHGlobal(oidBytes.Length), buffers = 0;
            try
            {
                Marshal.Copy(oidBytes, 0, oidMemory, oidBytes.Length);
                var oid = new Oid { Length = (uint)oidBytes.Length, Value = oidMemory };
                Check(gss_inquire_sec_context_by_oid(out _, context, ref oid, out buffers));
                var set = Marshal.PtrToStructure<BufferSet>(buffers);
                if (set.Count < 1) throw new SmbException(NtStatus.LogonFailure);
                var first = Marshal.PtrToStructure<Buffer>(set.Elements);
                if (first.Length < 16 || first.Length > 1024) throw new SmbException(NtStatus.LogonFailure);
                // MS-SMB2 Session.SessionKey uses the first 16 bytes of the mechanism key.
                var key = new byte[16]; Marshal.Copy(first.Value, key, 0, key.Length);
                return key;
            }
            finally
            {
                if (buffers != 0) gss_release_buffer_set(out _, ref buffers);
                Marshal.FreeHGlobal(oidMemory);
            }
        }
        private static byte[] Copy(Buffer buffer)
        {
            if (buffer.Length > SmbLimits.MaxAuthenticationTokenSize) throw new SmbException(NtStatus.LogonFailure);
            var bytes = new byte[(int)buffer.Length];
            if (bytes.Length != 0) Marshal.Copy(buffer.Value, bytes, 0, bytes.Length);
            return bytes;
        }
        private static void Check(uint status)
        {
            // Supplementary duplicate/old/unsequenced-token statuses are failures too.
            if (status is not (0 or 1)) throw new SmbException(NtStatus.LogonFailure);
        }
        public void Dispose()
        {
            if (context != 0) gss_delete_sec_context(out _, ref context, 0);
            if (credential != 0) gss_release_cred(out _, ref credential);
        }
        [DllImport(Library)] private static extern uint gss_import_name(out uint minor, ref Buffer input, nint type, out nint name);
        [DllImport(Library)] private static extern uint gss_acquire_cred_from(out uint minor, nint name, uint time, nint mechanisms, int usage, ref Store store, out nint credential, nint actual, nint lifetime);
        [DllImport(Library)] private static extern uint gss_accept_sec_context(out uint minor, ref nint context, nint credential, ref Buffer input, nint bindings, out nint name, out nint mechanism, out Buffer output, out uint flags, out uint lifetime, nint delegated);
        [DllImport(Library)] private static extern uint gss_inquire_sec_context_by_oid(out uint minor, nint context, ref Oid oid, out nint buffers);
        [DllImport(Library)] private static extern uint gss_release_buffer_set(out uint minor, ref nint buffers);
        [DllImport(Library)] private static extern uint gss_release_buffer(out uint minor, ref Buffer buffer);
        [DllImport(Library)] private static extern uint gss_release_name(out uint minor, ref nint name);
        [DllImport(Library)] private static extern uint gss_release_cred(out uint minor, ref nint credential);
        [DllImport(Library)] private static extern uint gss_delete_sec_context(out uint minor, ref nint context, nint output);
        [DllImport(Library)] private static extern uint gss_display_name(out uint minor, nint name, out Buffer output, nint type);
    }

    private sealed class SspiContext : ISmbAuthenticationContext
    {
        [StructLayout(LayoutKind.Sequential)] private struct Handle { internal nint Lower, Upper; }
        [StructLayout(LayoutKind.Sequential)] private struct Buffer { internal uint Length, Type; internal nint Value; }
        [StructLayout(LayoutKind.Sequential)] private struct Descriptor { internal uint Version, Count; internal nint Buffers; }
        [StructLayout(LayoutKind.Sequential)] private struct KeyInfo { internal uint Length; internal nint Key; }
        [StructLayout(LayoutKind.Sequential)] private struct NegotiationInfo { internal nint Package; internal uint State; }
        [StructLayout(LayoutKind.Sequential)] private struct PackageInfo { internal uint Capabilities; internal ushort Version, RpcId; internal uint MaxToken; internal nint Name, Comment; }
        private Handle credential, context;
        private bool haveContext, disposed, complete;
        internal SspiContext()
        {
            if (AcquireCredentialsHandleW(null, "Negotiate", 2, 0, 0, 0, 0, out credential, out _) != 0)
                throw new SmbException(NtStatus.LogonFailure);
        }
        public SmbAuthenticationStep Accept(ReadOnlySpan<byte> token)
        {
            if (disposed || complete) throw new SmbException(NtStatus.LogonFailure);
            nint inputBytes = Marshal.AllocHGlobal(token.Length), inputBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Buffer>()),
                outputBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Buffer>()), previous = Marshal.AllocHGlobal(Marshal.SizeOf<Handle>());
            try
            {
                Marshal.Copy(token.ToArray(), 0, inputBytes, token.Length);
                Marshal.StructureToPtr(new Buffer { Length = (uint)token.Length, Type = 2, Value = inputBytes }, inputBuffer, false);
                Marshal.StructureToPtr(new Buffer { Type = 2 }, outputBuffer, false);
                Marshal.StructureToPtr(context, previous, false);
                var input = new Descriptor { Count = 1, Buffers = inputBuffer };
                var output = new Descriptor { Count = 1, Buffers = outputBuffer };
                int status = AcceptSecurityContext(ref credential, haveContext ? previous : 0, ref input,
                    0x100 | 0x20000 | 0x10 | 0x0c, 0x10, out context, ref output, out _, out _);
                haveContext = context.Lower != 0 || context.Upper != 0;
                if (status != 0 && status != 0x00090312) throw new SmbException(NtStatus.LogonFailure);
                var buffer = Marshal.PtrToStructure<Buffer>(outputBuffer);
                if (buffer.Length > SmbLimits.MaxAuthenticationTokenSize) throw new SmbException(NtStatus.LogonFailure);
                var response = new byte[buffer.Length];
                if (response.Length != 0) Marshal.Copy(buffer.Value, response, 0, response.Length);
                if (status != 0) return new(response, null);
                if (QueryNegotiation(ref context, 12, out var negotiation) != 0) throw new SmbException(NtStatus.LogonFailure);
                try
                {
                    var package = Marshal.PtrToStructure<PackageInfo>(negotiation.Package);
                    if (!string.Equals(Marshal.PtrToStringUni(package.Name), "Kerberos", StringComparison.OrdinalIgnoreCase))
                        throw new SmbException(NtStatus.LogonFailure);
                }
                finally { FreeContextBuffer(negotiation.Package); }
                if (QueryKey(ref context, 9, out var keyInfo) != 0) throw new SmbException(NtStatus.LogonFailure);
                byte[] key;
                try
                {
                    if (keyInfo.Length < 16) throw new SmbException(NtStatus.LogonFailure);
                    key = new byte[16]; Marshal.Copy(keyInfo.Key, key, 0, key.Length);
                }
                finally { FreeContextBuffer(keyInfo.Key); }
                string? principal = null;
                if (QueryName(ref context, 1, out var name) == 0)
                {
                    try { principal = Marshal.PtrToStringUni(name); }
                    finally { FreeContextBuffer(name); }
                }
                complete = true;
                return new(response, key, principal);
            }
            finally
            {
                var buffer = Marshal.PtrToStructure<Buffer>(outputBuffer);
                if (buffer.Value != 0) FreeContextBuffer(buffer.Value);
                Marshal.FreeHGlobal(inputBytes); Marshal.FreeHGlobal(inputBuffer); Marshal.FreeHGlobal(outputBuffer); Marshal.FreeHGlobal(previous);
            }
        }
        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            if (haveContext) DeleteSecurityContext(ref context);
            FreeCredentialsHandle(ref credential);
        }
        [DllImport("secur32.dll", CharSet = CharSet.Unicode)] private static extern int AcquireCredentialsHandleW(string? principal, string package, uint usage, nint logon, nint auth, nint callback, nint callbackArgument, out Handle credential, out long expiry);
        [DllImport("secur32.dll")] private static extern int AcceptSecurityContext(ref Handle credential, nint previous, ref Descriptor input, uint requirements, uint representation, out Handle context, ref Descriptor output, out uint attributes, out long expiry);
        [DllImport("secur32.dll", EntryPoint = "QueryContextAttributesW")] private static extern int QueryKey(ref Handle context, uint attribute, out KeyInfo info);
        [DllImport("secur32.dll", EntryPoint = "QueryContextAttributesW")] private static extern int QueryNegotiation(ref Handle context, uint attribute, out NegotiationInfo info);
        [DllImport("secur32.dll", EntryPoint = "QueryContextAttributesW")] private static extern int QueryName(ref Handle context, uint attribute, out nint name);
        [DllImport("secur32.dll")] private static extern int FreeContextBuffer(nint buffer);
        [DllImport("secur32.dll")] private static extern int DeleteSecurityContext(ref Handle context);
        [DllImport("secur32.dll")] private static extern int FreeCredentialsHandle(ref Handle credential);
    }
}

internal sealed class NtlmAuthentication(string userName, string password) : ISmbAuthenticationProvider
{
    public ReadOnlyMemory<byte> NegotiateToken => Spnego.Initial;
    public ISmbAuthenticationContext CreateContext() => new Context(userName, password);
    private sealed class Context(string user, string password) : ISmbAuthenticationContext
    {
        private readonly NtlmServer server = new(user, password);
        private bool challenged, raw, complete;
        public SmbAuthenticationStep Accept(ReadOnlySpan<byte> token)
        {
            if (complete) throw new SmbException(NtStatus.LogonFailure);
            if (!challenged) raw = token.StartsWith("NTLMSSP\0"u8);
            byte[] input = Spnego.Unwrap(token.ToArray());
            if (!challenged)
            {
                byte[] challenge = server.Challenge(input);
                challenged = true;
                return new(raw ? challenge : Spnego.Response(challenge, true), null);
            }
            var key = server.Authenticate(input);
            complete = true;
            return new(raw ? [] : Spnego.Response([], false), key, user);
        }
        public void Dispose() { }
    }
}
