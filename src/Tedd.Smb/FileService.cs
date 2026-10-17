using System.Security.Cryptography;
using System.Text;
using System.IO.Enumeration;

namespace Tedd.Smb;

internal sealed class OpenFile : IDisposable
{
    internal required string Path;
    internal required byte[] Id;
    internal required uint Tree, Access, Share;
    internal bool Directory, DeletePending, Pipe;
    internal string ObjectId = "";
    internal string? DeletePath;
    internal FileStream? Stream;
    internal IEnumerator<string>? Entries;
    internal string? EntryCurrent;
    internal int EntryIndex;
    internal byte[] Rpc = [];
    internal readonly RpcService Endpoint = new();
    public void Dispose() { Entries?.Dispose(); Stream?.Dispose(); }
}

internal sealed class FileService : IDisposable
{
    private readonly SmbServer server;
    private readonly Dictionary<string, OpenFile> handles = [];
    internal byte[]? RelatedId;
    private const uint ReadMask = 0x21, WriteMask = 0x6, DeleteMask = 0x10000;
    internal FileService(SmbServer server) => this.server = server;
    internal byte[] Dispatch(int cmd, byte[] r, uint tree, bool pipe)
    {
        lock (server.FileGate)
        {
            return cmd switch
            {
                5 => Create(r, tree, pipe), 6 => Close(r, tree), 7 => Flush(r, tree), 8 => Read(r, tree), 9 => Write(r, tree),
                11 => Ioctl(r, tree), 14 => QueryDirectory(r, tree), 16 => QueryInfo(r, tree), 17 => SetInfo(r, tree),
                _ => throw new SmbException(Status.NotSupported)
            };
        }
    }
    private static void Structure(byte[] r, int size, int minimum)
    { if (r.Length < minimum || Wire.U16(r, 64) != size) throw new SmbException(Status.InvalidParameter); }
    private OpenFile Find(byte[] r, int p, uint tree)
    {
        var id = Wire.Slice(r, p, 16).ToArray();
        if (id.All(x => x == 255)) id = RelatedId ?? throw new SmbException(Status.InvalidHandle);
        if (!handles.TryGetValue(Convert.ToHexString(id), out var h) || h.Tree != tree) throw new SmbException(Status.InvalidHandle);
        return h;
    }
    private uint Expand(uint access)
    {
        if ((access & 0x10c0000) != 0) throw new SmbException(Status.AccessDenied);
        if ((access & 0x80000000) != 0) access |= 0x120089;
        if ((access & 0x40000000) != 0) access |= 0x120116;
        if ((access & 0x20000000) != 0) access |= 0x1200a0;
        if ((access & 0x12000000) != 0) access |= server.Options.Writable ? 0x1301ffu : 0x1200a9;
        return access & 0x1301ff;
    }
    private static void Require(OpenFile h, uint mask) { if ((h.Access & mask) == 0) throw new SmbException(Status.AccessDenied); }
    private void Writable() { if (!server.Options.Writable) throw new SmbException(Status.AccessDenied); }
    private string Resolve(string name)
    {
        if (name.IndexOf('\0') >= 0 || name.StartsWith('\\') || name.StartsWith('/') || name.Contains(':')) throw new SmbException(Status.AccessDenied);
        var parts = name.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries); string path = server.Options.RootPath;
        foreach (string part in parts)
        {
            if (part is "." or ".." || part.EndsWith(' ') || part.EndsWith('.')) throw new SmbException(Status.AccessDenied);
            if (part.Any(c => c < 32 || "<>\"|?*".Contains(c))) throw new SmbException(Status.AccessDenied);
            string device = part.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
            if (device is "CON" or "PRN" or "AUX" or "NUL" || (device.Length == 4 && (device.StartsWith("COM", StringComparison.Ordinal) || device.StartsWith("LPT", StringComparison.Ordinal)) && "123456789¹²³".Contains(device[3]))) throw new SmbException(Status.AccessDenied);
            if (Directory.Exists(path))
            {
                var matches = Directory.EnumerateFileSystemEntries(path).Where(x => Path.GetFileName(x).Equals(part, StringComparison.OrdinalIgnoreCase)).ToArray();
                string? exact = matches.FirstOrDefault(x => Path.GetFileName(x) == part);
                if (exact != null) path = exact;
                else if (matches.Length == 1) path = matches[0];
                else if (matches.Length > 1) throw new SmbException(Status.Collision);
                else path = Path.Combine(path, part);
            }
            else path = Path.Combine(path, part);
            try { if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new SmbException(Status.AccessDenied); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
        return path;
    }
    private byte[] Create(byte[] r, uint tree, bool pipe)
    {
        Structure(r, 57, 120); if (handles.Count >= 1024) throw new SmbException(0xc000011f);
        uint access = Expand(Wire.U32(r, 88)), share = Wire.U32(r, 96), disposition = Wire.U32(r, 100), options = Wire.U32(r, 104);
        if (share > 7 || disposition > 5 || (options & 0x41) == 0x41) throw new SmbException(Status.InvalidParameter);
        int o = Wire.U16(r, 108), n = Wire.U16(r, 110);
        if (n != 0 && o < 120) throw new SmbException(Status.InvalidParameter);
        string name = n == 0 ? "" : Wire.Text(Wire.Slice(r, o, n));
        uint ctxOffset = Wire.U32(r, 112), ctxLength = Wire.U32(r, 116);
        var contextNames = new HashSet<string>();
        if (ctxLength != 0)
        {
            int start = checked((int)ctxOffset), end = checked(start + (int)ctxLength);
            if (start < 120 || (start & 7) != 0) throw new SmbException(Status.InvalidParameter);
            _ = Wire.Slice(r, start, checked((int)ctxLength));
            for (int p = start, count = 0; ; count++)
            {
                if (count == 16) throw new SmbException(Status.InvalidParameter);
                var header = Wire.Slice(r, p, 16); int next = checked((int)Wire.U32(header, 0));
                int size = next == 0 ? end - p : next;
                if (size < 16 || size > end - p || (next != 0 && (next & 7) != 0)) throw new SmbException(Status.InvalidParameter);
                var context = Wire.Slice(r, p, size); int nameAt = Wire.U16(header, 4), dataAt = Wire.U16(header, 10), dataLength = checked((int)Wire.U32(header, 12));
                if (nameAt < 16 || (dataLength != 0 && dataAt < 16)) throw new SmbException(Status.InvalidParameter);
                string contextName = Encoding.ASCII.GetString(Wire.Slice(context, nameAt, Wire.U16(header, 6)));
                _ = Wire.Slice(context, dataLength == 0 ? 0 : dataAt, dataLength);
                if (!contextNames.Add(contextName)) throw new SmbException(Status.InvalidParameter);
                if (contextName == "ExtA" && dataLength != 0) throw new SmbException(0xc000004f);
                if (contextName == "TWrp") throw new SmbException(Status.NotSupported);
                if (next == 0) break; p += next;
            }
        }
        if (pipe)
        {
            if (!name.Equals("srvsvc", StringComparison.OrdinalIgnoreCase)) throw new SmbException(Status.NotFound);
            var ph = new OpenFile { Path = name, Id = RandomNumberGenerator.GetBytes(16), Tree = tree, Access = access, Share = share, Pipe = true };
            handles.Add(Convert.ToHexString(ph.Id), ph); server.OpenFiles.Add(ph); RelatedId = ph.Id;
            var pb = new byte[88]; Wire.W16(pb, 0, 89); Wire.W32(pb, 4, 1); ph.Id.CopyTo(pb, 64); return pb;
        }
        if ((options & 0x2000) != 0) throw new SmbException(Status.NotSupported);
        if ((Wire.U32(r, 92) & ~0xb3u) != 0) throw new SmbException(Status.NotSupported);
        if (!server.Options.Writable && ((access & 0xd0116) != 0 || disposition is not (1 or 3) || (options & 0x1000) != 0)) throw new SmbException(Status.AccessDenied);
        string path = Resolve(name); bool exists = File.Exists(path) || Directory.Exists(path), isDir = Directory.Exists(path);
        string objectId = exists ? Convert.ToHexString(FileMetadata.Identity(path)) : "";
        if (server.OpenFiles.Any(x => !x.Pipe && x.ObjectId == objectId && objectId.Length != 0 && x.DeletePending)) throw new SmbException(0xc0000056);
        foreach (var h in server.OpenFiles.Where(x => !x.Pipe && x.ObjectId == objectId && objectId.Length != 0))
        {
            if (((access & ReadMask) != 0 && (h.Share & 1) == 0) || ((access & WriteMask) != 0 && (h.Share & 2) == 0) || ((access & DeleteMask) != 0 && (h.Share & 4) == 0) ||
                ((h.Access & ReadMask) != 0 && (share & 1) == 0) || ((h.Access & WriteMask) != 0 && (share & 2) == 0) || ((h.Access & DeleteMask) != 0 && (share & 4) == 0)) throw new SmbException(Status.SharingViolation);
        }
        if (exists && disposition == 2) throw new SmbException(Status.Collision);
        if (!exists && disposition is 1 or 4) throw new SmbException(Status.NotFound);
        if (exists && (options & 1) != 0 && !isDir) throw new SmbException(Status.NotDirectory);
        if (isDir && (options & 0x40) != 0) throw new SmbException(Status.FileIsDirectory);
        if (isDir && disposition is 0 or 4 or 5) throw new SmbException(Status.FileIsDirectory);
        if ((options & 0x1000) != 0) { Writable(); if ((access & DeleteMask) == 0 || path == server.Options.RootPath) throw new SmbException(Status.AccessDenied); }
        FileStream? stream = null; uint action = exists ? 1u : 2;
        if (!exists)
        {
            Writable(); if (!Directory.Exists(Path.GetDirectoryName(path))) throw new SmbException(Status.NotFound);
            if ((options & 1) != 0) { Directory.CreateDirectory(path); isDir = true; }
        }
        if (!isDir)
        {
            FileMode mode = !exists ? FileMode.CreateNew : disposition is 0 or 4 or 5 ? FileMode.Truncate : FileMode.Open;
            if (mode == FileMode.Truncate) { Writable(); if ((access & 2) == 0) throw new SmbException(Status.AccessDenied); action = disposition == 0 ? 0u : 3; }
            FileAccess io = (access & WriteMask) != 0 || mode == FileMode.CreateNew ? FileAccess.ReadWrite : FileAccess.Read;
            stream = new FileStream(path, mode, io, (FileShare)share, 65536, (options & 2) != 0 ? FileOptions.WriteThrough : FileOptions.None);
        }
        var handle = new OpenFile { Path = path, Id = RandomNumberGenerator.GetBytes(16), Tree = tree, Access = access, Share = share, Directory = isDir, Stream = stream, DeletePending = (options & 0x1000) != 0 };
        try
        {
            handle.ObjectId = Convert.ToHexString(FileMetadata.Identity(path));
            if (handle.DeletePending) { handle.DeletePath = path; if (isDir && Directory.EnumerateFileSystemEntries(path).Any()) throw new SmbException(Status.DirectoryNotEmpty); }
            if (action != 1) { uint attributes = Wire.U32(r, 92); FileMetadata.SetAttributes(path, attributes | (isDir ? 0u : 0x20), isDir); FileMetadata.Changed(path); }
            var b = new byte[88]; Wire.W16(b, 0, 89); Wire.W32(b, 4, action); OpenInfo(b, 8, handle); handle.Id.CopyTo(b, 64);
            var contexts = new List<byte[]>();
            byte[] Context(string name, byte[] data)
            {
                var context = new byte[Wire.Align(24 + data.Length)]; Wire.W16(context, 4, 16); Wire.W16(context, 6, 4); Wire.W16(context, 10, 24); Wire.W32(context, 12, (uint)data.Length); Encoding.ASCII.GetBytes(name).CopyTo(context, 16); data.CopyTo(context, 24); return context;
            }
            if (contextNames.Contains("MxAc")) { var data = new byte[8]; Wire.W32(data, 4, server.Options.Writable ? 0x1301ffu : 0x1200a9); contexts.Add(Context("MxAc", data)); }
            if (contextNames.Contains("QFid")) { var data = new byte[32]; FileMetadata.Identity(path).CopyTo(data, 0); SHA256.HashData(Encoding.UTF8.GetBytes(server.Options.RootPath)).AsSpan(0, 8).CopyTo(data.AsSpan(8)); contexts.Add(Context("QFid", data)); }
            if (contexts.Count != 0)
            {
                for (int i = 0; i < contexts.Count - 1; i++) Wire.W32(contexts[i], 0, (uint)contexts[i].Length);
                var encoded = Wire.Join(contexts.ToArray()); Wire.W32(b, 80, 152); Wire.W32(b, 84, (uint)encoded.Length); b = Wire.Join(b, encoded);
            }
            handles.Add(Convert.ToHexString(handle.Id), handle); server.OpenFiles.Add(handle); RelatedId = handle.Id; return b;
        }
        catch { stream?.Dispose(); throw; }
    }
    private static FileSystemInfo Info(OpenFile h) => h.Directory ? new DirectoryInfo(h.Path) : new FileInfo(h.Path);
    private static ulong Size(OpenFile h) => h.Directory || h.Pipe ? 0 : (ulong)(h.Stream?.Length ?? new FileInfo(h.Path).Length);
    private static ulong Allocation(OpenFile h) => (Size(h) + 4095) & ~4095ul;
    private static void Times(byte[] b, int p, OpenFile h)
    {
        FileMetadata.Times(b, p, h.Path, Info(h));
    }
    private static uint Attributes(OpenFile h) => FileMetadata.Attributes(h.Path, Info(h));
    private static void Basic(byte[] b, int p, OpenFile h) { Times(b, p, h); Wire.W32(b, p + 32, Attributes(h)); }
    private static void Standard(byte[] b, int p, OpenFile h) { Wire.W64(b, p, Allocation(h)); Wire.W64(b, p + 8, Size(h)); Wire.W32(b, p + 16, FileMetadata.LinkCount(h.Path)); b[p + 20] = h.DeletePending ? (byte)1 : (byte)0; b[p + 21] = h.Directory ? (byte)1 : (byte)0; }
    private static void OpenInfo(byte[] b, int p, OpenFile h) { Basic(b, p, h); Wire.W64(b, p + 32, Allocation(h)); Wire.W64(b, p + 40, Size(h)); Wire.W32(b, p + 48, Attributes(h)); }
    private byte[] Close(byte[] r, uint tree)
    {
        Structure(r, 24, 88); var h = Find(r, 72, tree); var b = new byte[60]; Wire.W16(b, 0, 60);
        try { if (!h.Pipe && (Wire.U16(r, 66) & 1) != 0) { Wire.W16(b, 2, 1); OpenInfo(b, 8, h); } }
        finally { Remove(h); }
        return b;
    }
    private void Remove(OpenFile h)
    {
        handles.Remove(Convert.ToHexString(h.Id)); server.OpenFiles.Remove(h); h.Dispose();
        if (h.DeletePending && !h.Pipe)
        {
            string deletePath = h.DeletePath ?? h.Path;
            var others = server.OpenFiles.Where(x => x.ObjectId == h.ObjectId && !x.Pipe).ToArray();
            if (others.Length > 0) foreach (var x in others) { x.DeletePending = true; x.DeletePath = deletePath; }
            else if (h.Directory) Directory.Delete(deletePath); else File.Delete(deletePath);
        }
    }
    private byte[] Flush(byte[] r, uint tree) { Structure(r, 24, 88); var h = Find(r, 72, tree); h.Stream?.Flush(true); return new byte[] { 4, 0, 0, 0 }; }
    private byte[] Read(byte[] r, uint tree)
    {
        Structure(r, 49, 112); var h = Find(r, 80, tree); Require(h, 1); int n = checked((int)Wire.U32(r, 68)); long offset = checked((long)Wire.U64(r, 72));
        if (n > 65536 || Wire.U32(r, 96) > n || Wire.U32(r, 100) != 0 || Wire.U16(r, 110) != 0) throw new SmbException(Status.InvalidParameter);
        byte[] data;
        if (h.Pipe) { if (h.Rpc.Length == 0) throw new SmbException(0xc00000b0); data = h.Rpc[..Math.Min(n, h.Rpc.Length)]; h.Rpc = h.Rpc[data.Length..]; }
        else
        {
            if (h.Directory || h.Stream == null) throw new SmbException(Status.FileIsDirectory);
            data = new byte[n]; h.Stream.Position = offset; int used = h.Stream.Read(data); if ((used == 0 && n > 0) || used < Wire.U32(r, 96)) throw new SmbException(Status.EndOfFile); Array.Resize(ref data, used);
        }
        var b = new byte[16]; Wire.W16(b, 0, 17); b[2] = 80; Wire.W32(b, 4, (uint)data.Length); return Wire.Join(b, data);
    }
    private byte[] Write(byte[] r, uint tree)
    {
        Structure(r, 49, 112); var h = Find(r, 80, tree); Require(h, WriteMask); int n = checked((int)Wire.U32(r, 68)), o = Wire.U16(r, 66); long offset = checked((long)Wire.U64(r, 72));
        if (n > 65536 || o < 112 || Wire.U32(r, 96) != 0 || Wire.U16(r, 106) != 0) throw new SmbException(Status.InvalidParameter); var data = Wire.Slice(r, o, n);
        if (h.Pipe)
        {
            if (h.Rpc.Length != 0) throw new SmbException(0xc00000ae);
            h.Rpc = h.Endpoint.Feed(data.ToArray(), server.Options.ShareName);
        }
        else
        {
            Writable(); if (h.Directory || h.Stream == null) throw new SmbException(Status.FileIsDirectory);
            h.Stream.Position = (h.Access & 2) != 0 ? offset : h.Stream.Length; h.Stream.Write(data); FileMetadata.Changed(h.Path, true); if ((Wire.U32(r, 108) & 1) != 0) h.Stream.Flush(true);
        }
        var b = new byte[16]; Wire.W16(b, 0, 17); Wire.W32(b, 4, (uint)n); return b;
    }
    private byte[] Ioctl(byte[] r, uint tree)
    {
        Structure(r, 57, 120); uint code = Wire.U32(r, 68);
        if (code == 0x00140204) throw new SmbException(0xc0000225); // FSCTL_VALIDATE_NEGOTIATE_INFO is obsolete for 3.1.1.
        if (code != 0x0011c017) throw new SmbException(Status.NotSupported);
        var h = Find(r, 72, tree); if (!h.Pipe) throw new SmbException(Status.InvalidHandle);
        int o = checked((int)Wire.U32(r, 88)), n = checked((int)Wire.U32(r, 92));
        if (h.Rpc.Length != 0) throw new SmbException(0xc00000ae);
        var data = h.Endpoint.Feed(Wire.Slice(r, o, n).ToArray(), server.Options.ShareName);
        if (data.Length > Wire.U32(r, 108)) throw new SmbException(Status.BufferTooSmall);
        var b = new byte[48]; Wire.W16(b, 0, 49); Wire.W32(b, 4, code); h.Id.CopyTo(b, 8); Wire.W32(b, 32, 112); Wire.W32(b, 36, (uint)data.Length); return Wire.Join(b, data);
    }
    private byte[] QueryDirectory(byte[] r, uint tree)
    {
        Structure(r, 33, 96); var h = Find(r, 72, tree); Require(h, 1); if (!h.Directory) throw new SmbException(Status.NotDirectory);
        int cls = r[66], baseSize = cls switch { 1 => 64, 2 => 68, 3 => 94, 12 => 12, 37 => 104, 38 => 80, _ => throw new SmbException(Status.InvalidInfoClass) };
        int max = checked((int)Math.Min(Wire.U32(r, 92), 65536)); int nameOffset = Wire.U16(r, 88), nameLength = Wire.U16(r, 90);
        string pattern = nameLength == 0 ? "*" : Wire.Text(Wire.Slice(r, nameOffset, nameLength));
        if (h.Entries == null || (r[67] & 0x11) != 0)
        {
            h.Entries?.Dispose();
            h.Entries = Directory.EnumerateFileSystemEntries(h.Path).Where(x => (File.GetAttributes(x) & FileAttributes.ReparsePoint) == 0)
                .Where(x => FileSystemName.MatchesWin32Expression(pattern, Path.GetFileName(x), true)).GetEnumerator(); h.EntryIndex = 0; h.EntryCurrent = null;
        }
        var entries = new List<byte[]>(); int length = 0;
        while (true)
        {
            if (h.EntryCurrent == null) { if (!h.Entries.MoveNext()) break; h.EntryCurrent = h.Entries.Current; }
            string path = h.EntryCurrent; var name = Encoding.Unicode.GetBytes(Path.GetFileName(path)); var b = new byte[Wire.Align(baseSize + name.Length)];
            if (length + b.Length > max) { if (length == 0) throw new SmbException(Status.BufferTooSmall); break; }
            Wire.W32(b, 4, (uint)h.EntryIndex);
            if (cls == 12) Wire.W32(b, 8, (uint)name.Length);
            else
            {
                var entry = new OpenFile { Path = path, Id = [], Tree = tree, Access = 0, Share = 0, Directory = Directory.Exists(path) };
                OpenInfo(b, 8, entry); Wire.W64(b, 40, Size(entry)); Wire.W64(b, 48, Allocation(entry)); Wire.W32(b, 60, (uint)name.Length);
                if (cls == 37) FileMetadata.Identity(path).CopyTo(b, 96);
                if (cls == 38) FileMetadata.Identity(path).CopyTo(b, 72);
            }
            name.CopyTo(b, baseSize); entries.Add(b); length += b.Length; h.EntryIndex++; h.EntryCurrent = null;
            if ((r[67] & 2) != 0) break;
        }
        if (entries.Count == 0) throw new SmbException(Status.NoMoreFiles);
        for (int i = 0; i < entries.Count - 1; i++) Wire.W32(entries[i], 0, (uint)entries[i].Length);
        return Output(Wire.Join(entries.ToArray()), max);
    }
    private static byte[] Output(byte[] data, int max)
    {
        if (data.Length > max) throw new SmbException(Status.BufferTooSmall);
        var b = new byte[8]; Wire.W16(b, 0, 9); Wire.W16(b, 2, 72); Wire.W32(b, 4, (uint)data.Length); return Wire.Join(b, data);
    }
    private byte[] QueryInfo(byte[] r, uint tree)
    {
        Structure(r, 41, 104); var h = Find(r, 88, tree); if (h.Pipe) throw new SmbException(Status.NotSupported);
        int inputLength = checked((int)Wire.U32(r, 76)), inputOffset = Wire.U16(r, 72);
        if (inputLength != 0) { if (inputOffset < 104) throw new SmbException(Status.InvalidParameter); _ = Wire.Slice(r, inputOffset, inputLength); }
        int cls = r[67]; byte[] b = new byte[512]; int n;
        if (r[66] == 1)
        {
            switch (cls)
            {
                case 4: Require(h, 0x80); Basic(b, 0, h); n = 40; break;
                case 5: Standard(b, 0, h); n = 24; break;
                case 6: FileMetadata.Identity(h.Path).CopyTo(b, 0); n = 8; break;
                case 7: n = 4; break;
                case 8: Wire.W32(b, 0, h.Access); n = 4; break;
                case 14: n = 8; break;
                case 16: case 17: n = 4; break;
                case 18:
                    Basic(b, 0, h); Standard(b, 40, h); FileMetadata.Identity(h.Path).CopyTo(b, 64); Wire.W32(b, 76, h.Access);
                    string relativeName = Path.GetRelativePath(server.Options.RootPath, h.Path);
                    var fullName = Encoding.Unicode.GetBytes("\\" + (relativeName == "." ? "" : relativeName.Replace('/', '\\')));
                    if (fullName.Length > b.Length - 100) Array.Resize(ref b, 100 + fullName.Length);
                    Wire.W32(b, 96, (uint)fullName.Length); fullName.CopyTo(b, 100); n = 100 + fullName.Length; break;
                case 22:
                    n = 0; if (!h.Directory) { var name = Encoding.Unicode.GetBytes("::$DATA"); Wire.W32(b, 4, (uint)name.Length); Wire.W64(b, 8, Size(h)); Wire.W64(b, 16, Allocation(h)); name.CopyTo(b, 24); n = 24 + name.Length; } break;
                case 28: Wire.W64(b, 0, Size(h)); n = 16; break;
                case 34: OpenInfo(b, 0, h); n = 56; break;
                case 35: Wire.W32(b, 0, Attributes(h)); n = 8; break;
                default: throw new SmbException(Status.InvalidInfoClass);
            }
        }
        else if (r[66] == 2)
        {
            var drive = new DriveInfo(Path.GetPathRoot(server.Options.RootPath)!);
            switch (cls)
            {
                case 1:
                    var label = Encoding.Unicode.GetBytes(server.Options.ShareName); Wire.W64(b, 0, (ulong)Directory.GetCreationTimeUtc(server.Options.RootPath).ToFileTimeUtc()); Wire.W32(b, 8, 0x534d4233); Wire.W32(b, 12, (uint)label.Length); label.CopyTo(b, 18); n = 18 + label.Length; break;
                case 3: case 7:
                    Wire.W64(b, 0, (ulong)drive.TotalSize / 4096); Wire.W64(b, 8, (ulong)drive.AvailableFreeSpace / 4096);
                    if (cls == 3) { Wire.W32(b, 16, 8); Wire.W32(b, 20, 512); n = 24; }
                    else { Wire.W64(b, 16, (ulong)drive.TotalFreeSpace / 4096); Wire.W32(b, 24, 8); Wire.W32(b, 28, 512); n = 32; } break;
                case 4: Wire.W32(b, 0, 7); Wire.W32(b, 4, 0x10); n = 8; break;
                case 5: Wire.W32(b, 0, 6 | (server.Options.Writable ? 0u : 0x80000)); Wire.W32(b, 4, 255); Wire.W32(b, 8, 8); Encoding.Unicode.GetBytes("SMB3").CopyTo(b, 12); n = 20; break;
                case 6: n = 48; break;
                case 11: Wire.W32(b, 0, 512); Wire.W32(b, 4, 4096); Wire.W32(b, 8, 4096); Wire.W32(b, 12, 4096); Wire.W32(b, 16, 3); n = 28; break;
                default: throw new SmbException(Status.InvalidInfoClass);
            }
        }
        else throw new SmbException(Status.NotSupported);
        Array.Resize(ref b, n); return Output(b, checked((int)Wire.U32(r, 68)));
    }
    private byte[] SetInfo(byte[] r, uint tree)
    {
        Structure(r, 33, 96); Writable(); var h = Find(r, 80, tree);
        if (r[66] != 1 || h.Pipe) throw new SmbException(Status.NotSupported);
        int n = checked((int)Wire.U32(r, 68)), o = Wire.U16(r, 72); if (n != 0 && o < 96) throw new SmbException(Status.InvalidParameter); var data = Wire.Slice(r, o, n);
        switch (r[67])
        {
            case 4:
                Require(h, 0x100); if (data.Length != 40) throw new SmbException(Status.InfoLengthMismatch);
                uint attr = Wire.U32(data, 32);
                if ((attr & ~0xb3u) != 0) throw new SmbException(Status.NotSupported);
                FileMetadata.SetTimes(h.Path, data);
                if (attr != 0) FileMetadata.SetAttributes(h.Path, attr, h.Directory); break;
            case 10:
                Require(h, DeleteMask); if (data.Length < 20 || Wire.U64(data, 8) != 0) throw new SmbException(Status.InvalidParameter);
                if (h.Path == server.Options.RootPath || server.OpenFiles.Any(x => x != h && ((x.Path == h.Path && (x.Share & 4) == 0) || x.Path.StartsWith(h.Path + Path.DirectorySeparatorChar, StringComparison.Ordinal)))) throw new SmbException(Status.SharingViolation);
                string destination = Resolve(Wire.Text(Wire.Slice(data, 20, checked((int)Wire.U32(data, 16)))));
                if (server.OpenFiles.Any(x => x != h && x.Path == destination)) throw new SmbException(Status.SharingViolation);
                string oldPath = h.Path;
                if (h.Directory) Directory.Move(oldPath, destination); else File.Move(oldPath, destination, data[0] != 0);
                foreach (var open in server.OpenFiles.Where(x => !x.Pipe && x.Path == oldPath)) open.Path = destination;
                FileMetadata.Changed(destination);
                break;
            case 13:
                Require(h, DeleteMask); if (data.Length != 1) throw new SmbException(Status.InfoLengthMismatch);
                if (h.Path == server.Options.RootPath) throw new SmbException(Status.AccessDenied);
                if (data[0] != 0 && h.Directory && Directory.EnumerateFileSystemEntries(h.Path).Any()) throw new SmbException(Status.DirectoryNotEmpty);
                if (server.OpenFiles.Any(x => x != h && x.Path == h.Path && (x.Share & 4) == 0)) throw new SmbException(Status.SharingViolation);
                h.DeletePending = data[0] != 0; h.DeletePath = h.DeletePending ? h.Path : null; break;
            case 19: case 20:
                Require(h, 2); if (data.Length != 8 || h.Directory || h.Stream == null) throw new SmbException(Status.InvalidParameter);
                long size = checked((long)Wire.U64(data, 0)); if (r[67] == 20 || size < h.Stream.Length) { h.Stream.SetLength(size); FileMetadata.Changed(h.Path, true); } break;
            default: throw new SmbException(Status.InvalidInfoClass);
        }
        return new byte[] { 2, 0 };
    }
    internal void CloseTree(uint tree) { lock (server.FileGate) foreach (var h in handles.Values.Where(x => x.Tree == tree).ToArray()) Remove(h); }
    public void Dispose()
    {
        lock (server.FileGate) foreach (var h in handles.Values.ToArray()) { try { Remove(h); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
    }
}
