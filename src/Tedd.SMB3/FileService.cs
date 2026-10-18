using System.Security.Cryptography;
using System.Text;
using System.IO.Enumeration;

namespace Tedd.SMB3;

/// <summary>Connection-owned file or pipe handle and its enumeration/delete state.</summary>
internal sealed class OpenFile : IDisposable
{
    internal required string Path;
    internal required byte[] Id;
    internal required uint Tree;
    internal required uint Access;
    internal required uint Share;
    internal bool Directory;
    internal bool DeletePending;
    internal bool Pipe;
    internal string ObjectId = "";
    internal string? DeletePath;
    internal FileStream? Stream;
    internal IEnumerator<string>? Entries;
    internal string? EntryCurrent;
    internal int EntryIndex;
    internal byte[] Rpc = [];
    internal readonly RpcService Endpoint = new();
    public void Dispose()
    {
        Entries?.Dispose();
        Stream?.Dispose();
    }
}

/// <summary>Translates validated SMB commands into filesystem and srvsvc operations.</summary>
/// <remarks>The server's async file gate protects cross-connection sharing invariants.</remarks>
internal sealed class FileService : IAsyncDisposable
{
    private readonly SmbServer server;
    private readonly Dictionary<FileHandleId, OpenFile> handles = [];
    internal byte[]? RelatedId;
    private const uint ReadMask = SmbLimits.ReadSharingAccess;
    private const uint WriteMask = SmbLimits.WriteSharingAccess;
    private const uint DeleteMask = FileAccessMask.Delete;
    internal FileService(SmbServer server) => this.server = server;
    internal async ValueTask<byte[]> DispatchAsync(int cmd, ReadOnlyMemory<byte> request, uint tree, bool pipe, CancellationToken cancellationToken)
    {
        await server.FileGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return cmd switch
            {
                Smb3Command.Create => Create(request.Span, tree, pipe),
                Smb3Command.Close => Close(request.Span, tree),
                Smb3Command.Flush => Flush(request.Span, tree),
                Smb3Command.Read => await ReadAsync(request, tree, cancellationToken).ConfigureAwait(false),
                Smb3Command.Write => await WriteAsync(request, tree, cancellationToken).ConfigureAwait(false),
                Smb3Command.Ioctl => Ioctl(request.Span, tree),
                Smb3Command.QueryDirectory => QueryDirectory(request.Span, tree),
                Smb3Command.QueryInfo => QueryInfo(request.Span, tree),
                Smb3Command.SetInfo => SetInfo(request.Span, tree),
                _ => throw new SmbException(NtStatus.NotSupported)
            };
        }
        finally
        {
            server.FileGate.Release();
        }
    }

    private static void ValidateStructure(ReadOnlySpan<byte> r, int size, int minimum)
    {
        if (r.Length < minimum || Wire.ReadUInt16LittleEndian(r, Smb3Header.Size) != size)
            throw new SmbException(NtStatus.InvalidParameter);
    }

    private OpenFile FindHandle(ReadOnlySpan<byte> r, int p, uint tree)
    {
        // All-one file IDs inherit the preceding CREATE only in related compounds.
        var id = Wire.Slice(r, p, Smb3FileId.Size);
        if (id.IndexOfAnyExcept(Smb3FileId.RelatedOperationByte) < 0)
            id = RelatedId ?? throw new SmbException(NtStatus.InvalidHandle);
        if (!handles.TryGetValue(FileHandleId.Read(id), out var h) || h.Tree != tree)
            throw new SmbException(NtStatus.InvalidHandle);
        return h;
    }

    private uint ExpandAccess(uint access)
    {
        if ((access & SmbLimits.UnsupportedSecurityAccess) != 0)
            throw new SmbException(NtStatus.AccessDenied);
        if ((access & FileAccessMask.GenericRead) != 0)
            access |= FileAccessMask.FileGenericRead;
        if ((access & FileAccessMask.GenericWrite) != 0)
            access |= FileAccessMask.FileGenericWrite;
        if ((access & FileAccessMask.GenericExecute) != 0)
            access |= FileAccessMask.FileGenericExecute;
        if ((access & (FileAccessMask.GenericAll | FileAccessMask.MaximumAllowed)) != 0)
            access |= server.Options.Writable ? SmbLimits.SupportedFileAccess : SmbLimits.ReadAccess;
        return access & SmbLimits.SupportedFileAccess;
    }

    private static void RequireAccess(OpenFile h, uint mask)
    {
        if ((h.Access & mask) == 0)
            throw new SmbException(NtStatus.AccessDenied);
    }

    private void EnsureWritable()
    {
        if (!server.Options.Writable)
            throw new SmbException(NtStatus.AccessDenied);
    }

    private string ResolvePath(string name)
    {
        // Resolve components case-insensitively and reject traversal, devices and links.
        // The export must not be concurrently modified by untrusted local processes.
        if (name.IndexOf('\0') >= 0 || name.StartsWith('\\') || name.StartsWith('/') || name.Contains(':'))
            throw new SmbException(NtStatus.AccessDenied);
        var parts = name.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        string path = server.Options.RootPath;
        foreach (string part in parts)
        {
            if (part is "." or ".." || part.EndsWith(' ') || part.EndsWith('.'))
                throw new SmbException(NtStatus.AccessDenied);
            if (part.Any(c => c < 32 || "<>\"|?*".Contains(c)))
                throw new SmbException(NtStatus.AccessDenied);
            if (IsReservedDevice(part))
                throw new SmbException(NtStatus.AccessDenied);
            if (Directory.Exists(path))
            {
                // An exact spelling wins; otherwise a case-insensitive match must be unique.
                string? exact = null, match = null;
                int matches = 0;
                foreach (string entry in Directory.EnumerateFileSystemEntries(path))
                {
                    var entryName = Path.GetFileName(entry.AsSpan());
                    if (!entryName.Equals(part, StringComparison.OrdinalIgnoreCase))
                        continue;
                    matches++;
                    match = entry;
                    if (entryName.SequenceEqual(part))
                    {
                        exact = entry;
                        break;
                    }
                }

                if (exact != null)
                    path = exact;
                else if (matches == 1)
                    path = match!;
                else if (matches > 1)
                    throw new SmbException(NtStatus.ObjectNameCollision);
                else
                    path = Path.Combine(path, part);
            }
            else
                path = Path.Combine(path, part);
            try
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new SmbException(NtStatus.AccessDenied);
            }
            catch (FileNotFoundException)
            {
            }
            catch (DirectoryNotFoundException)
            {
            }
        }

        return path;
    }

    private static bool IsReservedDevice(ReadOnlySpan<char> component)
    {
        int extension = component.IndexOf('.');
        var basename = (extension < 0 ? component : component[..extension]).TrimEnd(' ');
        if (basename.Equals("CON", StringComparison.OrdinalIgnoreCase) || basename.Equals("PRN", StringComparison.OrdinalIgnoreCase) || basename.Equals("AUX", StringComparison.OrdinalIgnoreCase) || basename.Equals("NUL", StringComparison.OrdinalIgnoreCase))
            return true;
        // Windows also reserves the superscript digits one, two and three for devices.
        return basename.Length == 4 && (basename.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || basename.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) && "123456789\u00b9\u00b2\u00b3".Contains(basename[3]);
    }

    private byte[] Create(ReadOnlySpan<byte> r, uint tree, bool pipe)
    {
        ValidateStructure(r, Smb3CreateRequest.StructureSize, Smb3Header.Size + Smb3CreateRequest.FixedSize);
        if (handles.Count >= SmbLimits.MaxHandles)
            throw new SmbException(NtStatus.TooManyOpenedFiles);
        uint access = ExpandAccess(Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3CreateRequest.DesiredAccessOffset)), share = Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3CreateRequest.ShareAccessOffset), disposition = Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3CreateRequest.CreateDispositionOffset), options = Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3CreateRequest.CreateOptionsOffset);
        if (share > FileShareAccess.All || disposition > Smb3CreateDisposition.OverwriteIf || (options & Smb3CreateOptions.ConflictingDirectoryOptions) == Smb3CreateOptions.ConflictingDirectoryOptions)
            throw new SmbException(NtStatus.InvalidParameter);
        int o = Wire.ReadUInt16LittleEndian(r, Smb3Header.Size + Smb3CreateRequest.NameOffsetFieldOffset), n = Wire.ReadUInt16LittleEndian(r, Smb3Header.Size + Smb3CreateRequest.NameLengthOffset);
        if (n != 0 && o < Smb3Header.Size + Smb3CreateRequest.FixedSize)
            throw new SmbException(NtStatus.InvalidParameter);
        string name = n == 0 ? "" : Wire.Text(Wire.Slice(r, o, n));
        uint ctxOffset = Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3CreateRequest.CreateContextsOffsetFieldOffset), ctxLength = Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3CreateRequest.CreateContextsLengthOffset);
        var contextNames = new HashSet<string>();
        if (ctxLength != 0)
        {
            int start = checked((int)ctxOffset), end = checked(start + (int)ctxLength);
            if (start < Smb3Header.Size + Smb3CreateRequest.FixedSize || (start & 7) != 0)
                throw new SmbException(NtStatus.InvalidParameter);
            _ = Wire.Slice(r, start, checked((int)ctxLength));
            for (int p = start, count = 0; ; count++)
            {
                if (count == SmbLimits.MaxCreateContexts)
                    throw new SmbException(NtStatus.InvalidParameter);
                var header = Wire.Slice(r, p, Smb3CreateContext.HeaderSize);
                int next = checked((int)Wire.ReadUInt32LittleEndian(header, Smb3CreateContext.NextOffset));
                int size = next == 0 ? end - p : next;
                if (size < Smb3CreateContext.HeaderSize || size > end - p || (next != 0 && (next & 7) != 0))
                    throw new SmbException(NtStatus.InvalidParameter);
                var context = Wire.Slice(r, p, size);
                int nameAt = Wire.ReadUInt16LittleEndian(header, Smb3CreateContext.NameOffsetFieldOffset), dataAt = Wire.ReadUInt16LittleEndian(header, Smb3CreateContext.DataOffsetFieldOffset), dataLength = checked((int)Wire.ReadUInt32LittleEndian(header, Smb3CreateContext.DataLengthOffset));
                if (nameAt < Smb3CreateContext.HeaderSize || (dataLength != 0 && dataAt < Smb3CreateContext.HeaderSize))
                    throw new SmbException(NtStatus.InvalidParameter);
                string contextName = Encoding.ASCII.GetString(Wire.Slice(context, nameAt, Wire.ReadUInt16LittleEndian(header, Smb3CreateContext.NameLengthOffset)));
                _ = Wire.Slice(context, dataLength == 0 ? 0 : dataAt, dataLength);
                if (!contextNames.Add(contextName))
                    throw new SmbException(NtStatus.InvalidParameter);
                if (contextName == Smb3CreateContextName.EaBuffer && dataLength != 0)
                    throw new SmbException(NtStatus.EasNotSupported);
                if (contextName == Smb3CreateContextName.TimewarpToken)
                    throw new SmbException(NtStatus.NotSupported);
                if (next == 0)
                    break;
                p += next;
            }
        }

        if (pipe)
        {
            if (!name.Equals("srvsvc", StringComparison.OrdinalIgnoreCase))
                throw new SmbException(NtStatus.ObjectNameNotFound);
            var ph = new OpenFile
            {
                Path = name,
                Id = RandomNumberGenerator.GetBytes(Smb3FileId.Size),
                Tree = tree,
                Access = access,
                Share = share,
                Pipe = true
            };
            handles.Add(FileHandleId.Read(ph.Id), ph);
            server.OpenFiles.Add(ph);
            RelatedId = ph.Id;
            var pb = new byte[Smb3CreateResponse.FixedSize];
            Wire.WriteUInt16LittleEndian(pb, 0, Smb3CreateResponse.StructureSize);
            Wire.WriteUInt32LittleEndian(pb, Smb3CreateResponse.CreateActionOffset, Smb3CreateAction.Opened);
            ph.Id.CopyTo(pb, Smb3CreateResponse.FileIdOffset);
            return pb;
        }

        if ((options & Smb3CreateOptions.OpenByFileId) != 0)
            throw new SmbException(NtStatus.NotSupported);
        if ((Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3CreateRequest.FileAttributesOffset) & ~SmbLimits.SupportedFileAttributes) != 0)
            throw new SmbException(NtStatus.NotSupported);
        if (!server.Options.Writable && ((access & SmbLimits.MutatingAccess) != 0 || disposition is not (Smb3CreateDisposition.Open or Smb3CreateDisposition.OpenIf) || (options & Smb3CreateOptions.DeleteOnClose) != 0))
            throw new SmbException(NtStatus.AccessDenied);
        string path = ResolvePath(name);
        bool exists = File.Exists(path) || Directory.Exists(path), isDir = Directory.Exists(path);
        string objectId = exists ? Convert.ToHexString(FileMetadata.Identity(path)) : "";
        if (server.OpenFiles.Any(x => !x.Pipe && x.ObjectId == objectId && objectId.Length != 0 && x.DeletePending))
            throw new SmbException(NtStatus.DeletePending);
        foreach (var h in server.OpenFiles.Where(x => !x.Pipe && x.ObjectId == objectId && objectId.Length != 0))
        {
            if (((access & ReadMask) != 0 && (h.Share & FileShareAccess.Read) == 0) || ((access & WriteMask) != 0 && (h.Share & FileShareAccess.Write) == 0) || ((access & DeleteMask) != 0 && (h.Share & FileShareAccess.Delete) == 0) || ((h.Access & ReadMask) != 0 && (share & FileShareAccess.Read) == 0) || ((h.Access & WriteMask) != 0 && (share & FileShareAccess.Write) == 0) || ((h.Access & DeleteMask) != 0 && (share & FileShareAccess.Delete) == 0))
                throw new SmbException(NtStatus.SharingViolation);
        }

        if (exists && disposition == Smb3CreateDisposition.Create)
            throw new SmbException(NtStatus.ObjectNameCollision);
        if (!exists && disposition is Smb3CreateDisposition.Open or Smb3CreateDisposition.Overwrite)
            throw new SmbException(NtStatus.ObjectNameNotFound);
        if (exists && (options & Smb3CreateOptions.DirectoryFile) != 0 && !isDir)
            throw new SmbException(NtStatus.NotADirectory);
        if (isDir && (options & Smb3CreateOptions.NonDirectoryFile) != 0)
            throw new SmbException(NtStatus.FileIsADirectory);
        if (isDir && disposition is Smb3CreateDisposition.Supersede or Smb3CreateDisposition.Overwrite or Smb3CreateDisposition.OverwriteIf)
            throw new SmbException(NtStatus.FileIsADirectory);
        if ((options & Smb3CreateOptions.DeleteOnClose) != 0)
        {
            EnsureWritable();
            if ((access & DeleteMask) == 0 || path == server.Options.RootPath)
                throw new SmbException(NtStatus.AccessDenied);
        }

        FileStream? stream = null;
        uint action = exists ? Smb3CreateAction.Opened : Smb3CreateAction.Created;
        if (!exists)
        {
            EnsureWritable();
            if (!Directory.Exists(Path.GetDirectoryName(path)))
                throw new SmbException(NtStatus.ObjectNameNotFound);
            if ((options & Smb3CreateOptions.DirectoryFile) != 0)
            {
                Directory.CreateDirectory(path);
                isDir = true;
            }
        }

        if (!isDir)
        {
            FileMode mode = !exists ? FileMode.CreateNew : disposition is Smb3CreateDisposition.Supersede or Smb3CreateDisposition.Overwrite or Smb3CreateDisposition.OverwriteIf ? FileMode.Truncate : FileMode.Open;
            if (mode == FileMode.Truncate)
            {
                EnsureWritable();
                if ((access & FileAccessMask.WriteData) == 0)
                    throw new SmbException(NtStatus.AccessDenied);
                action = disposition == Smb3CreateDisposition.Supersede ? Smb3CreateAction.Superseded : Smb3CreateAction.Overwritten;
            }

            FileAccess io = (access & WriteMask) != 0 || mode == FileMode.CreateNew ? FileAccess.ReadWrite : FileAccess.Read;
            stream = new FileStream(path, mode, io, (FileShare)share, 1, FileOptions.Asynchronous | ((options & Smb3CreateOptions.WriteThrough) != 0 ? FileOptions.WriteThrough : FileOptions.None));
        }

        var handle = new OpenFile
        {
            Path = path,
            Id = RandomNumberGenerator.GetBytes(Smb3FileId.Size),
            Tree = tree,
            Access = access,
            Share = share,
            Directory = isDir,
            Stream = stream,
            DeletePending = (options & Smb3CreateOptions.DeleteOnClose) != 0
        };
        try
        {
            handle.ObjectId = Convert.ToHexString(FileMetadata.Identity(path));
            if (handle.DeletePending)
            {
                handle.DeletePath = path;
                if (isDir && Directory.EnumerateFileSystemEntries(path).Any())
                    throw new SmbException(NtStatus.DirectoryNotEmpty);
            }

            if (action != Smb3CreateAction.Opened)
            {
                uint attributes = Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3CreateRequest.FileAttributesOffset);
                FileMetadata.SetAttributes(path, attributes | (isDir ? 0u : FileAttributeFlags.Archive), isDir);
                FileMetadata.Changed(path);
            }

            var b = new byte[Smb3CreateResponse.FixedSize];
            Wire.WriteUInt16LittleEndian(b, 0, Smb3CreateResponse.StructureSize);
            Wire.WriteUInt32LittleEndian(b, Smb3CreateResponse.CreateActionOffset, action);
            WriteOpenInfo(b, Smb3CreateResponse.CreationTimeOffset, handle);
            handle.Id.CopyTo(b, Smb3CreateResponse.FileIdOffset);
            var contexts = new List<byte[]>();
            byte[] Context(string name, byte[] data)
            {
                var context = new byte[Wire.Align(Smb3CreateContext.ResponseDataOffset + data.Length)];
                Wire.WriteUInt16LittleEndian(context, Smb3CreateContext.NameOffsetFieldOffset, Smb3CreateContext.ResponseNameOffset);
                Wire.WriteUInt16LittleEndian(context, Smb3CreateContext.NameLengthOffset, Smb3CreateContext.TagSize);
                Wire.WriteUInt16LittleEndian(context, Smb3CreateContext.DataOffsetFieldOffset, Smb3CreateContext.ResponseDataOffset);
                Wire.WriteUInt32LittleEndian(context, Smb3CreateContext.DataLengthOffset, (uint)data.Length);
                Encoding.ASCII.GetBytes(name).CopyTo(context, Smb3CreateContext.ResponseNameOffset);
                data.CopyTo(context, Smb3CreateContext.ResponseDataOffset);
                return context;
            }

            if (contextNames.Contains(Smb3CreateContextName.QueryMaximalAccess))
            {
                var data = new byte[Smb3QueryMaximalAccessResponse.Size];
                Wire.WriteUInt32LittleEndian(data, Smb3QueryMaximalAccessResponse.MaximalAccessOffset, server.Options.Writable ? SmbLimits.SupportedFileAccess : SmbLimits.ReadAccess);
                contexts.Add(Context(Smb3CreateContextName.QueryMaximalAccess, data));
            }

            if (contextNames.Contains(Smb3CreateContextName.QueryOnDiskId))
            {
                var data = new byte[Smb3QueryOnDiskIdResponse.Size];
                FileMetadata.Identity(path).CopyTo(data, Smb3QueryOnDiskIdResponse.DiskFileIdOffset);
                SHA256.HashData(Encoding.UTF8.GetBytes(server.Options.RootPath)).AsSpan(0, Smb3QueryOnDiskIdResponse.IdentifierSize).CopyTo(data.AsSpan(Smb3QueryOnDiskIdResponse.VolumeIdOffset));
                contexts.Add(Context(Smb3CreateContextName.QueryOnDiskId, data));
            }

            if (contexts.Count != 0)
            {
                for (int i = 0; i < contexts.Count - 1; i++)
                    Wire.WriteUInt32LittleEndian(contexts[i], Smb3CreateContext.NextOffset, (uint)contexts[i].Length);
                var encoded = Wire.Join(contexts.ToArray());
                Wire.WriteUInt32LittleEndian(b, Smb3CreateResponse.CreateContextsOffsetFieldOffset, Smb3Header.Size + Smb3CreateResponse.FixedSize);
                Wire.WriteUInt32LittleEndian(b, Smb3CreateResponse.CreateContextsLengthOffset, (uint)encoded.Length);
                b = Wire.Join(b, encoded);
            }

            handles.Add(FileHandleId.Read(handle.Id), handle);
            server.OpenFiles.Add(handle);
            RelatedId = handle.Id;
            return b;
        }
        catch
        {
            stream?.Dispose();
            throw;
        }
    }

    private static FileSystemInfo GetFileSystemInfo(OpenFile h) => h.Directory ? new DirectoryInfo(h.Path) : new FileInfo(h.Path);
    private static ulong GetFileSize(OpenFile h) => h.Directory || h.Pipe ? 0 : (ulong)(h.Stream?.Length ?? new FileInfo(h.Path).Length);
    private static ulong GetAllocationSize(OpenFile h) => (GetFileSize(h) + (SmbLimits.AllocationUnitSize - 1)) & ~(ulong)(SmbLimits.AllocationUnitSize - 1);
    private static void WriteTimes(byte[] b, int p, OpenFile h)
    {
        FileMetadata.Times(b, p, h.Path, GetFileSystemInfo(h));
    }

    private static uint GetAttributes(OpenFile h) => FileMetadata.Attributes(h.Path, GetFileSystemInfo(h));
    private static void WriteBasicInfo(byte[] b, int p, OpenFile h)
    {
        WriteTimes(b, p, h);
        Wire.WriteUInt32LittleEndian(b, p + FileBasicInformation.FileAttributesOffset, GetAttributes(h));
    }

    private static void WriteStandardInfo(byte[] b, int p, OpenFile h)
    {
        Wire.WriteUInt64LittleEndian(b, p, GetAllocationSize(h));
        Wire.WriteUInt64LittleEndian(b, p + FileStandardInformation.EndOfFileOffset, GetFileSize(h));
        Wire.WriteUInt32LittleEndian(b, p + FileStandardInformation.NumberOfLinksOffset, FileMetadata.LinkCount(h.Path));
        b[p + FileStandardInformation.DeletePendingOffset] = h.DeletePending ? (byte)1 : (byte)0;
        b[p + FileStandardInformation.DirectoryOffset] = h.Directory ? (byte)1 : (byte)0;
    }

    private static void WriteOpenInfo(byte[] b, int p, OpenFile h)
    {
        WriteBasicInfo(b, p, h);
        Wire.WriteUInt64LittleEndian(b, p + FileNetworkOpenInformation.AllocationSizeOffset, GetAllocationSize(h));
        Wire.WriteUInt64LittleEndian(b, p + FileNetworkOpenInformation.EndOfFileOffset, GetFileSize(h));
        Wire.WriteUInt32LittleEndian(b, p + FileNetworkOpenInformation.FileAttributesOffset, GetAttributes(h));
    }

    private byte[] Close(ReadOnlySpan<byte> r, uint tree)
    {
        ValidateStructure(r, Smb3CloseRequest.StructureSize, Smb3Header.Size + Smb3CloseRequest.FixedSize);
        var h = FindHandle(r, Smb3Header.Size + Smb3CloseRequest.FileIdOffset, tree);
        var b = new byte[Smb3CloseResponse.FixedSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb3CloseResponse.StructureSize);
        try
        {
            if (!h.Pipe && (Wire.ReadUInt16LittleEndian(r, Smb3Header.Size + Smb3CloseRequest.FlagsOffset) & Smb3CloseFlags.PostqueryAttributes) != 0)
            {
                Wire.WriteUInt16LittleEndian(b, Smb3CloseResponse.FlagsOffset, Smb3CloseFlags.PostqueryAttributes);
                WriteOpenInfo(b, Smb3CloseResponse.CreationTimeOffset, h);
            }
        }
        finally
        {
            Remove(h);
        }

        return b;
    }

    private void Remove(OpenFile h)
    {
        // A pending delete follows the object until the last shared handle closes.
        handles.Remove(FileHandleId.Read(h.Id));
        server.OpenFiles.Remove(h);
        h.Dispose();
        if (h.DeletePending && !h.Pipe)
        {
            string deletePath = h.DeletePath ?? h.Path;
            var others = server.OpenFiles.Where(x => x.ObjectId == h.ObjectId && !x.Pipe).ToArray();
            if (others.Length > 0)
                foreach (var x in others)
                {
                    x.DeletePending = true;
                    x.DeletePath = deletePath;
                }
            else if (h.Directory)
                Directory.Delete(deletePath);
            else
                File.Delete(deletePath);
        }
    }

    private byte[] Flush(ReadOnlySpan<byte> r, uint tree)
    {
        ValidateStructure(r, Smb3FlushRequest.StructureSize, Smb3Header.Size + Smb3FlushRequest.FixedSize);
        var h = FindHandle(r, Smb3Header.Size + Smb3FlushRequest.FileIdOffset, tree);
        h.Stream?.Flush(true);
        return Wire.CreateSimpleMessage();
    }

    // Payload buffers remain owned until the awaited positional I/O completes.
    private async ValueTask<byte[]> ReadAsync(ReadOnlyMemory<byte> request, uint tree, CancellationToken cancellationToken)
    {
        ValidateStructure(request.Span, Smb3ReadRequest.StructureSize, Smb3Header.Size + Smb3ReadRequest.FixedSize);
        var handle = FindHandle(request.Span, Smb3Header.Size + Smb3ReadRequest.FileIdOffset, tree);
        RequireAccess(handle, FileAccessMask.ReadData);
        int count = checked((int)Wire.ReadUInt32LittleEndian(request.Span, Smb3Header.Size + Smb3ReadRequest.LengthOffset));
        long offset = checked((long)Wire.ReadUInt64LittleEndian(request.Span, Smb3Header.Size + Smb3ReadRequest.OffsetFieldOffset));
        uint minimum = Wire.ReadUInt32LittleEndian(request.Span, Smb3Header.Size + Smb3ReadRequest.MinimumCountOffset);
        if (count > SmbLimits.MaxTransferSize || minimum > count || Wire.ReadUInt32LittleEndian(request.Span, Smb3Header.Size + Smb3ReadRequest.ChannelOffset) != 0 || Wire.ReadUInt16LittleEndian(request.Span, Smb3Header.Size + Smb3ReadRequest.ReadChannelInfoLengthOffset) != 0)
            throw new SmbException(NtStatus.InvalidParameter);
        var response = new byte[Smb3ReadResponse.FixedSize + count];
        int used;
        if (handle.Pipe)
        {
            if (handle.Rpc.Length == 0)
                throw new SmbException(NtStatus.PipeDisconnected);
            used = Math.Min(count, handle.Rpc.Length);
            handle.Rpc.AsSpan(0, used).CopyTo(response.AsSpan(Smb3ReadResponse.FixedSize));
            handle.Rpc = handle.Rpc[used..];
        }
        else
        {
            if (handle.Directory || handle.Stream == null)
                throw new SmbException(NtStatus.FileIsADirectory);
            // Read directly into the response, avoiding an intermediate payload array.
            used = await RandomAccess.ReadAsync(handle.Stream.SafeFileHandle, response.AsMemory(Smb3ReadResponse.FixedSize, count), offset, cancellationToken).ConfigureAwait(false);
            if ((used == 0 && count > 0) || used < minimum)
                throw new SmbException(NtStatus.EndOfFile);
        }

        if (used != count)
            Array.Resize(ref response, Smb3ReadResponse.FixedSize + used);
        Wire.WriteUInt16LittleEndian(response, 0, Smb3ReadResponse.StructureSize);
        response[Smb3ReadResponse.DataOffsetFieldOffset] = Smb3Header.Size + Smb3ReadResponse.FixedSize;
        Wire.WriteUInt32LittleEndian(response, Smb3ReadResponse.DataLengthOffset, (uint)used);
        return response;
    }

    private async ValueTask<byte[]> WriteAsync(ReadOnlyMemory<byte> request, uint tree, CancellationToken cancellationToken)
    {
        ValidateStructure(request.Span, Smb3WriteRequest.StructureSize, Smb3Header.Size + Smb3WriteRequest.FixedSize);
        var handle = FindHandle(request.Span, Smb3Header.Size + Smb3WriteRequest.FileIdOffset, tree);
        RequireAccess(handle, WriteMask);
        int count = checked((int)Wire.ReadUInt32LittleEndian(request.Span, Smb3Header.Size + Smb3WriteRequest.LengthOffset));
        int dataOffset = Wire.ReadUInt16LittleEndian(request.Span, Smb3Header.Size + Smb3WriteRequest.DataOffsetFieldOffset);
        long offset = checked((long)Wire.ReadUInt64LittleEndian(request.Span, Smb3Header.Size + Smb3WriteRequest.OffsetFieldOffset));
        if (count > SmbLimits.MaxTransferSize || dataOffset < Smb3Header.Size + Smb3WriteRequest.FixedSize || Wire.ReadUInt32LittleEndian(request.Span, Smb3Header.Size + Smb3WriteRequest.ChannelOffset) != 0 || Wire.ReadUInt16LittleEndian(request.Span, Smb3Header.Size + Smb3WriteRequest.WriteChannelInfoLengthOffset) != 0)
            throw new SmbException(NtStatus.InvalidParameter);
        _ = Wire.Slice(request.Span, dataOffset, count);
        var data = request.Slice(dataOffset, count);
        if (handle.Pipe)
        {
            if (handle.Rpc.Length != 0)
                throw new SmbException(NtStatus.PipeBusy);
            handle.Rpc = handle.Endpoint.Feed(data.Span, server.Options.ShareName);
        }
        else
        {
            EnsureWritable();
            if (handle.Directory || handle.Stream == null)
                throw new SmbException(NtStatus.FileIsADirectory);
            if ((handle.Access & FileAccessMask.WriteData) == 0)
                offset = handle.Stream.Length;
            await RandomAccess.WriteAsync(handle.Stream.SafeFileHandle, data, offset, cancellationToken).ConfigureAwait(false);
            FileMetadata.Changed(handle.Path, true);
            // Flush-to-disk has no asynchronous BCL equivalent; durability is mandatory.
            if ((Wire.ReadUInt32LittleEndian(request.Span, Smb3Header.Size + Smb3WriteRequest.FlagsOffset) & Smb3WriteFlags.WriteThrough) != 0)
                handle.Stream.Flush(true);
        }

        var response = new byte[Smb3WriteResponse.FixedSize];
        Wire.WriteUInt16LittleEndian(response, 0, Smb3WriteResponse.StructureSize);
        Wire.WriteUInt32LittleEndian(response, Smb3WriteResponse.CountOffset, (uint)count);
        return response;
    }

    private byte[] Ioctl(ReadOnlySpan<byte> r, uint tree)
    {
        ValidateStructure(r, Smb3IoctlRequest.StructureSize, Smb3Header.Size + Smb3IoctlRequest.FixedSize);
        uint code = Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3IoctlRequest.CtlCodeOffset);
        if (code == FileSystemControlCode.ValidateNegotiateInfo)
            throw new SmbException(NtStatus.NotFound); // FSCTL_VALIDATE_NEGOTIATE_INFO is obsolete for 3.1.1.
        if (code != FileSystemControlCode.PipeTransceive)
            throw new SmbException(NtStatus.NotSupported);
        var h = FindHandle(r, Smb3Header.Size + Smb3IoctlRequest.FileIdOffset, tree);
        if (!h.Pipe)
            throw new SmbException(NtStatus.InvalidHandle);
        int o = checked((int)Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3IoctlRequest.InputOffsetFieldOffset)), n = checked((int)Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3IoctlRequest.InputCountOffset));
        if (h.Rpc.Length != 0)
            throw new SmbException(NtStatus.PipeBusy);
        var data = h.Endpoint.Feed(Wire.Slice(r, o, n), server.Options.ShareName);
        if (data.Length > Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3IoctlRequest.MaxOutputResponseOffset))
            throw new SmbException(NtStatus.BufferTooSmall);
        var b = new byte[Smb3IoctlResponse.FixedSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb3IoctlResponse.StructureSize);
        Wire.WriteUInt32LittleEndian(b, Smb3IoctlResponse.CtlCodeOffset, code);
        h.Id.CopyTo(b, Smb3IoctlResponse.FileIdOffset);
        Wire.WriteUInt32LittleEndian(b, Smb3IoctlResponse.OutputOffsetFieldOffset, Smb3Header.Size + Smb3IoctlResponse.FixedSize);
        Wire.WriteUInt32LittleEndian(b, Smb3IoctlResponse.OutputCountOffset, (uint)data.Length);
        return Wire.Join(b, data);
    }

    private byte[] QueryDirectory(ReadOnlySpan<byte> r, uint tree)
    {
        // Keep the enumerator and next unreturned entry on the handle across pages.
        ValidateStructure(r, Smb3QueryDirectoryRequest.StructureSize, Smb3Header.Size + Smb3QueryDirectoryRequest.FixedSize);
        var h = FindHandle(r, Smb3Header.Size + Smb3QueryDirectoryRequest.FileIdOffset, tree);
        RequireAccess(h, FileAccessMask.ReadData);
        if (!h.Directory)
            throw new SmbException(NtStatus.NotADirectory);
        int cls = r[Smb3Header.Size + Smb3QueryDirectoryRequest.FileInformationClassOffset], baseSize = cls switch
        {
            FileInformationClass.DirectoryInformation => FileDirectoryInformation.FixedSize,
            FileInformationClass.FullDirectoryInformation => FileDirectoryInformation.FullFixedSize,
            FileInformationClass.BothDirectoryInformation => FileDirectoryInformation.BothFixedSize,
            FileInformationClass.NamesInformation => FileDirectoryInformation.NamesFixedSize,
            FileInformationClass.IdBothDirectoryInformation => FileDirectoryInformation.IdBothFixedSize,
            FileInformationClass.IdFullDirectoryInformation => FileDirectoryInformation.IdFullFixedSize,
            _ => throw new SmbException(NtStatus.InvalidInfoClass)
        };
        int max = checked((int)Math.Min(Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3QueryDirectoryRequest.OutputBufferLengthOffset), SmbLimits.MaxTransferSize));
        int nameOffset = Wire.ReadUInt16LittleEndian(r, Smb3Header.Size + Smb3QueryDirectoryRequest.FileNameOffsetFieldOffset), nameLength = Wire.ReadUInt16LittleEndian(r, Smb3Header.Size + Smb3QueryDirectoryRequest.FileNameLengthOffset);
        string pattern = nameLength == 0 ? "*" : Wire.Text(Wire.Slice(r, nameOffset, nameLength));
        if (h.Entries == null || (r[Smb3Header.Size + Smb3QueryDirectoryRequest.FlagsOffset] & (Smb3QueryDirectoryFlags.RestartScans | Smb3QueryDirectoryFlags.Reopen)) != 0)
        {
            h.Entries?.Dispose();
            h.Entries = Directory.EnumerateFileSystemEntries(h.Path).Where(x => (File.GetAttributes(x) & FileAttributes.ReparsePoint) == 0).Where(x => FileSystemName.MatchesWin32Expression(pattern, Path.GetFileName(x), true)).GetEnumerator();
            h.EntryIndex = 0;
            h.EntryCurrent = null;
        }

        var entries = new List<byte[]>();
        int length = 0;
        while (true)
        {
            if (h.EntryCurrent == null)
            {
                if (!h.Entries.MoveNext())
                    break;
                h.EntryCurrent = h.Entries.Current;
            }

            string path = h.EntryCurrent;
            var name = Encoding.Unicode.GetBytes(Path.GetFileName(path));
            var b = new byte[Wire.Align(baseSize + name.Length)];
            if (length + b.Length > max)
            {
                if (length == 0)
                    throw new SmbException(NtStatus.BufferTooSmall);
                break;
            }

            Wire.WriteUInt32LittleEndian(b, FileDirectoryInformation.FileIndexOffset, (uint)h.EntryIndex);
            if (cls == FileInformationClass.NamesInformation)
                Wire.WriteUInt32LittleEndian(b, FileDirectoryInformation.NamesFileNameLengthOffset, (uint)name.Length);
            else
            {
                var entry = new OpenFile
                {
                    Path = path,
                    Id = [],
                    Tree = tree,
                    Access = 0,
                    Share = 0,
                    Directory = Directory.Exists(path)
                };
                WriteOpenInfo(b, FileDirectoryInformation.CreationTimeOffset, entry);
                Wire.WriteUInt64LittleEndian(b, FileDirectoryInformation.EndOfFileOffset, GetFileSize(entry));
                Wire.WriteUInt64LittleEndian(b, FileDirectoryInformation.AllocationSizeOffset, GetAllocationSize(entry));
                Wire.WriteUInt32LittleEndian(b, FileDirectoryInformation.FileNameLengthOffset, (uint)name.Length);
                if (cls == FileInformationClass.IdBothDirectoryInformation)
                    FileMetadata.Identity(path).CopyTo(b, FileDirectoryInformation.IdBothFileIdOffset);
                if (cls == FileInformationClass.IdFullDirectoryInformation)
                    FileMetadata.Identity(path).CopyTo(b, FileDirectoryInformation.IdFullFileIdOffset);
            }

            name.CopyTo(b, baseSize);
            entries.Add(b);
            length += b.Length;
            h.EntryIndex++;
            h.EntryCurrent = null;
            if ((r[Smb3Header.Size + Smb3QueryDirectoryRequest.FlagsOffset] & Smb3QueryDirectoryFlags.ReturnSingleEntry) != 0)
                break;
        }

        if (entries.Count == 0)
            throw new SmbException(NtStatus.NoMoreFiles);
        for (int i = 0; i < entries.Count - 1; i++)
            Wire.WriteUInt32LittleEndian(entries[i], FileDirectoryInformation.NextEntryOffsetFieldOffset, (uint)entries[i].Length);
        return CreateQueryResponse(Wire.Join(entries.ToArray()), max);
    }

    private static byte[] CreateQueryResponse(byte[] data, int max)
    {
        if (data.Length > max)
            throw new SmbException(NtStatus.BufferTooSmall);
        var b = new byte[Smb3QueryResponse.FixedSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb3QueryResponse.StructureSize);
        Wire.WriteUInt16LittleEndian(b, Smb3QueryResponse.OutputBufferOffsetFieldOffset, Smb3Header.Size + Smb3QueryResponse.FixedSize);
        Wire.WriteUInt32LittleEndian(b, Smb3QueryResponse.OutputBufferLengthOffset, (uint)data.Length);
        return Wire.Join(b, data);
    }

    private byte[] QueryInfo(ReadOnlySpan<byte> r, uint tree)
    {
        ValidateStructure(r, Smb3QueryInfoRequest.StructureSize, Smb3Header.Size + Smb3QueryInfoRequest.FixedSize);
        var h = FindHandle(r, Smb3Header.Size + Smb3QueryInfoRequest.FileIdOffset, tree);
        if (h.Pipe)
            throw new SmbException(NtStatus.NotSupported);
        int inputLength = checked((int)Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3QueryInfoRequest.InputBufferLengthOffset)), inputOffset = Wire.ReadUInt16LittleEndian(r, Smb3Header.Size + Smb3QueryInfoRequest.InputBufferOffsetFieldOffset);
        if (inputLength != 0)
        {
            if (inputOffset < Smb3Header.Size + Smb3QueryInfoRequest.FixedSize)
                throw new SmbException(NtStatus.InvalidParameter);
            _ = Wire.Slice(r, inputOffset, inputLength);
        }

        int cls = r[Smb3Header.Size + Smb3QueryInfoRequest.FileInfoClassOffset];
        byte[] b = new byte[SmbLimits.InitialInformationBufferSize];
        int n;
        if (r[Smb3Header.Size + Smb3QueryInfoRequest.InfoTypeOffset] == Smb3InfoType.File)
        {
            switch (cls)
            {
                case FileInformationClass.BasicInformation:
                    RequireAccess(h, FileAccessMask.ReadAttributes);
                    WriteBasicInfo(b, 0, h);
                    n = FileBasicInformation.Size;
                    break;
                case FileInformationClass.StandardInformation:
                    WriteStandardInfo(b, 0, h);
                    n = FileStandardInformation.Size;
                    break;
                case FileInformationClass.InternalInformation:
                    FileMetadata.Identity(h.Path).CopyTo(b, 0);
                    n = FileInternalInformation.Size;
                    break;
                case FileInformationClass.EaInformation:
                    n = sizeof(uint);
                    break;
                case FileInformationClass.AccessInformation:
                    Wire.WriteUInt32LittleEndian(b, 0, h.Access);
                    n = sizeof(uint);
                    break;
                case FileInformationClass.PositionInformation:
                    n = sizeof(ulong);
                    break;
                case FileInformationClass.ModeInformation:
                case FileInformationClass.AlignmentInformation:
                    n = sizeof(uint);
                    break;
                case FileInformationClass.AllInformation:
                    WriteBasicInfo(b, 0, h);
                    WriteStandardInfo(b, FileAllInformation.StandardInformationOffset, h);
                    FileMetadata.Identity(h.Path).CopyTo(b, FileAllInformation.IndexNumberOffset);
                    Wire.WriteUInt32LittleEndian(b, FileAllInformation.AccessFlagsOffset, h.Access);
                    string relativeName = Path.GetRelativePath(server.Options.RootPath, h.Path);
                    var fullName = Encoding.Unicode.GetBytes("\\" + (relativeName == "." ? "" : relativeName.Replace('/', '\\')));
                    if (fullName.Length > b.Length - FileAllInformation.FixedSize)
                        Array.Resize(ref b, FileAllInformation.FixedSize + fullName.Length);
                    Wire.WriteUInt32LittleEndian(b, FileAllInformation.FileNameLengthOffset, (uint)fullName.Length);
                    fullName.CopyTo(b, FileAllInformation.FileNameOffset);
                    n = FileAllInformation.FixedSize + fullName.Length;
                    break;
                case FileInformationClass.StreamInformation:
                    n = 0;
                    if (!h.Directory)
                    {
                        var name = Encoding.Unicode.GetBytes("::$DATA");
                        Wire.WriteUInt32LittleEndian(b, FileStreamInformation.StreamNameLengthOffset, (uint)name.Length);
                        Wire.WriteUInt64LittleEndian(b, FileStreamInformation.StreamSizeOffset, GetFileSize(h));
                        Wire.WriteUInt64LittleEndian(b, FileStreamInformation.StreamAllocationSizeOffset, GetAllocationSize(h));
                        name.CopyTo(b, FileStreamInformation.FixedSize);
                        n = FileStreamInformation.FixedSize + name.Length;
                    }

                    break;
                case FileInformationClass.CompressionInformation:
                    Wire.WriteUInt64LittleEndian(b, 0, GetFileSize(h));
                    n = FileCompressionInformation.Size;
                    break;
                case FileInformationClass.NetworkOpenInformation:
                    WriteOpenInfo(b, 0, h);
                    n = FileNetworkOpenInformation.Size;
                    break;
                case FileInformationClass.AttributeTagInformation:
                    Wire.WriteUInt32LittleEndian(b, FileAttributeTagInformation.FileAttributesOffset, GetAttributes(h));
                    n = FileAttributeTagInformation.Size;
                    break;
                default:
                    throw new SmbException(NtStatus.InvalidInfoClass);
            }
        }
        else if (r[Smb3Header.Size + Smb3QueryInfoRequest.InfoTypeOffset] == Smb3InfoType.FileSystem)
        {
            var drive = new DriveInfo(Path.GetPathRoot(server.Options.RootPath)!);
            switch (cls)
            {
                case FileSystemInformationClass.VolumeInformation:
                    var label = Encoding.Unicode.GetBytes(server.Options.ShareName);
                    Wire.WriteUInt64LittleEndian(b, FileFsVolumeInformation.VolumeCreationTimeOffset, (ulong)Directory.GetCreationTimeUtc(server.Options.RootPath).ToFileTimeUtc());
                    Wire.WriteUInt32LittleEndian(b, FileFsVolumeInformation.VolumeSerialNumberOffset, SmbLimits.VolumeSerialNumber);
                    Wire.WriteUInt32LittleEndian(b, FileFsVolumeInformation.VolumeLabelLengthOffset, (uint)label.Length);
                    label.CopyTo(b, FileFsVolumeInformation.FixedSize);
                    n = FileFsVolumeInformation.FixedSize + label.Length;
                    break;
                case FileSystemInformationClass.SizeInformation:
                case FileSystemInformationClass.FullSizeInformation:
                    Wire.WriteUInt64LittleEndian(b, FileFsSizeInformation.TotalAllocationUnitsOffset, (ulong)drive.TotalSize / SmbLimits.AllocationUnitSize);
                    Wire.WriteUInt64LittleEndian(b, FileFsSizeInformation.AvailableAllocationUnitsOffset, (ulong)drive.AvailableFreeSpace / SmbLimits.AllocationUnitSize);
                    if (cls == FileSystemInformationClass.SizeInformation)
                    {
                        Wire.WriteUInt32LittleEndian(b, FileFsSizeInformation.SectorsPerAllocationUnitOffset, SmbLimits.AllocationUnitSize / SmbLimits.SectorSize);
                        Wire.WriteUInt32LittleEndian(b, FileFsSizeInformation.BytesPerSectorOffset, SmbLimits.SectorSize);
                        n = FileFsSizeInformation.Size;
                    }
                    else
                    {
                        Wire.WriteUInt64LittleEndian(b, FileFsFullSizeInformation.ActualAvailableAllocationUnitsOffset, (ulong)drive.TotalFreeSpace / SmbLimits.AllocationUnitSize);
                        Wire.WriteUInt32LittleEndian(b, FileFsFullSizeInformation.SectorsPerAllocationUnitOffset, SmbLimits.AllocationUnitSize / SmbLimits.SectorSize);
                        Wire.WriteUInt32LittleEndian(b, FileFsFullSizeInformation.BytesPerSectorOffset, SmbLimits.SectorSize);
                        n = FileFsFullSizeInformation.Size;
                    }

                    break;
                case FileSystemInformationClass.DeviceInformation:
                    Wire.WriteUInt32LittleEndian(b, FileFsDeviceInformation.DeviceTypeOffset, FileFsDeviceInformation.FileDeviceDisk);
                    Wire.WriteUInt32LittleEndian(b, FileFsDeviceInformation.CharacteristicsOffset, FileFsDeviceInformation.FileRemoteDevice);
                    n = FileFsDeviceInformation.Size;
                    break;
                case FileSystemInformationClass.AttributeInformation:
                    Wire.WriteUInt32LittleEndian(b, FileFsAttributeInformation.FileSystemAttributesOffset, FileSystemAttributeFlags.CasePreservedNames | FileSystemAttributeFlags.UnicodeOnDisk | (server.Options.Writable ? 0u : FileSystemAttributeFlags.ReadOnlyVolume));
                    Wire.WriteUInt32LittleEndian(b, FileFsAttributeInformation.MaximumComponentNameLengthOffset, SmbLimits.MaxComponentLength);
                    Wire.WriteUInt32LittleEndian(b, FileFsAttributeInformation.FileSystemNameLengthOffset, (uint)(SmbLimits.FileSystemName.Length * sizeof(char)));
                    Encoding.Unicode.GetBytes(SmbLimits.FileSystemName).CopyTo(b, FileFsAttributeInformation.FixedSize);
                    n = FileFsAttributeInformation.FixedSize + SmbLimits.FileSystemName.Length * sizeof(char);
                    break;
                case FileSystemInformationClass.ControlInformation:
                    n = FileFsControlInformation.Size;
                    break;
                case FileSystemInformationClass.SectorSizeInformation:
                    Wire.WriteUInt32LittleEndian(b, FileFsSectorSizeInformation.LogicalBytesPerSectorOffset, SmbLimits.SectorSize);
                    Wire.WriteUInt32LittleEndian(b, FileFsSectorSizeInformation.PhysicalBytesPerSectorForAtomicityOffset, SmbLimits.AllocationUnitSize);
                    Wire.WriteUInt32LittleEndian(b, FileFsSectorSizeInformation.PhysicalBytesPerSectorForPerformanceOffset, SmbLimits.AllocationUnitSize);
                    Wire.WriteUInt32LittleEndian(b, FileFsSectorSizeInformation.FileSystemEffectivePhysicalBytesPerSectorForAtomicityOffset, SmbLimits.AllocationUnitSize);
                    Wire.WriteUInt32LittleEndian(b, FileFsSectorSizeInformation.FlagsOffset, FileFsSectorSizeInformation.AlignedDevice | FileFsSectorSizeInformation.PartitionAlignedOnDevice);
                    n = FileFsSectorSizeInformation.Size;
                    break;
                default:
                    throw new SmbException(NtStatus.InvalidInfoClass);
            }
        }
        else
            throw new SmbException(NtStatus.NotSupported);
        Array.Resize(ref b, n);
        return CreateQueryResponse(b, checked((int)Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3QueryInfoRequest.OutputBufferLengthOffset)));
    }

    private byte[] SetInfo(ReadOnlySpan<byte> r, uint tree)
    {
        ValidateStructure(r, Smb3SetInfoRequest.StructureSize, Smb3Header.Size + Smb3SetInfoRequest.FixedSize);
        EnsureWritable();
        var h = FindHandle(r, Smb3Header.Size + Smb3SetInfoRequest.FileIdOffset, tree);
        if (r[Smb3Header.Size + Smb3SetInfoRequest.InfoTypeOffset] != Smb3InfoType.File || h.Pipe)
            throw new SmbException(NtStatus.NotSupported);
        int n = checked((int)Wire.ReadUInt32LittleEndian(r, Smb3Header.Size + Smb3SetInfoRequest.BufferLengthOffset)), o = Wire.ReadUInt16LittleEndian(r, Smb3Header.Size + Smb3SetInfoRequest.BufferOffsetFieldOffset);
        if (n != 0 && o < Smb3Header.Size + Smb3SetInfoRequest.FixedSize)
            throw new SmbException(NtStatus.InvalidParameter);
        var data = Wire.Slice(r, o, n);
        switch (r[Smb3Header.Size + Smb3SetInfoRequest.FileInfoClassOffset])
        {
            case FileInformationClass.BasicInformation:
                RequireAccess(h, FileAccessMask.WriteAttributes);
                if (data.Length != FileBasicInformation.Size)
                    throw new SmbException(NtStatus.InfoLengthMismatch);
                uint attr = Wire.ReadUInt32LittleEndian(data, FileBasicInformation.FileAttributesOffset);
                if ((attr & ~SmbLimits.SupportedFileAttributes) != 0)
                    throw new SmbException(NtStatus.NotSupported);
                FileMetadata.SetTimes(h.Path, data);
                if (attr != 0)
                    FileMetadata.SetAttributes(h.Path, attr, h.Directory);
                break;
            case FileInformationClass.RenameInformation:
                RequireAccess(h, DeleteMask);
                if (data.Length < FileRenameInformation.FixedSize || Wire.ReadUInt64LittleEndian(data, FileRenameInformation.RootDirectoryOffset) != 0)
                    throw new SmbException(NtStatus.InvalidParameter);
                if (h.Path == server.Options.RootPath || server.OpenFiles.Any(x => x != h && ((x.Path == h.Path && (x.Share & FileShareAccess.Delete) == 0) || x.Path.StartsWith(h.Path + Path.DirectorySeparatorChar, StringComparison.Ordinal))))
                    throw new SmbException(NtStatus.SharingViolation);
                string destination = ResolvePath(Wire.Text(Wire.Slice(data, FileRenameInformation.FixedSize, checked((int)Wire.ReadUInt32LittleEndian(data, FileRenameInformation.FileNameLengthOffset)))));
                if (server.OpenFiles.Any(x => x != h && x.Path == destination))
                    throw new SmbException(NtStatus.SharingViolation);
                string oldPath = h.Path;
                if (h.Directory)
                    Directory.Move(oldPath, destination);
                else
                    File.Move(oldPath, destination, data[0] != 0);
                foreach (var open in server.OpenFiles.Where(x => !x.Pipe && x.Path == oldPath))
                    open.Path = destination;
                FileMetadata.Changed(destination);
                break;
            case FileInformationClass.DispositionInformation:
                RequireAccess(h, DeleteMask);
                if (data.Length != FileDispositionInformation.Size)
                    throw new SmbException(NtStatus.InfoLengthMismatch);
                if (h.Path == server.Options.RootPath)
                    throw new SmbException(NtStatus.AccessDenied);
                if (data[0] != 0 && h.Directory && Directory.EnumerateFileSystemEntries(h.Path).Any())
                    throw new SmbException(NtStatus.DirectoryNotEmpty);
                if (server.OpenFiles.Any(x => x != h && x.Path == h.Path && (x.Share & FileShareAccess.Delete) == 0))
                    throw new SmbException(NtStatus.SharingViolation);
                h.DeletePending = data[0] != 0;
                h.DeletePath = h.DeletePending ? h.Path : null;
                break;
            case FileInformationClass.AllocationInformation:
            case FileInformationClass.EndOfFileInformation:
                RequireAccess(h, FileAccessMask.WriteData);
                if (data.Length != FileEndOfFileInformation.Size || h.Directory || h.Stream == null)
                    throw new SmbException(NtStatus.InvalidParameter);
                long size = checked((long)Wire.ReadUInt64LittleEndian(data, 0));
                if (r[Smb3Header.Size + Smb3SetInfoRequest.FileInfoClassOffset] == FileInformationClass.EndOfFileInformation || size < h.Stream.Length)
                {
                    h.Stream.SetLength(size);
                    FileMetadata.Changed(h.Path, true);
                }

                break;
            default:
                throw new SmbException(NtStatus.InvalidInfoClass);
        }

        return new byte[]
        {
            Smb3SetInfoResponse.StructureSize,
            0
        };
    }

    internal async ValueTask CloseTreeAsync(uint tree, CancellationToken cancellationToken)
    {
        await server.FileGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            foreach (var handle in handles.Values.Where(x => x.Tree == tree).ToArray())
                Remove(handle);
        }
        finally
        {
            server.FileGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await server.FileGate.WaitAsync().ConfigureAwait(false);
        try
        {
            foreach (var handle in handles.Values.ToArray())
            {
                try
                {
                    Remove(handle);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }
        finally
        {
            server.FileGate.Release();
        }
    }
}
