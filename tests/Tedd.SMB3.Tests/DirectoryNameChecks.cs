using Tedd.SMB3;

internal static class DirectoryNameChecks
{
    internal static async Task RunAsync(string root)
    {
        string fixture = Path.Combine(root, "directory-names");
        string outside = Path.Combine(root, "directory-names-outside");
        Directory.CreateDirectory(fixture);
        Directory.CreateDirectory(Path.Combine(fixture, "Nested"));
        Directory.CreateDirectory(outside);
        string[] names = ["ReadMe.txt", "résumé.bin", "æøå-文件-😀.bin", "Kelvin.bin", "Hidden.dat",
            new string('x', 120) + ".bin", "Nested/Inside.txt"];
        try
        {
            foreach (string name in names) File.WriteAllBytes(Path.Combine(fixture, name), [1, 2, 3]);
            if (OperatingSystem.IsWindows()) File.SetAttributes(Path.Combine(fixture, "Hidden.dat"), FileAttributes.Hidden);
            var provider = SmbDirectoryProvider.Create(fixture);
            foreach (string name in names)
            foreach (string requested in new[] { name, name.ToLowerInvariant(), name.ToUpperInvariant() })
            {
                string expected = ReferenceResolve(fixture, requested);
                if (provider.ResolvePath(requested) != expected)
                    throw new Exception($"Directory spelling/metadata mismatch: {requested}.");
                if (!File.Exists(Path.Combine(fixture, expected)))
                {
                    if (provider.GetMetadata(requested) != null) throw new Exception("Absent case variant acquired metadata.");
                    continue;
                }
                if (provider.GetMetadata(requested)?.Length != 3) throw new Exception("Resolved file metadata mismatch.");
                using var file = provider.OpenFile(requested, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, false);
                byte[] data = new byte[3];
                if (await file.ReadAsync(data, 0, default) != 3 || !data.AsSpan().SequenceEqual(new byte[] { 1, 2, 3 }))
                    throw new Exception("Directory spelling resolved to incorrect content.");
            }

            if (provider.ResolvePath("") != "" || provider.ResolvePath("Nested/Missing.txt") != "Nested/Missing.txt" ||
                provider.GetMetadata("Nested/Missing.txt") != null)
                throw new Exception("Root or absent-name resolution changed.");
            if (OperatingSystem.IsWindows())
            {
                string longest = new string('L', 249) + "😀.bin";
                string extended = @"\\?\" + Path.Combine(fixture, longest);
                File.WriteAllBytes(extended, [8]);
                if (!FileMetadata.HasExactName(extended, longest) || FileMetadata.HasExactName(extended, longest.ToLowerInvariant()))
                    throw new Exception("Native exact-name lookup truncated or folded a maximum-length Unicode name.");
            }
            ulong identity = provider.GetMetadata("ReadMe.txt")!.FileId;
            File.Move(Path.Combine(fixture, "ReadMe.txt"), Path.Combine(fixture, "Renamed.txt"));
            if (provider.GetMetadata("ReadMe.txt") != null || provider.ResolvePath("RENAMED.TXT") != "Renamed.txt" ||
                provider.GetMetadata("Renamed.txt")?.FileId != identity)
                throw new Exception("External rename was not observed with stable identity.");
            provider.Delete("Renamed.txt", false);
            if (provider.GetMetadata("Renamed.txt") != null) throw new Exception("Deleted name remained visible.");
            using (provider.OpenFile("Created.txt", FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite, false)) { }
            provider.Move("Created.txt", "Moved.txt", false, false);
            if (provider.ResolvePath("MOVED.TXT") != "Moved.txt") throw new Exception("Created/moved name mismatch.");

            File.WriteAllBytes(Path.Combine(fixture, "CasePair"), [4]);
            File.WriteAllBytes(Path.Combine(fixture, "CASEPAIR"), [5]);
            if (Directory.EnumerateFileSystemEntries(fixture).Count(p => Path.GetFileName(p).Equals("casepair", StringComparison.OrdinalIgnoreCase)) == 2)
            {
                if (provider.ResolvePath("CasePair") != "CasePair" || provider.ResolvePath("CASEPAIR") != "CASEPAIR")
                    throw new Exception("Exact case did not disambiguate existing names.");
                Reject(() => provider.ResolvePath("casepair"), NtStatus.ObjectNameCollision);
            }
            foreach (string invalid in new[] { "../outside", "/absolute", "file:stream", "*.txt", "Nested/..", "NUL.txt" })
                Reject(() => provider.ResolvePath(invalid), NtStatus.AccessDenied);

            File.WriteAllBytes(Path.Combine(outside, "secret.bin"), [9]);
            string link = Path.Combine(fixture, "Link");
            bool linked = false;
            try { Directory.CreateSymbolicLink(link, outside); linked = true; }
            catch (Exception e) when (e is UnauthorizedAccessException or IOException or PlatformNotSupportedException) { }
            if (linked)
            {
                try { Reject(() => provider.ResolvePath("Link/secret.bin"), NtStatus.AccessDenied); }
                finally { Directory.Delete(link); }
            }
            Console.WriteLine(linked ? "PASS directory link rejection" : "SKIP directory link fixture: symbolic-link creation unavailable");
            Console.WriteLine("PASS exact/mixed-case Unicode directory names, missing names, rename/create/delete visibility, identity and path guards");
        }
        finally
        {
            Directory.Delete(fixture, true);
            Directory.Delete(outside, true);
        }
    }

    // An independent linear directory walk provides canonical names for the native-query path.
    private static string ReferenceResolve(string root, string name)
    {
        string path = root;
        foreach (string part in name.Split('/'))
        {
            string[] matches = Directory.EnumerateFileSystemEntries(path)
                .Where(entry => Path.GetFileName(entry).Equals(part, StringComparison.OrdinalIgnoreCase)).ToArray();
            path = matches.FirstOrDefault(entry => Path.GetFileName(entry) == part)
                ?? (matches.Length == 0 ? Path.Combine(path, part) : matches.Length == 1 ? matches[0]
                    : throw new Exception("Ambiguous reference fixture."));
        }
        return Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');
    }

    private static void Reject(Action action, uint status)
    {
        try { action(); }
        catch (SmbException e) when (e.NtStatus == status) { return; }
        throw new Exception($"Expected directory status {status:X8}.");
    }
}
