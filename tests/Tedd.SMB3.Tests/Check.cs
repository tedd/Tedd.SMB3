using Tedd.SMB3;

internal static class Check
{
    internal static void Equal<T>(T expected, T actual, string scenario)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException($"{scenario}: expected {expected}, received {actual}.");
    }

    internal static void Bytes(byte[] expected, byte[] actual, string scenario)
    {
        if (!expected.AsSpan().SequenceEqual(actual))
            throw new InvalidOperationException($"{scenario}: content mismatch (expected {expected.Length} bytes, received {actual.Length}).");
    }

    internal static async Task<T> ThrowsAsync<T>(Func<Task> action, string scenario) where T : Exception
    {
        try { await action(); }
        catch (T error) { return error; }
        catch (Exception error) { throw new InvalidOperationException($"{scenario}: expected {typeof(T).Name}.", error); }
        throw new InvalidOperationException($"{scenario}: expected {typeof(T).Name}, operation succeeded.");
    }

    internal static async Task StatusAsync(uint expected, Func<Task> action, string scenario)
    {
        var error = await ThrowsAsync<SmbException>(action, scenario);
        Equal(expected.ToString("X8"), error.NtStatus.ToString("X8"), scenario);
    }
}
