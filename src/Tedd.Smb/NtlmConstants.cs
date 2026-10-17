namespace Tedd.Smb;

// MS-NLMP negotiate flags, AV_PAIR identifiers and message layouts.
internal static class NtlmNegotiateFlags
{
    internal const uint Unicode = 0x00000001, RequestTarget = 0x00000004, Sign = 0x00000010,
        Seal = 0x00000020, Ntlm = 0x00000200, AlwaysSign = 0x00008000,
        TargetTypeServer = 0x00020000, ExtendedSessionSecurity = 0x00080000,
        TargetInfo = 0x00800000, Version = 0x02000000, Negotiate128 = 0x20000000,
        KeyExchange = 0x40000000, Negotiate56 = 0x80000000;
    internal const uint Supported = Unicode | RequestTarget | Sign | Seal | Ntlm | AlwaysSign |
        ExtendedSessionSecurity | Version | Negotiate128 | KeyExchange | Negotiate56;
    internal const uint ServerChallenge = TargetInfo | TargetTypeServer | AlwaysSign | RequestTarget | Unicode;
    internal const uint Required = Unicode | Ntlm | ExtendedSessionSecurity;
    internal const uint AuthenticateConsistencyMask = Required | Sign | KeyExchange;
}

internal static class NtlmMessageType
{
    internal const uint Negotiate = 1, Challenge = 2, Authenticate = 3;
}

internal static class NtlmAvId
{
    internal const ushort Eol = 0, NbComputerName = 1, NbDomainName = 2, DnsComputerName = 3, Flags = 6, Timestamp = 7;
}

internal static class NtlmAvFlags
{
    internal const uint MicPresent = 0x00000002;
}

internal static class NtlmMessage
{
    internal const int MessageTypeOffset = 8, ChallengeSize = 8, SessionKeySize = 16, MicSize = 16,
        LmResponseSize = 24, TimestampSize = sizeof(ulong);
    internal static ReadOnlySpan<byte> Signature => "NTLMSSP\0"u8;
}

internal static class NtlmSecurityBuffer
{
    internal const int Size = 8, LengthOffset = 0, MaximumLengthOffset = 2, BufferOffset = 4;
}

internal static class NtlmAvPair
{
    internal const int HeaderSize = 4, AvIdOffset = 0, AvLenOffset = 2;
}

internal static class NtlmNegotiateMessage
{
    internal const int FixedSize = 32, SizeWithVersion = 40, NegotiateFlagsOffset = 12, VersionOffset = 32;
}

internal static class NtlmChallengeMessage
{
    internal const int FixedSize = 48, SizeWithVersion = 56, TargetNameFieldsOffset = 12,
        NegotiateFlagsOffset = 20, ServerChallengeOffset = 24, TargetInfoFieldsOffset = 40, VersionOffset = 48;
}

internal static class NtlmAuthenticateMessage
{
    internal const int FixedSize = 64, SizeWithVersion = 72, LmChallengeResponseFieldsOffset = 12,
        NtChallengeResponseFieldsOffset = 20, DomainNameFieldsOffset = 28, UserNameFieldsOffset = 36,
        WorkstationFieldsOffset = 44, EncryptedRandomSessionKeyFieldsOffset = 52,
        NegotiateFlagsOffset = 60, VersionOffset = 64;
}

internal static class NtlmVersion
{
    internal const int ProductMajorVersionOffset = 0, NtlmRevisionCurrentOffset = 7;
    internal const byte Windows10MajorVersion = 10, RevisionW2k3 = 15;
}

// Includes the NTProofStr prefix, so these offsets are relative to the complete NT response.
internal static class NtlmV2Response
{
    internal const int MinimumSize = 48, ProofSize = 16, ResponseTypeOffset = 16, HiResponseTypeOffset = 17,
        Reserved1Offset = 18, Reserved2Offset = 20, TimestampOffset = 24, Reserved3Offset = 40, AvPairsOffset = 44;
    internal const byte ResponseVersion = 1;
}

internal static class Asn1Tag
{
    internal const byte OctetString = 0x04, Enumerated = 0x0a, Sequence = 0x30, Constructed = 0x20;
}

internal static class SpnegoTag
{
    internal const byte InitialContextToken = 0x60, NegTokenInit = 0xa0, NegTokenResp = 0xa1,
        MechTypes = 0xa0, MechToken = 0xa2, NegState = 0xa0, SupportedMech = 0xa1, ResponseToken = 0xa2;
}

internal static class SpnegoNegState
{
    internal const byte AcceptCompleted = 0, AcceptIncomplete = 1;
}
