namespace Tedd.SMB3;

// MS-NLMP negotiate flags, AV_PAIR identifiers and message layouts.
internal static class NtlmNegotiateFlags
{
    internal const uint Unicode = 0x00000001;
    internal const uint RequestTarget = 0x00000004;
    internal const uint Sign = 0x00000010;
    internal const uint Seal = 0x00000020;
    internal const uint Ntlm = 0x00000200;
    internal const uint AlwaysSign = 0x00008000;
    internal const uint TargetTypeServer = 0x00020000;
    internal const uint ExtendedSessionSecurity = 0x00080000;
    internal const uint TargetInfo = 0x00800000;
    internal const uint Version = 0x02000000;
    internal const uint Negotiate128 = 0x20000000;
    internal const uint KeyExchange = 0x40000000;
    internal const uint Negotiate56 = 0x80000000;
    internal const uint Supported = Unicode | RequestTarget | Sign | Seal | Ntlm | AlwaysSign | ExtendedSessionSecurity | Version | Negotiate128 | KeyExchange | Negotiate56;
    internal const uint ServerChallenge = TargetInfo | TargetTypeServer | AlwaysSign | RequestTarget | Unicode;
    internal const uint Required = Unicode | Ntlm | ExtendedSessionSecurity;
    internal const uint AuthenticateConsistencyMask = Required | Sign | KeyExchange;
}

internal static class NtlmMessageType
{
    internal const uint Negotiate = 1;
    internal const uint Challenge = 2;
    internal const uint Authenticate = 3;
}

internal static class NtlmAvId
{
    internal const ushort Eol = 0;
    internal const ushort NbComputerName = 1;
    internal const ushort NbDomainName = 2;
    internal const ushort DnsComputerName = 3;
    internal const ushort Flags = 6;
    internal const ushort Timestamp = 7;
}

internal static class NtlmAvFlags
{
    internal const uint MicPresent = 0x00000002;
}

internal static class NtlmMessage
{
    internal const int MessageTypeOffset = 8;
    internal const int ChallengeSize = 8;
    internal const int SessionKeySize = 16;
    internal const int MicSize = 16;
    internal const int LmResponseSize = 24;
    internal const int TimestampSize = sizeof(ulong);
    internal static ReadOnlySpan<byte> Signature => "NTLMSSP\0"u8;
}

// Length and capacity are 16-bit; the payload location is a message-relative 32-bit offset.
internal static class NtlmSecurityBuffer
{
    internal const int Size = 8;
    internal const int LengthOffset = 0;
    internal const int MaximumLengthOffset = 2;
    internal const int BufferOffset = 4;
}

internal static class NtlmAvPair
{
    internal const int HeaderSize = 4;
    internal const int AvIdOffset = 0;
    internal const int AvLenOffset = 2;
}

internal static class NtlmNegotiateMessage
{
    internal const int FixedSize = 32;
    internal const int SizeWithVersion = 40;
    internal const int NegotiateFlagsOffset = 12;
    internal const int VersionOffset = 32;
}

internal static class NtlmChallengeMessage
{
    internal const int FixedSize = 48;
    internal const int SizeWithVersion = 56;
    internal const int TargetNameFieldsOffset = 12;
    internal const int NegotiateFlagsOffset = 20;
    internal const int ServerChallengeOffset = 24;
    internal const int TargetInfoFieldsOffset = 40;
    internal const int VersionOffset = 48;
}

internal static class NtlmAuthenticateMessage
{
    internal const int FixedSize = 64;
    internal const int SizeWithVersion = 72;
    internal const int LmChallengeResponseFieldsOffset = 12;
    internal const int NtChallengeResponseFieldsOffset = 20;
    internal const int DomainNameFieldsOffset = 28;
    internal const int UserNameFieldsOffset = 36;
    internal const int WorkstationFieldsOffset = 44;
    internal const int EncryptedRandomSessionKeyFieldsOffset = 52;
    internal const int NegotiateFlagsOffset = 60;
    internal const int VersionOffset = 64;
}

internal static class NtlmVersion
{
    internal const int ProductMajorVersionOffset = 0;
    internal const int NtlmRevisionCurrentOffset = 7;
    internal const byte Windows10MajorVersion = 10;
    internal const byte RevisionW2k3 = 15;
}

// Includes the NTProofStr prefix, so these offsets are relative to the complete NT response.
// The client-challenge blob includes timestamp, nonce and the server's AV pairs.
internal static class NtlmV2Response
{
    internal const int MinimumSize = 48;
    internal const int ProofSize = 16;
    internal const int ResponseTypeOffset = 16;
    internal const int HiResponseTypeOffset = 17;
    internal const int Reserved1Offset = 18;
    internal const int Reserved2Offset = 20;
    internal const int TimestampOffset = 24;
    internal const int Reserved3Offset = 40;
    internal const int AvPairsOffset = 44;
    internal const byte ResponseVersion = 1;
}

internal static class Asn1Tag
{
    internal const byte OctetString = 0x04;
    internal const byte Enumerated = 0x0a;
    internal const byte Sequence = 0x30;
    internal const byte Constructed = 0x20;
}

internal static class SpnegoTag
{
    internal const byte InitialContextToken = 0x60;
    internal const byte NegTokenInit = 0xa0;
    internal const byte NegTokenResp = 0xa1;
    internal const byte MechTypes = 0xa0;
    internal const byte MechToken = 0xa2;
    internal const byte NegState = 0xa0;
    internal const byte SupportedMech = 0xa1;
    internal const byte ResponseToken = 0xa2;
}

internal static class SpnegoNegState
{
    internal const byte AcceptCompleted = 0;
    internal const byte AcceptIncomplete = 1;
}
