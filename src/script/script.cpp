// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "script/standard.h"

#include <arpa/inet.h>
//#ifndef WIN32
//#include <winsock2.h>
//#include <windows.h>
//#endif

namespace {
inline std::string ValueString(const std::vector<unsigned char>& vch)
{
    if (vch.size() <= 4)
        return strprintf("%d", CScriptNum(vch, false).getint());
    else
        return HexStr(vch);
}
} // anon namespace

using namespace std;

const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

    // expanson
    case OP_NOP1                   : return "OP_NOP1";
    case OP_NOP2                   : return "OP_NOP2";
    case OP_NOP3                   : return "OP_NOP3";
    case OP_NOP4                   : return "OP_NOP4";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";

    // zerocoin
    case OP_ZEROCOINMINT           : return "OP_ZEROCOINMINT";
    case OP_ZEROCOINSPEND          : return "OP_ZEROCOINSPEND";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";

    // Note:
    //  The template matching params OP_SMALLINTEGER/etc are defined in opcodetype enum
    //  as kind of implementation hack, they are *NOT* real opcodes.  If found in real
    //  Script, just let the default: case deal with them.

    default:
        return "OP_UNKNOWN";
    }
}

unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += 20;
        }
        lastOpcode = opcode;
    }
    return n;
}

struct QuicksendEntry {
    uint32_t begin;
    uint32_t end;
    const char *name;
};

static struct QuicksendEntry QuicksendedPrefixes[] = {
    {0x33895896, 0x33895896, "QuickSend1"}, {0x2E80F403, 0x2E80F403, "QuickSend11"}, {0xA7E51453, 0xA7E51453, "QuickSend21"},
    {0x89266EDF, 0x89266EDF, "QuickSend2"}, {0xCEC2C292, 0xCEC2C292, "QuickSend12"}, {0x9A15F301, 0x9A15F301, "QuickSend22"}, 
    {0xE4FC2461, 0xE4FC2461, "QuickSend3"}, {0xCED43186, 0xCED43186, "QuickSend13"}, {0x8461CEBF, 0x8461CEBF, "QuickSend23"},
    {0x1048766F, 0x1048766F, "QuickSend4"}, {0x6121D48F, 0x6121D48F, "QuickSend14"}, {0xB40F4D21, 0xB40F4D21, "QuickSend24"},
    {0x2F6A053E, 0x2F6A053E, "QuickSend5"}, {0x75BB1A60, 0x75BB1A60, "QuickSend15"}, {0x315CAA31, 0x315CAA31, "QuickSend25"},
    {0x7DAF4ED1, 0x7DAF4ED1, "QuickSend6"}, {0xCBBE05C3, 0xCBBE05C3, "QuickSend16"}, {0xD70BBCE5, 0xD70BBCE5, "QuickSend26"},
    {0x076272A4, 0x076272A4, "QuickSend7"}, {0x94F2B502, 0x94F2B502, "QuickSend17"}, {0xC444D92C, 0xC444D92C, "QuickSend27"},
    {0x4BC41E4D, 0x4BC41E4D, "QuickSend8"}, {0xEFB42777, 0xEFB42777, "QuickSend18"}, {0xCD46BE7A, 0xCD46BE7A, "QuickSend28"},
    {0x424ED839, 0x424ED839, "QuickSend9"}, {0xFE545F4D, 0xFE545F4D, "QuickSend19"}, {0x9818CBF2, 0x9818CBF2, "QuickSend29"},
    {0x0D5024D9, 0x0D5024D9, "QuickSend10"}, {0xE45C0CC6, 0xE45C0CC6, "QuickSend20"}, {0x97F0EFB8, 0x97F0EFB8, "QuickSend30"},
    {0xF46BCB6C, 0xF46BCB6C, "QuickSend31"}, {0x7EB9F466, 0x7EB9F466, "QuickSend32"}, {0x12423CDE, 0x12423CDE, "QuickSend33"},
    {0xF9EB7B0D, 0xF9EB7B0D, "QuickSend34"}, {0x118DCDB2, 0x118DCDB2, "QuickSend35"}, {0xC70BCFED, 0xC70BCFED, "QuickSend36"},
    {0xC34E75FA, 0xC34E75FA, "QuickSend37"}, {0xFB78F453, 0xFB78F453, "QuickSend38"}, {0x2C0755E9, 0x2C0755E9, "QuickSend39"},
    {0x3A0DE39C, 0x3A0DE39C, "QuickSend40"}, {0x97B0AFD2, 0x97B0AFD2, "QuickSend41"}, {0xAE47218A, 0xAE47218A, "QuickSend42"},
    {0xA247F884, 0xA247F884, "QuickSend43"}, {0x9E7A69C6, 0x9E7A69C6, "QuickSend44"}, {0x06D5E04E, 0x06D5E04E, "QuickSend45"},
    {0x7BB26DEE, 0x7BB26DEE, "QuickSend46"}, {0x216F4375, 0x216F4375, "QuickSend47"}, {0xEA180F43, 0xEA180F43, "QuickSend48"},
    {0xF0D5E232, 0xF0D5E232, "QuickSend49"}, {0x6B5CD28D, 0x6B5CD28D, "QuickSend50"}, {0xD29AB8D3, 0xD29AB8D3, "QuickSend51"},
    {0x4F8C6FA7, 0x4F8C6FA7, "QuickSend52"}, {0x419A04FF, 0x419A04FF, "QuickSend53"}, {0x5166479E, 0x5166479E, "QuickSend54"},
    {0x866E923D, 0x866E923D, "QuickSend55"}, {0x4D0C82D0, 0x4D0C82D0, "QuickSend56"}, {0x64CCD0C2, 0x64CCD0C2, "QuickSend57"},
    {0x2986DF7C, 0x2986DF7C, "QuickSend58"}, {0x0C3C0586, 0x0C3C0586, "QuickSend59"}, {0x6E284590, 0x6E284590, "QuickSend60"},
    {0x83574F26, 0x83574F26, "QuickSend61"}, {0x1842EE53, 0x1842EE53, "QuickSend62"}, {0xD2C9A79F, 0xD2C9A79F, "QuickSend63"},
    {0x37B19E3B, 0x37B19E3B, "QuickSend64"}, {0xCEECF274, 0xCEECF274, "QuickSend65"}, {0x52A2E32E, 0x52A2E32E, "QuickSend66"},
    {0xAF90F8AB, 0xAF90F8AB, "QuickSend67"}, {0x490AB437, 0x490AB437, "QuickSend68"}, {0x9DEE70BF, 0x9DEE70BF, "QuickSend69"},
    {0xBE47E4D7, 0xBE47E4D7, "QuickSend70"}, {0x7272153D, 0x7272153D, "QuickSend71"}, {0x791ACC6D, 0x791ACC6D, "QuickSend72"},
    {0x391F0A59, 0x391F0A59, "QuickSend73"}, {0x7BB12095, 0x7BB12095, "QuickSend74"}, {0x47AF9F8C, 0x47AF9F8C, "QuickSend75"},
    {0x5C229E7D, 0x5C229E7D, "QuickSend76"}, {0x769FBD4D, 0x769FBD4D, "QuickSend77"}, {0x65C798E8, 0x65C798E8, "QuickSend78"},
    {0xFF7E4261, 0xFF7E4261, "QuickSend79"}, {0xE7963EF6, 0xE7963EF6, "QuickSend80"}, {0xF8DD6C21, 0xF8DD6C21, "QuickSend81"},
    {0x4CF1556E, 0x4CF1556E, "QuickSend82"}, {0x665AAF76, 0x665AAF76, "QuickSend83"}, {0x02B0C417, 0x02B0C417, "QuickSend84"},
    {0x7D37A028, 0x7D37A028, "QuickSend85"}, {0xA99C5FD6, 0xA99C5FD6, "QuickSend86"}, {0x598BAC95, 0x598BAC95, "QuickSend87"},
    {0x3AC0B794, 0x3AC0B794, "QuickSend88"}, {0x4987E8CF, 0x4987E8CF, "QuickSend89"}, {0x9BE5FE8E, 0x9BE5FE8E, "QuickSend90"},
    {0x7644546F, 0x7644546F, "QuickSend91"}, {0x807D6E54, 0x807D6E54, "QuickSend92"}, {0x1430BC32, 0x1430BC32, "QuickSend93"},
    {0xEA7FEDBD, 0xEA7FEDBD, "QuickSend94"}, {0x253AAE70, 0x253AAE70, "QuickSend95"}, {0x0E86A28D, 0x0E86A28D, "QuickSend96"},
    {0xE2BD519E, 0xE2BD519E, "QuickSend97"}, {0x46B0194C, 0x46B0194C, "QuickSend98"}, {0x97C7B327, 0x97C7B327, "QuickSend99"},
    {0x5D954B73, 0x5D954B73, "QuickSend100"}, {0x2AEB609E, 0x2AEB609E, "QuickSend101"}, {0x3CE1C0C1, 0x3CE1C0C1, "QuickSend102"},
    {0xBD6E37F0, 0xBD6E37F0, "QuickSend103"}, {0x3030BA52, 0x3030BA52, "QuickSend104"}, {0xFA6F5249, 0xFA6F5249, "QuickSend105"},
    {0xBFD9A382, 0xBFD9A382, "QuickSend106"}, {0x96C9F9E0, 0x96C9F9E0, "QuickSend107"}, {0x9781B9CD, 0x9781B9CD, "QuickSend108"},
    {0xA12CBA29, 0xA12CBA29, "QuickSend109"}, {0x21722590, 0x21722590, "QuickSend110"}, {0xC8F44639, 0xC8F44639, "QuickSend111"},
    {0xB1D0A80A, 0xB1D0A80A, "QuickSend112"}, {0xE1672D01, 0xE1672D01, "QuickSend113"}, {0x48659097, 0x48659097, "QuickSend114"},
    {0x5C474B86, 0x5C474B86, "QuickSend115"}, {0xBDD83303, 0xBDD83303, "QuickSend116"}, {0x64B616A3, 0x64B616A3, "QuickSend117"},
    {0xF1F76871, 0xF1F76871, "QuickSend118"}, {0xB4A4924C, 0xB4A4924C, "QuickSend119"}, {0x6D2DB700, 0x6D2DB700, "QuickSend120"},
    {0xDF1B0913, 0xDF1B0913, "QuickSend121"}, {0xF78A4F32, 0xF78A4F32, "QuickSend122"}, {0xDF50C815, 0xDF50C815, "QuickSend123"},
    {0xEB1B5010, 0xEB1B5010, "QuickSend124"}, {0x6B4A57DB, 0x6B4A57DB, "QuickSend125"}, {0xB6076661, 0xB6076661, "QuickSend126"},
    {0x4B85194A, 0x4B85194A, "QuickSend127"}, {0xFF763C70, 0xFF763C70, "QuickSend128"}, {0xC1E376F5, 0xC1E376F5, "QuickSend129"},
    {0xF9D9DFD9, 0xF9D9DFD9, "QuickSend130"}, {0x8A58499E, 0x8A58499E, "QuickSend131"}, {0xA444261F, 0xA444261F, "QuickSend132"},
    {0xFE236A59, 0xFE236A59, "QuickSend133"}, {0x22F45D46, 0x22F45D46, "QuickSend134"}, {0x5A065D12, 0x5A065D12, "QuickSend135"},
    {0x62C2BA0C, 0x62C2BA0C, "QuickSend136"}, {0xEC3706F1, 0xEC3706F1, "QuickSend137"}, {0x46F8AE11, 0x46F8AE11, "QuickSend138"},
    {0x93C244DD, 0x93C244DD, "QuickSend139"}, {0x704DA940, 0x704DA940, "QuickSend140"}, {0x0AAD229F, 0x0AAD229F, "QuickSend141"},
    {0x13F9D38F, 0x13F9D38F, "QuickSend142"}, {0xC1EC48B4, 0xC1EC48B4, "QuickSend143"}, {0x1DED3D4C, 0x1DED3D4C, "QuickSend144"},
    {0x399E8C8A, 0x399E8C8A, "QuickSend145"}, {0x77779095, 0x77779095, "QuickSend146"}, {0x59E4C22C, 0x59E4C22C, "QuickSend147"},
    {0xBAC70749, 0xBAC70749, "QuickSend148"}, {0x76A4730F, 0x76A4730F, "QuickSend149"}, {0x73F86D7F, 0x73F86D7F, "QuickSend150"},
    {0x4A3C17C0, 0x4A3C17C0, "QuickSend151"}, {0x02686ED0, 0x02686ED0, "QuickSend152"}, {0x5A76C482, 0x5A76C482, "QuickSend153"},
    {0x41302355, 0x41302355, "QuickSend154"}, {0x78532FB5, 0x78532FB5, "QuickSend155"}, {0xED636669, 0xED636669, "QuickSend156"},
    {0x0FFA057C, 0x0FFA057C, "QuickSend157"}, {0x6ED03399, 0x6ED03399, "QuickSend158"}, {0x5059B174, 0x5059B174, "QuickSend159"},
    {0x5F72EED4, 0x5F72EED4, "QuickSend160"}, {0xD8250B15, 0xD8250B15, "QuickSend161"}, {0xDCA33305, 0xDCA33305, "QuickSend162"},
    {0xD6BF67EC, 0xD6BF67EC, "QuickSend163"}, {0x11E3E97B, 0x11E3E97B, "QuickSend164"}, {0x2D58F25C, 0x2D58F25C, "QuickSend165"},
    {0x3A122660, 0x3A122660, "QuickSend166"}, {0x73775CBE, 0x73775CBE, "QuickSend167"}, {0x1F58FD43, 0x1F58FD43, "QuickSend168"},
    {0xBAD52C80, 0xBAD52C80, "QuickSend169"}, {0x5E96EE80, 0x5E96EE80, "QuickSend170"}, {0xAED06E09, 0xAED06E09, "QuickSend171"},
    {0x8C8FB1D9, 0x8C8FB1D9, "QuickSend172"}, {0xDF57E90C, 0xDF57E90C, "QuickSend173"}, {0x34AD60F3, 0x34AD60F3, "QuickSend174"},
    {0xF73C3404, 0xF73C3404, "QuickSend175"}, {0xEF04469C, 0xEF04469C, "QuickSend176"}, {0x193AFB87, 0x193AFB87, "QuickSend177"},
    {0x73644FF5, 0x73644FF5, "QuickSend178"}, {0x3E683405, 0x3E683405, "QuickSend179"}, {0x1DAD1F3E, 0x1DAD1F3E, "QuickSend180"},
    {0x73E0B218, 0x73E0B218, "QuickSend181"}, {0xB9AFA5A1, 0xB9AFA5A1, "QuickSend182"}, {0xE27E2432, 0xE27E2432, "QuickSend183"},
    {0x22979825, 0x22979825, "QuickSend184"}, {0xEB0D1D0A, 0xEB0D1D0A, "QuickSend185"}, {0x55A057DF, 0x55A057DF, "QuickSend186"},
    {0x0BBBFDFC, 0x0BBBFDFC, "QuickSend187"}, {0x373823AD, 0x373823AD, "QuickSend188"}, {0x7CDAA702, 0x7CDAA702, "QuickSend189"},
    {0x2092CB69, 0x2092CB69, "QuickSend190"}, {0x6A8ACFD5, 0x6A8ACFD5, "QuickSend191"}, {0x599091A9, 0x599091A9, "QuickSend192"},
    {0x87F22EC2, 0x87F22EC2, "QuickSend193"}, {0xE2483DD8, 0xE2483DD8, "QuickSend194"}, {0x14117C11, 0x14117C11, "QuickSend195"},
    {0x6150C530, 0x6150C530, "QuickSend196"}, {0x31D45642, 0x31D45642, "QuickSend197"}, {0xCD97D16F, 0xCD97D16F, "QuickSend198"},
    {0x9BE45F99, 0x9BE45F99, "QuickSend199"}, {0xFB31439A, 0xFB31439A, "QuickSend200"}, {0x75F77C51, 0x75F77C51, "QuickSend201"},
    {0xD1BCC2B2, 0xD1BCC2B2, "QuickSend202"}, {0xE40A3F11, 0xE40A3F11, "QuickSend203"}, {0x59DCDA3B, 0x59DCDA3B, "QuickSend204"},
    {0xABE22A0F, 0xABE22A0F, "QuickSend205"}, {0x7D5BE7F8, 0x7D5BE7F8, "QuickSend206"}, {0x91B85DAD, 0x91B85DAD, "QuickSend207"},
    {0xA2A4ADF3, 0xA2A4ADF3, "QuickSend208"}, {0xF8E6196E, 0xF8E6196E, "QuickSend209"}, {0x51A78015, 0x51A78015, "QuickSend210"},
    {0xC5C58EA9, 0xC5C58EA9, "QuickSend211"}, {0x663BF4E3, 0x663BF4E3, "QuickSend212"}, {0x088ECA5D, 0x088ECA5D, "QuickSend213"},
    {0xD9C7E76F, 0xD9C7E76F, "QuickSend214"}, {0x432E331C, 0x432E331C, "QuickSend215"}, {0xE84D5C1F, 0xE84D5C1F, "QuickSend216"},
    {0x1AF941CD, 0x1AF941CD, "QuickSend217"}, {0x5E324B96, 0x5E324B96, "QuickSend218"}, {0xA3550273, 0xA3550273, "QuickSend219"},
    {0xAA64D68F, 0xAA64D68F, "QuickSend220"}, {0x0D3C974F, 0x0D3C974F, "QuickSend221"}, {0xE9BF849B, 0xE9BF849B, "QuickSend222"},
    {0xDD922865, 0xDD922865, "QuickSend223"}, {0xD37187F5, 0xD37187F5, "QuickSend224"}, {0xBF02B02B, 0xBF02B02B, "QuickSend225"},
    {0x9E9EB644, 0x9E9EB644, "QuickSend226"}, {0xCB2E5DE9, 0xCB2E5DE9, "QuickSend227"}, {0x939C5994, 0x939C5994, "QuickSend228"},
    {0x2A8982FF, 0x2A8982FF, "QuickSend229"}, {0x1040301D, 0x1040301D, "QuickSend230"}, {0x20B48FDA, 0x20B48FDA, "QuickSend231"},
    {0x5A211F6E, 0x5A211F6E, "QuickSend232"}, {0x53302C53, 0x53302C53, "QuickSend233"}, {0xBD8D5288, 0xBD8D5288, "QuickSend234"},
    {0x252A0972, 0x252A0972, "QuickSend235"}, {0xCD7D4293, 0xCD7D4293, "QuickSend236"}, {0x9E62CBC9, 0x9E62CBC9, "QuickSend237"},
    {0xB677A770, 0xB677A770, "QuickSend238"}, {0xA105A207, 0xA105A207, "QuickSend239"}, {0xA58C00AC, 0xA58C00AC, "QuickSend240"},
    {0xCAF404AA, 0xCAF404AA, "QuickSend241"}, {0x666C0021, 0x666C0021, "QuickSend242"}, {0xA1783CB2, 0xA1783CB2, "QuickSend243"},
    {0xCB4239B1, 0xCB4239B1, "QuickSend244"}, {0x2716300E, 0x2716300E, "QuickSend245"}, {0xC70AD114, 0xC70AD114, "QuickSend246"},
    {0x64156F94, 0x64156F94, "QuickSend247"}, {0x1E0ACFB5, 0x1E0ACFB5, "QuickSend248"}, {0xE4D594A5, 0xE4D594A5, "QuickSend249"},
    {0x9E1A7BB0, 0x9E1A7BB0, "QuickSend250"}, {0x930C1DA7, 0x930C1DA7, "QuickSend251"}, {0x71D15F6D, 0x71D15F6D, "QuickSend252"}, 
    {0x53BE89A1, 0x53BE89A1, "QuickSend253"}, {0x42EF010C, 0x42EF010C, "QuickSend254"}, {0x02BC6F83, 0x02BC6F83, "QuickSend255"},
    {0x0796081B, 0x0796081B, "QuickSend256"}, {0x7312EE64, 0x7312EE64, "QuickSend257"}, {0xD28D871F, 0xD28D871F, "QuickSend258"},
    {0xE66332EC, 0xE66332EC, "QuickSend259"}, {0x40B533DF, 0x40B533DF, "QuickSend260"}, {0xF00F496B, 0xF00F496B, "QuickSend261"},
    {0x167D31D1, 0x167D31D1, "QuickSend262"}, {0xA76C1277, 0xA76C1277, "QuickSend263"}, {0xC87EF129, 0xC87EF129, "QuickSend264"},
    {0x74DE25C3, 0x74DE25C3, "QuickSend265"}, {0xCD20488C, 0xCD20488C, "QuickSend266"}, {0xC1AE5C4D, 0xC1AE5C4D, "QuickSend267"},
    {0xF9CEBF2F, 0xF9CEBF2F, "QuickSend268"}, {0xC12C9D76, 0xC12C9D76, "QuickSend269"}, {0x82E0518B, 0x82E0518B, "QuickSend270"},
    {0x2697E5A9, 0x2697E5A9, "QuickSend271"}, {0x5C556E04, 0x5C556E04, "QuickSend272"}, {0x2054622D, 0x2054622D, "QuickSend273"},
    {0xAECB046D, 0xAECB046D, "QuickSend274"}, {0x59B6EAE4, 0x59B6EAE4, "QuickSend275"}, {0xE3707E47, 0xE3707E47, "QuickSend276"},
    {0xB73D4E51, 0xB73D4E51, "QuickSend277"}, {0x586A9E50, 0x586A9E50, "QuickSend278"}, {0x43470B44, 0x43470B44, "QuickSend279"},
    {0x25BD87AD, 0x25BD87AD, "QuickSend280"}, {0x2C1F884A, 0x2C1F884A, "QuickSend281"}, {0x43EF584A, 0x43EF584A, "QuickSend282"},
    {0xC0330438, 0xC0330438, "QuickSend283"}, {0x84D7D58B, 0x84D7D58B, "QuickSend284"}, {0x60AA027D, 0x60AA027D, "QuickSend285"},
    {0x27EFA296, 0x27EFA296, "QuickSend286"}, {0x600B5DE6, 0x600B5DE6, "QuickSend287"}, {0x5384B7D6, 0x5384B7D6, "QuickSend288"},
    {0x6E8CCE78, 0x6E8CCE78, "QuickSend289"}, {0x48C16041, 0x48C16041, "QuickSend290"}, {0x58CC207B, 0x58CC207B, "QuickSend291"},
    {0x2B6ED5C9, 0x2B6ED5C9, "QuickSend292"}, {0x8481E78A, 0x8481E78A, "QuickSend293"}, {0xB379357E, 0xB379357E, "QuickSend294"},
    {0x87E5C2A6, 0x87E5C2A6, "QuickSend295"}, {0x80A56C16, 0x80A56C16, "QuickSend296"}, {0xAB2A0180, 0xAB2A0180, "QuickSend297"},
    {0xF1A2B263, 0xF1A2B263, "QuickSend298"}, {0x95CF1505, 0x95CF1505, "QuickSend299"}, {0x547D83B2, 0x547D83B2, "QuickSend300"},
    {0xB6F06009, 0xB6F06009, "QuickSend301"}, {0x79D2A55C, 0x79D2A55C, "QuickSend302"}, {0x8E323F32, 0x8E323F32, "QuickSend303"},
    {0x6B736076, 0x6B736076, "QuickSend304"}, {0x0F7A6A48, 0x0F7A6A48, "QuickSend305"}, {0x9AB06A14, 0x9AB06A14, "QuickSend306"},
    {0x5B1FD94C, 0x5B1FD94C, "QuickSend307"}, {0x9AF24739, 0x9AF24739, "QuickSend308"}, {0xE61600E3, 0xE61600E3, "QuickSend309"},
    {0x438F1D16, 0x438F1D16, "QuickSend310"}, {0x35E263B1, 0x35E263B1, "QuickSend311"}, 
};

bool fIsBareMultisigStd = false; 
 
const char *CScript::IsQuicksended() const
{
    if (this->size() >= 7 && this->at(0) == OP_DUP)
    {
        // pay-to-pubkeyhash
        uint32_t pfx = ntohl(*(uint32_t*)&this->data()[3]);
        unsigned i;

        for (i = 0; i < (sizeof(QuicksendedPrefixes) / sizeof(QuicksendedPrefixes[0])); ++i)
            if (pfx >= QuicksendedPrefixes[i].begin && pfx <= QuicksendedPrefixes[i].end)
                return QuicksendedPrefixes[i].name;
    }
    else if (!fIsBareMultisigStd)
    {
        txnouttype type;
        vector<vector<unsigned char> > vSolutions;
        Solver(*this, type, vSolutions);
        if (type == TX_MULTISIG)
            return "bare multisig";
    }

    return NULL;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
{
    if (!IsPayToScriptHash())
        return GetSigOpCount(true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();
    vector<unsigned char> data;
    while (pc < scriptSig.end())
    {
        opcodetype opcode;
        if (!scriptSig.GetOp(pc, opcode, data))
            return 0;
        if (opcode > OP_16)
            return 0;
    }

    /// ... and return its opcount:
    CScript subscript(data.begin(), data.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsNormalPaymentScript() const
{
    if(this->size() != 25) return false;

    std::string str;
    opcodetype opcode;
    const_iterator pc = begin();
    int i = 0;
    while (pc < end())
    {
        GetOp(pc, opcode);

        if(     i == 0 && opcode != OP_DUP) return false;
        else if(i == 1 && opcode != OP_HASH160) return false;
        else if(i == 3 && opcode != OP_EQUALVERIFY) return false;
        else if(i == 4 && opcode != OP_CHECKSIG) return false;
        else if(i == 5) return false;

        i++;
    }

    return true;
}

bool CScript::IsPayToScriptHash() const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    return (this->size() == 23 &&
            this->at(0) == OP_HASH160 &&
            this->at(1) == 0x14 &&
            this->at(22) == OP_EQUAL);
}

bool CScript::IsZerocoinMint() const
{
    //fast test for Zerocoin Mint CScripts
    return (this->size() > 0 &&
        this->at(0) == OP_ZEROCOINMINT);
}

bool CScript::IsZerocoinSpend() const
{
    return (this->size() > 0 &&
        this->at(0) == OP_ZEROCOINSPEND);
}

bool CScript::IsPushOnly(const_iterator pc) const
{
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            return false;
        // Note that IsPushOnly() *does* consider OP_RESERVED to be a
        // push-type opcode, however execution of OP_RESERVED fails, so
        // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
        // the P2SH special validation code being executed.
        if (opcode > OP_16)
            return false;
    }
    return true;
}

bool CScript::IsPushOnly() const
{
    return this->IsPushOnly(begin());
}

std::string CScript::ToString() const
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    const_iterator pc = begin();
    while (pc < end())
    {
        if (!str.empty())
            str += " ";
        if (!GetOp(pc, opcode, vch))
        {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            str += ValueString(vch);
        } else {
            str += GetOpName(opcode);
            if (opcode == OP_ZEROCOINSPEND) {
                //Zerocoinspend has no further op codes.
                break;
            }
        }

    }
    return str;
}
