# dns_type_name
```c
#include <stdio.h>

typedef enum {
    DNS_TYPE_A          = 1 , // IPv4地址
    DNS_TYPE_NS         = 2 , // 名称服务器
    DNS_TYPE_MD         = 3 , // 主DNS服务器（已弃用）
    DNS_TYPE_MF         = 4 , // 主邮件服务器（已弃用）
    DNS_TYPE_CNAME      = 5 , // 别名
    DNS_TYPE_SOA        = 6 , // 开始授权
    DNS_TYPE_MB         = 7 , // 主机信息（实验性）
    DNS_TYPE_MG         = 8 , // 邮件组（实验性）
    DNS_TYPE_MR         = 9 , // 邮件重命名（实验性）
    DNS_TYPE_NULL       = 10, // 空记录（实验性）
    DNS_TYPE_WKS        = 11, // 熟知服务
    DNS_TYPE_PTR        = 12, // 指针记录
    DNS_TYPE_HINFO      = 13, // 主机信息
    DNS_TYPE_MINFO      = 14, // 邮件信息
    DNS_TYPE_MX         = 15, // 邮件交换记录
    DNS_TYPE_TXT        = 16, // 文本记录
    DNS_TYPE_RP         = 17, // 负责人记录（实验性）
    DNS_TYPE_AFSDB      = 18, // AFS数据库位置
    DNS_TYPE_X25        = 19, // X.25地址（实验性）
    DNS_TYPE_ISDN       = 20, // ISDN地址（实验性）
    DNS_TYPE_RT         = 21, // 路由通过记录（实验性）
    DNS_TYPE_NSAP       = 22, // NSAP地址（实验性）
    DNS_TYPE_NSAP_PTR   = 23, // NSAP指针（实验性）
    DNS_TYPE_SIG        = 24, // 签名
    DNS_TYPE_KEY        = 25, // 密钥记录
    DNS_TYPE_PX         = 26, // 映射记录（实验性）
    DNS_TYPE_GPOS       = 27, // 地理位置记录（实验性）
    DNS_TYPE_AAAA       = 28, // IPv6地址
    DNS_TYPE_LOC        = 29, // 地理位置记录
    DNS_TYPE_NXT        = 30, // 下一个记录（已弃用）
    DNS_TYPE_EID        = 31, // 端点标识符（实验性）
    DNS_TYPE_NIMLOC     = 32, // NIMLOC记录（实验性）
    DNS_TYPE_SRV        = 33, // 服务定位记录
    DNS_TYPE_ATMA       = 34, // ATM地址（实验性）
    DNS_TYPE_NAPTR      = 35, // 名称权限指针
    DNS_TYPE_KX         = 36, // 密钥交换记录
    DNS_TYPE_CERT       = 37, // 证书记录
    DNS_TYPE_A6         = 38, // IPv6地址（已弃用）
    DNS_TYPE_DNAME      = 39, // DNAME记录
    DNS_TYPE_SINK       = 40, // SINK记录（实验性）
    DNS_TYPE_OPT        = 41, // 选项（EDNS）
    DNS_TYPE_APL        = 42, // 地址前缀列表（实验性）
    DNS_TYPE_DS         = 43, // 委派签名
    DNS_TYPE_SSHFP      = 44, // SSH密钥指纹
    DNS_TYPE_IPSECKEY   = 45, // IPsec密钥
    DNS_TYPE_RRSIG      = 46, // RRSIG记录
    DNS_TYPE_NSEC       = 47, // NSEC记录
    DNS_TYPE_DNSKEY     = 48, // DNS密钥记录
    DNS_TYPE_DHCID      = 49, // DHCP标识符
    DNS_TYPE_NSEC3      = 50, // NSEC3记录
    DNS_TYPE_NSEC3PARAM = 51,// NSEC3参数
    DNS_TYPE_TLSA       = 52, // TLSA记录
    DNS_TYPE_SVCB       = 64, // SVCB记录
    DNS_TYPE_HTTPS      = 65, // HTTPS记录
    DNS_TYPE_SPF        = 99, // SPF
} dns_type_t;

const char* dns_type_name(int qtype) {
    switch (qtype) {
        case 1:
            return "A (Address answer)";
        case 2:
            return "NS (Name server answer)";
        case 5:
            return "CNAME (Canonical name answer)";
        case 6:
            return "SOA (Start of Authority answer)";
        case 12:
            return "PTR (Pointer answer)";
        case 15:
            return "MX (Mail exchange answer)";
        case 16:
            return "TXT (Text answer)";
        case 28:
            return "AAAA (IPv6 address answer)";
        case 33:
            return "SRV (Service answer)";
        case 35:
            return "NAPTR (Naming Authority Pointer answer)";
        case 39:
            return "DNAME (Delegation Name answer)";
        case 44:
            return "OPT (Option answer)";
        case 47:
            return "SSHFP (SSH Public Key Fingerprint answer)";
        case 50:
            return "NSEC (Next Secure answer)";
        case 51:
            return "DNSKEY (DNS Key answer)";
        case 52:
            return "DHCID (DHCP Identifier answer)";
        case 53:
            return "NSEC3 (Next Secure answer version 3)";
        case 54:
            return "NSEC3PARAM (NSEC3 Parameters answer)";
        case 55:
            return "TLSA (TLSA certificate association answer)";
        case 65:
            return "HIP (Host Identity Protocol answer)";
        case 99:
            return "SPF (Sender Policy Framework answer)";
        case 108:
            return "EUI48 (MAC address (EUI-48) answer)";
        case 109:
            return "EUI64 (MAC address (EUI-64) answer)";
        case 249:
            return "TKEY (Transaction Key answer)";
        case 250:
            return "TSIG (Transaction Signature answer)";
        case 252:
            return "AXFR (Authoritative Zone Transfer answer)";
        case 253:
            return "MAILB (Mailbox answer)";
        case 254:
            return "MAILA (Mail Agent answer)";
        case 255:
            return "ANY (Any answer)";
        case 256:
            return "URI (Uniform Resource Identifier answer)";
        case 257:
            return "CAA (Certification Authority Authorization answer)";
        case 32768:
            return "TA (DNSSEC Trust Authorities answer)";
        case 32769:
            return "DLV (DNSSEC Lookaside Validation answer)";
        default:
            return "UNKNOWN (Unknown answer type)";
    }
}
```