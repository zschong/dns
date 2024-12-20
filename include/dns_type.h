#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


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

const char* dns_type_name(dns_type_t qtype);

#ifdef __cplusplus
}
#endif