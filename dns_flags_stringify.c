#include <stdint.h>
#include <stdio.h>

#include "dns_flags.h"
#include "dns_binstring.h"

/**
 * @brief 获取QR标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含QR标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_qr(uint16_t flags, char *buf, uint32_t buf_size)
{
    if (NULL == buf || buf_size < 1) {
        return NULL;
    }
    int qr = dns_flags_get_qr(flags);
    snprintf(buf, buf_size, "QR    : %d - %s", qr, qr ? "Response" : "Query");
    return buf;
}

/**
 * @brief 获取OPCODE标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含OPCODE标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_opcode(uint16_t flags, char *buf, uint32_t buf_size)
{
    if (NULL == buf || buf_size < 1) {
        return NULL;
    }
    dns_opcode_t opcode = dns_flags_get_opcode(flags);
    const char *opcode_desc;
    switch (opcode) {
    case DNS_OPCODE_QUERY:
        opcode_desc = "Standard Query";
        break;
    case DNS_OPCODE_IQUERY:
        opcode_desc = "Inverse Query";
        break;
    case DNS_OPCODE_STATUS:
        opcode_desc = "Server Status Request";
        break;
    case DNS_OPCODE_NOTIFY:
        opcode_desc = "Zone Change Notification";
        break;
    case DNS_OPCODE_UPDATE:
        opcode_desc = "Zone Update Message";
        break;
    default:
        opcode_desc = "Reserved";
        break;
    }
    snprintf(buf, buf_size, "OPCODE: %d - %s", opcode, opcode_desc);
    return buf;
}

/**
 * @brief 获取AA标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含AA标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_aa(uint16_t flags, char *buf, uint32_t buf_size)
{
    if (NULL == buf || buf_size < 1) {
        return NULL;
    }
    int aa = dns_flags_get_aa(flags);
    snprintf(buf, buf_size, "AA    : %d - %s", aa, aa ? "Authoritative Answer" : "Not Authoritative");
    return buf;
}

/**
 * @brief 获取TC标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含TC标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_tc(uint16_t flags, char *buf, uint32_t buf_size)
{
    if (NULL == buf || buf_size < 1) {
        return NULL;
    }
    int tc = dns_flags_get_tc(flags);
    snprintf(buf, buf_size, "TC    : %d - %s", tc, tc ? "Truncated" : "Not Truncated");
    return buf;
}

/**
 * @brief 获取RD标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含RD标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_rd(uint16_t flags, char *buf, uint32_t buf_size)
{
    if (NULL == buf || buf_size < 1) {
        return NULL;
    }

    int rd = dns_flags_get_rd(flags);
    snprintf(buf, buf_size, "RD    : %d - %s", rd, rd ? "Recursion Desired" : "Recursion Not Desired");
    return buf;
}

/**
 * @brief 获取RA标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含RA标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_ra(uint16_t flags, char *buf, uint32_t buf_size)
{
    if (NULL == buf || buf_size < 1) {
        return NULL;
    }

    int ra = dns_flags_get_ra(flags);
    snprintf(buf, buf_size, "RA    : %d - %s", ra, ra ? "Recursion Available" : "Recursion Not Available");
    return buf;
}

/**
 * @brief 获取RCODE标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含RCODE标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_rcode(uint16_t flags, char *buf, uint32_t buf_size)
{
    if (NULL == buf || buf_size < 1) {
        return NULL;
    }

    int         rcode = dns_flags_get_rcode(flags);
    const char *rcode_desc = NULL;
    switch (rcode) {
    case DNS_RCODE_NOERROR:
        rcode_desc = "No Error";
        break;
    case DNS_RCODE_FORMERR:
        rcode_desc = "Format Error";
        break;
    case DNS_RCODE_SERVFAIL:
        rcode_desc = "Server Failure";
        break;
    case DNS_RCODE_NXDOMAIN:
        rcode_desc = "Name Error";
        break;
    case DNS_RCODE_NOTIMP:
        rcode_desc = "Not Implemented";
        break;
    case DNS_RCODE_REFUSED:
        rcode_desc = "Refused";
        break;
    case DNS_RCODE_YXDOMAIN:
        rcode_desc = "YXDomain";
        break;
    case DNS_RCODE_YXRRSET:
        rcode_desc = "YXRRSet";
        break;
    case DNS_RCODE_NXRRSET:
        rcode_desc = "NXRRSet";
        break;
    case DNS_RCODE_NOTAUTH:
        rcode_desc = "NotAuth";
        break;
    case DNS_RCODE_NOTZONE:
        rcode_desc = "NotZone";
        break;
    default:
        rcode_desc = "Reserved";
        break;
    }
    snprintf(buf, buf_size, "RCODE : %d - %s", rcode, rcode_desc);
    return buf;
}

const char *dns_flags_to_string(uint16_t flags, char *buf, uint32_t buf_size)
{
    if (NULL == buf || buf_size < 1) {
        return NULL;
    }

    char qr_buf[32];
    char opcode_buf[32];
    char aa_buf[32];
    char tc_buf[32];
    char rd_buf[32];
    char ra_buf[32];
    char rcode_buf[32];
    char binstr[32];

    snprintf(buf,
             buf_size,
             "dns_flags: 0x%04X=[%s] {QR(1)|opcode(4)|AA(1)|TC(1)|RD(1)|RA(1)|zero(3)|rcode(4)}\n"
             "  %s\n" // QR
             "  %s\n" // OPCODE
             "  %s\n" // AA
             "  %s\n" // TC
             "  %s\n" // RD
             "  %s\n" // RA
             "  %s\n", // RCODE
             flags,
             dns_value_binstring((uint8_t*)&flags, sizeof(flags), binstr, sizeof(binstr)),
             dns_flags_stringify_qr    (flags, qr_buf    , sizeof(qr_buf    )),
             dns_flags_stringify_opcode(flags, opcode_buf, sizeof(opcode_buf)),
             dns_flags_stringify_aa    (flags, aa_buf    , sizeof(aa_buf    )),
             dns_flags_stringify_tc    (flags, tc_buf    , sizeof(tc_buf    )),
             dns_flags_stringify_rd    (flags, rd_buf    , sizeof(rd_buf    )),
             dns_flags_stringify_ra    (flags, ra_buf    , sizeof(ra_buf    )),
             dns_flags_stringify_rcode (flags, rcode_buf , sizeof(rcode_buf )));
    return buf;
}

#ifdef DNS_FLAGS_STRINGIFY_TEST
int main()
{
    uint16_t flags = 0x8180;
    char     buf[256];

    dns_flags_set_qr    (&flags, 1);
    dns_flags_set_opcode(&flags, 0);
    dns_flags_set_aa    (&flags, 1);
    dns_flags_set_rd    (&flags, 1);
    dns_flags_set_ra    (&flags, 1);
    dns_flags_set_rcode (&flags, 0);
    dns_flags_to_string(flags, buf, sizeof(buf));

    printf("%s\n", buf);

    return 0;
}
#endif  // DNS_FLAGS_STRINGIFY_TEST
