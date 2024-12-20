#include "dns_flags.h"

/**
 * @brief 获取QR标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: QR值，0表示查询报文，1表示响应报文
 */
int dns_flags_get_qr(uint16_t flags)
{
    return (flags >> DNS_FLAGS_INDEX_QR) & 0x01;
}

/**
 * @brief 获取OPCODE标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: OPCODE值，0-15，表示不同的操作码
 */
int dns_flags_get_opcode(uint16_t flags)
{
    return (flags >> DNS_FLAGS_INDEX_OPCODE) & 0x0F;
}

/**
 * @brief 获取AA标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: AA值，0表示非权威回答，1表示权威回答
 */
int dns_flags_get_aa(uint16_t flags)
{
    return (flags >> DNS_FLAGS_INDEX_AA) & 0x01;
}

/**
 * @brief 获取TC标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: TC值，0表示未截断，1表示已截断
 */
int dns_flags_get_tc(uint16_t flags)
{
    return (flags >> DNS_FLAGS_INDEX_TC) & 0x01;
}

/**
 * @brief 获取RD标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: RD值，0表示不希望递归，1表示希望递归
 */
int dns_flags_get_rd(uint16_t flags)
{
    return (flags >> DNS_FLAGS_INDEX_RD) & 0x01;
}

/**
 * @brief 获取RA标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: RA值，0表示递归不可用，1表示递归可用
 */
int dns_flags_get_ra(uint16_t flags)
{
    return (flags >> DNS_FLAGS_INDEX_RA) & 0x01;
}

/**
 * @brief 获取RCODE标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: RCODE值，0-15，表示响应状态码
 */
int dns_flags_get_rcode(uint16_t flags)
{
    return flags & 0x0F;
}

#ifdef DNS_FLAGS_GET_TEST
int main()
{
    uint16_t flags = 0x8180;  // 假设标志位为1000 0001 1000 0000

    printf("QR    : %d\n", dns_flags_get_qr(flags));
    printf("OPCODE: %d\n", dns_flags_get_opcode(flags));
    printf("AA    : %d\n", dns_flags_get_aa(flags));
    printf("TC    : %d\n", dns_flags_get_tc(flags));
    printf("RD    : %d\n", dns_flags_get_rd(flags));
    printf("RA    : %d\n", dns_flags_get_ra(flags));
    printf("RCODE : %d\n", dns_flags_get_rcode(flags));

    return 0;
}
#endif
