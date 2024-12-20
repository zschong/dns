#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "dns_flags.h"

/**
 * @brief 设置QR标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param qr: QR值，0表示查询报文，1表示响应报文
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_qr(uint16_t *flags, int qr)
{
    if (NULL == flags || (qr != 0 && qr != 1)) {
        return false;
    }
    *flags = (qr << DNS_FLAGS_INDEX_QR) | (*flags & ~(1 << DNS_FLAGS_INDEX_QR));
    return true;
}

/**
 * @brief 设置OPCODE标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param opcode: OPCODE值，0-15，表示不同的操作码
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_opcode(uint16_t *flags, int opcode)
{
    if (NULL == flags || opcode < 0 || opcode > 15) {
        return false;
    }
    *flags = (opcode << DNS_FLAGS_INDEX_OPCODE) | (*flags & ~(0xF << DNS_FLAGS_INDEX_OPCODE));
    return true;
}

/**
 * @brief 设置AA标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param aa: AA值，0表示非权威回答，1表示权威回答
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_aa(uint16_t *flags, int aa)
{
    if (NULL == flags || (aa != 0 && aa != 1)) {
        return false;
    }
    *flags = (aa << DNS_FLAGS_INDEX_AA) | (*flags & ~(1 << DNS_FLAGS_INDEX_AA));
    return true;
}

/**
 * @brief 设置TC标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param tc: TC值，0表示未截断，1表示已截断
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_tc(uint16_t *flags, int tc)
{
    if (NULL == flags || (tc != 0 && tc != 1)) {
        return false;
    }
    *flags = (tc << DNS_FLAGS_INDEX_TC) | (*flags & ~(1 << DNS_FLAGS_INDEX_TC));
    return true;
}

/**
 * @brief 设置RD标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param rd: RD值，0表示不希望递归，1表示希望递归
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_rd(uint16_t *flags, int rd)
{
    if (NULL == flags || (rd != 0 && rd != 1)) {
        return false;
    }
    *flags = (rd << DNS_FLAGS_INDEX_RD) | (*flags & ~(1 << DNS_FLAGS_INDEX_RD));
    return true;
}

/**
 * @brief 设置RA标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param ra: RA值，0表示递归不可用，1表示递归可用
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_ra(uint16_t *flags, int ra)
{
    if (NULL == flags || (ra != 0 && ra != 1)) {
        return false;
    }
    *flags = (ra << DNS_FLAGS_INDEX_RA) | (*flags & ~(1 << DNS_FLAGS_INDEX_RA));
    return true;
}

/**
 * @brief 设置RCODE标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param rcode: RCODE值，0-15，表示响应状态码
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_rcode(uint16_t *flags, int rcode)
{
    if (NULL == flags || rcode < 0 || rcode > 15) {
        return false;
    }
    *flags = rcode | (*flags & ~0xF);
    return true;
}
