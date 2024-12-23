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
bool dns_flags_set_qr(uint16_t *flags, dns_qr_t qr)
{
    if (NULL == flags) {
        return false;
    }

    switch (qr) {
    case DNS_QR_QUERY:
    case DNS_QR_RESPONSE:
        *flags &= ~(1 << DNS_FLAGS_INDEX_QR);
        *flags |= (qr << DNS_FLAGS_INDEX_QR);
        break;
    default:
        return false;
    }
    
    // *flags = (qr << DNS_FLAGS_INDEX_QR) | (*flags & ~(1 << DNS_FLAGS_INDEX_QR));
    return true;
}

/**
 * @brief 设置OPCODE标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param opcode: OPCODE值，0-15，表示不同的操作码
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_opcode(uint16_t *flags, dns_opcode_t opcode)
{
    if (NULL == flags) {
        return false;
    }

    switch(opcode) {
    case DNS_OPCODE_QUERY:
    case DNS_OPCODE_IQUERY:
    case DNS_OPCODE_STATUS:
    case DNS_OPCODE_NOTIFY:
    case DNS_OPCODE_UPDATE:
        *flags &= ~(0xF << DNS_FLAGS_INDEX_OPCODE);
        *flags |= (opcode << DNS_FLAGS_INDEX_OPCODE);
        break;
    default:
        return false;
    }

    // *flags = (opcode << DNS_FLAGS_INDEX_OPCODE) | (*flags & ~(0xF << DNS_FLAGS_INDEX_OPCODE));
    return true;
}

/**
 * @brief 设置AA标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param aa: AA值，0表示非权威回答，1表示权威回答
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_aa(uint16_t *flags, dns_aa_t aa)
{
    if (NULL == flags) {
        return false;
    }

    switch (aa) {
    case DNS_AA_NO:
    case DNS_AA_YES:
        *flags &= ~(1 << DNS_FLAGS_INDEX_AA);
        *flags |= (aa << DNS_FLAGS_INDEX_AA);
        break;
    default:
        return false;
    }

    // *flags = (aa << DNS_FLAGS_INDEX_AA) | (*flags & ~(1 << DNS_FLAGS_INDEX_AA));
    return true;
}

/**
 * @brief 设置TC标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param tc: TC值，0表示未截断，1表示已截断
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_tc(uint16_t *flags, dns_tc_t tc)
{
    if (NULL == flags) {
        return false;
    }

    switch (tc) {
    case DNS_TC_NO:
    case DNS_TC_YES:
        *flags &= ~(1 << DNS_FLAGS_INDEX_TC);
        *flags |= (tc << DNS_FLAGS_INDEX_TC);
        break;
    default:
        return false;
    }

    // *flags = (tc << DNS_FLAGS_INDEX_TC) | (*flags & ~(1 << DNS_FLAGS_INDEX_TC));
    return true;
}

/**
 * @brief 设置RD标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param rd: RD值，0表示不希望递归，1表示希望递归
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_rd(uint16_t *flags, dns_rd_t rd)
{
    if (NULL == flags) {
        return false;
    }

    switch(rd) {
        case DNS_RD_NO:
        case DNS_RD_YES:
            *flags &= ~(1 << DNS_FLAGS_INDEX_RD);
            *flags |= (rd << DNS_FLAGS_INDEX_RD);
            break;
        default:
            return false;
    }
    // *flags = (rd << DNS_FLAGS_INDEX_RD) | (*flags & ~(1 << DNS_FLAGS_INDEX_RD));
    return true;
}

/**
 * @brief 设置RA标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param ra: RA值，0表示递归不可用，1表示递归可用
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_ra(uint16_t *flags, dns_ra_t ra)
{
    if (NULL == flags) {
        return false;
    }

    switch(ra) {
        case DNS_RA_NO:
        case DNS_RA_YES:
            *flags &= ~(1 << DNS_FLAGS_INDEX_RA);
            *flags |= (ra << DNS_FLAGS_INDEX_RA);
            break;
        default:
            return false;
    }

    return true;
    // *flags = (ra << DNS_FLAGS_INDEX_RA) | (*flags & ~(1 << DNS_FLAGS_INDEX_RA));
}

/**
 * @brief 设置RCODE标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param rcode: RCODE值，0-15，表示响应状态码
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_rcode(uint16_t *flags, dns_rcode_t rcode)
{
    if (NULL == flags) {
        return false;
    }

    switch(rcode) {
        case DNS_RCODE_NOERROR:
        case DNS_RCODE_FORMERR:
        case DNS_RCODE_SERVFAIL:
        case DNS_RCODE_NXDOMAIN:
        case DNS_RCODE_NOTIMP:
        case DNS_RCODE_REFUSED:
        case DNS_RCODE_YXDOMAIN:
        case DNS_RCODE_YXRRSET:
        case DNS_RCODE_NXRRSET:
        case DNS_RCODE_NOTAUTH:
        case DNS_RCODE_NOTZONE:
        case DNS_RCODE_BADSIG:
            *flags = rcode | (*flags & ~0xF);
             return true;
        default:
            return false;
    }
}
