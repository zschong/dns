#pragma once
#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief DNS 标志位分布
 * +-----+---------+-----+-----+-----+-----+-------+--------+
 * |QR(1)|opcode(4)|AA(1)|TC(1)|RD(1)|RA(1)|zero(3)|rcode(4)|
 * +-----+---------+-----+-----+-----+-----+-------+--------+
 */

typedef enum {
    DNS_FLAGS_INDEX_QR     = 15,
    DNS_FLAGS_INDEX_OPCODE = 11,
    DNS_FLAGS_INDEX_AA     = 10,
    DNS_FLAGS_INDEX_TC     = 9 ,
    DNS_FLAGS_INDEX_RD     = 8 ,
    DNS_FLAGS_INDEX_RA     = 7 ,
    DNS_FLAGS_INDEX_ZERO   = 4 ,
    DNS_FLAGS_INDEX_RCODE  = 0
} dns_flags_index_t;

/**
 * @brief QR标志位
 * @param DNS_QR_QUERY   : 查询报文
 * @param DNS_QR_RESPONSE: 响应报文
 */
typedef enum {
    DNS_QR_QUERY    = 0,
    DNS_QR_RESPONSE = 1
} dns_qr_t;

/**
 * @brief OPCODE标志位
 * @param DNS_OPCODE_QUERY : 查询
 * @param DNS_OPCODE_IQUERY: 反向查询
 * @param DNS_OPCODE_STATUS: 状态查询
 * @param DNS_OPCODE_NOTIFY: 通知
 * @param DNS_OPCODE_UPDATE: 更新
 */
typedef enum {
    DNS_OPCODE_QUERY  = 0,
    DNS_OPCODE_IQUERY = 1,
    DNS_OPCODE_STATUS = 2,
    DNS_OPCODE_NOTIFY = 4,
    DNS_OPCODE_UPDATE = 5
} dns_opcode_t;

/**
 * @brief RCODE标志位
 * @param DNS_RCODE_NOERROR : 无错误
 * @param DNS_RCODE_FORMERR : 格式错误
 * @param DNS_RCODE_SERVFAIL: 服务器失败
 * @param DNS_RCODE_NXDOMAIN: 域名不存在
 * @param DNS_RCODE_NOTIMP  : 未实现
 * @param DNS_RCODE_REFUSED : 拒绝
 * @param DNS_RCODE_YXDOMAIN: 域名存在
 * @param DNS_RCODE_YXRRSET : RR集存在
 * @param DNS_RCODE_NXRRSET : RR集不存在
 * @param DNS_RCODE_NOTAUTH : 未授权
 * @param DNS_RCODE_NOTZONE : 不在区域
 * @param DNS_RCODE_BADSIG  : 签名错误
 */
typedef enum {
    DNS_RCODE_NOERROR  = 0,
    DNS_RCODE_FORMERR  = 1,
    DNS_RCODE_SERVFAIL = 2,
    DNS_RCODE_NXDOMAIN = 3,
    DNS_RCODE_NOTIMP   = 4,
    DNS_RCODE_REFUSED  = 5,
    DNS_RCODE_YXDOMAIN = 6,
    DNS_RCODE_YXRRSET  = 7,
    DNS_RCODE_NXRRSET  = 8,
    DNS_RCODE_NOTAUTH  = 9,
    DNS_RCODE_NOTZONE  = 10,
    DNS_RCODE_BADSIG   = 16,  // RFC2845
} dns_rcode_t;

/**
 * @brief QR标志位
 * @param DNS_AA_NO  : 非权威回答
 * @param DNS_AA_YES : 权威回答
 */
typedef enum {
    DNS_AA_NO  = 0,
    DNS_AA_YES = 1
} dns_aa_t;

/**
 * @brief TC标志位
 * @param DNS_TC_NO  : 未截断
 * @param DNS_TC_YES : 已截断
 */
typedef enum {
    DNS_TC_NO  = 0,
    DNS_TC_YES = 1
} dns_tc_t;

/**
 * @brief RD标志位
 * @param DNS_RD_NO  : 不希望递归
 * @param DNS_RD_YES : 希望递归
 */
typedef enum {
    DNS_RD_NO  = 0,
    DNS_RD_YES = 1
} dns_rd_t;

/**
 * @brief RA标志位
 * @param DNS_RA_NO  : 不支持递归
 * @param DNS_RA_YES : 支持递归
 */
typedef enum {
    DNS_RA_NO  = 0,
    DNS_RA_YES = 1
} dns_ra_t;

/**
 * @brief 设置QR标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param qr: QR值，0表示查询报文，1表示响应报文
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_qr(uint16_t *flags, int qr);

/**
 * @brief 设置OPCODE标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param opcode: OPCODE值，0-15，表示不同的操作码
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_opcode(uint16_t *flags, int opcode);

/**
 * @brief 设置AA标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param aa: AA值，0表示非权威回答，1表示权威回答
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_aa(uint16_t *flags, int aa);

/**
 * @brief 设置TC标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param tc: TC值，0表示未截断，1表示已截断
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_tc(uint16_t *flags, int tc);

/**
 * @brief 设置RD标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param rd: RD值，0表示不希望递归，1表示希望递归
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_rd(uint16_t *flags, int rd);

/**
 * @brief 设置RA标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param ra: RA值，0表示递归不可用，1表示递归可用
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_ra(uint16_t *flags, int ra);

/**
 * @brief 设置RCODE标志位
 * @param flags: 指向包含DNS标志的16位无符号整数的指针
 * @param rcode: RCODE值，0-15，表示响应状态码
 * @return bool: 设置成功返回true，否则返回false
 */
bool dns_flags_set_rcode(uint16_t *flags, int rcode);

/**
 * @brief 获取QR标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: QR值，0表示查询报文，1表示响应报文
 */
int  dns_flags_get_qr(uint16_t flags);

/**
 * @brief 获取OPCODE标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: OPCODE值，0-15，表示不同的操作码
 */
int  dns_flags_get_opcode(uint16_t flags);

/**
 * @brief 获取AA标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: AA值，0表示非权威回答，1表示权威回答
 */
int  dns_flags_get_aa(uint16_t flags);

/**
 * @brief 获取TC标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: TC值，0表示未截断，1表示已截断
 */
int  dns_flags_get_tc(uint16_t flags);

/**
 * @brief 获取RD标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: RD值，0表示不希望递归，1表示希望递归
 */
int  dns_flags_get_rd(uint16_t flags);

/**
 * @brief 获取RA标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: RA值，0表示递归不可用，1表示递归可用
 */
int  dns_flags_get_ra(uint16_t flags);

/**
 * @brief 获取RCODE标志位的值
 * @param flags: 包含DNS标志的16位无符号整数
 * @return int: RCODE值，0-15，表示响应状态码
 */
int  dns_flags_get_rcode(uint16_t flags);
;

/**
 * @brief 获取QR标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含QR标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_qr(uint16_t flags, char *buf, uint32_t buf_size);

/**
 * @brief 获取OPCODE标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含OPCODE标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_opcode(uint16_t flags, char *buf, uint32_t buf_size);

/**
 * @brief 获取AA标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含AA标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_aa(uint16_t flags, char *buf, uint32_t buf_size);

/**
 * @brief 获取TC标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含TC标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_tc(uint16_t flags, char *buf, uint32_t buf_size);

/**
 * @brief 获取RD标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含RD标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_rd(uint16_t flags, char *buf, uint32_t buf_size);

/**
 * @brief 获取RA标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含RA标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_ra(uint16_t flags, char *buf, uint32_t buf_size);

/**
 * @brief 获取RCODE标志位的描述字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含RCODE标志位的描述，如果参数无效则返回NULL
 */
const char *dns_flags_stringify_rcode(uint16_t flags, char *buf, uint32_t buf_size);

/**
 * @brief 将DNS标志位转换为字符串
 * @param flags: 包含DNS标志的16位无符号整数
 * @param buf: 指向缓冲区的指针，用于存储结果字符串
 * @param buf_size: 缓冲区的大小
 * @return const char*: 指向缓冲区的指针，包含DNS标志位的描述，如果参数无效则返回NULL
 * */
const char *dns_flags_to_string(uint16_t flags, char *buf, uint32_t buf_size);

#ifdef __cplusplus
}
#endif