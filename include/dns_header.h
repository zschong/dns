#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define DNS_HEADER_SIZE 12

/**
 * @brief DNS 头部定义
 * @param id            : DNS 消息标识符
 * @param flags         : DNS 消息标志
 * @param questions_count     : 问题记录数
 * @param answers_count    : 回答记录数
 * @param authorities_count : 权威记录数
 * @param additional_count: 附加记录数
 * @note DNS 头部大小为 12 字节
 */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t questions_count;
    uint16_t answers_count;
    uint16_t authorities_count;
    uint16_t additional_count;
} dns_header_t;
;

/**
 * @brief 初始化 DNS 头部
 * @param header : DNS 头部指针
 * @return true  : 初始化成功, false : 初始化失败
 */
bool dns_header_init(dns_header_t *header);
;

/**
 * @brief 设置 DNS 头部标识符
 * @param header : DNS 头部指针
 * @param id     : DNS 消息标识符
 * @return true  : 设置成功, false : 设置失败
 */
bool dns_header_set_id(dns_header_t *header, uint16_t id);
;

/**
 * @brief 设置 DNS 头部标志
 * @param header : DNS 头部指针
 * @param flags  : DNS 消息标志
 * @return true  : 设置成功, false : 设置失败
 */
bool dns_header_set_flags(dns_header_t *header, uint16_t flags);
;

/**
 * @brief 设置 DNS 头部问题记录数
 * @param header    : DNS 头部指针
 * @param questions_count : 问题记录数
 * @return true     : 设置成功, false : 设置失败
 */
bool dns_header_set_questions(dns_header_t *header, uint16_t questions_count);
;

/**
 * @brief 设置 DNS 头部回答记录数
 * @param header     : DNS 头部指针
 * @param answers_count : 回答记录数
 * @return true      : 设置成功, false : 设置失败
 */
bool dns_header_set_answer_rrs(dns_header_t *header, uint16_t answers_count);
;

/**
 * @brief 设置 DNS 头部权威记录数
 * @param header        : DNS 头部指针
 * @param authorities_count : 权威记录数
 * @return true         : 设置成功, false : 设置失败
 */
bool dns_header_set_authority_rrs(dns_header_t *header, uint16_t authorities_count);
;

/**
 * @brief 设置 DNS 头部附加记录数
 * @param header         : DNS 头部指针
 * @param additional_count : 附加记录数
 * @return true          : 设置成功, false : 设置失败
 */
bool dns_header_set_additional_rrs(dns_header_t *header, uint16_t additional_count);
;

/**
 * @brief 获取 DNS 头部标识符
 * @param header : DNS 头部指针
 * @return uint16_t : DNS 消息标识符
 */
uint16_t dns_header_get_id(dns_header_t *header);
;

/**
 * @brief 获取 DNS 头部标志
 * @param header : DNS 头部指针
 * @return uint16_t : DNS 消息标志
 * */
uint16_t dns_header_get_flags(dns_header_t *header);
;

/**
 * @brief 获取 DNS 头部问题记录数
 * @param header : DNS 头部指针
 * @return uint16_t : 问题记录数
 */
uint16_t dns_header_get_questions(dns_header_t *header);
;

/**
 * @brief 获取 DNS 头部回答记录数
 * @param header : DNS 头部指针
 * @return uint16_t : 回答记录数
 */
uint16_t dns_header_get_answer_rrs(dns_header_t *header);
;

/**
 * @brief 获取 DNS 头部权威记录数
 * @param header : DNS 头部指针
 * @return uint16_t : 权威记录数
 */
uint16_t dns_header_get_authority_rrs(dns_header_t *header);
;

/**
 * @brief 获取 DNS 头部附加记录数
 * @param header : DNS 头部指针
 * @return uint16_t : 附加记录数
 */
uint16_t dns_header_get_additional_rrs(dns_header_t *header);
;

/**
 * @brief 序列化,将 DNS 头部写入到 buf 中
 * @param[in]  header: DNS 头部指针
 * @param[out]  buf: DNS 数据指针
 * @param[in]  buf_size: DNS 数据长度
 * @return uint32_t : 序列化填充 buf 的长度 ， 0表示参数错误
 */
uint32_t dns_header_serialize(const dns_header_t *header, uint8_t *buf, uint32_t buf_size);
;

/**
 * @brief 反序列化数据，读出 DNS 头部
 * @param header : DNS 头部指针
 * @param data   : DNS 数据指针
 * @param len    : DNS 数据长度
 * @return 返回序列化消耗 data 的长度， 0表示参数错误
 */
uint32_t dns_header_deserialize(dns_header_t *header, const uint8_t *data, uint16_t len);
;

/**
 * @brief 将 DNS 头部转换为字符串
 * @param header : DNS 头部指针
 * @param buf    : 字符串缓冲区指针
 * @param buf_size : 字符串缓冲区大小
 * @return const char* : 字符串
 */
const char *dns_header_to_string(dns_header_t *header, char *buf, uint32_t buf_size);
;

#ifdef __cplusplus
}
#endif
