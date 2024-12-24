#pragma once
#include "dns_answer.h"
#include "dns_header.h"
#include "dns_question.h"
#include "dns_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief DNS消息定义
 * @param header DNS消息头
 * @param questions DNS查询列表，如果为空，则表示该消息为响应消息
 * @param responses DNS响应列表，如果为空，则表示该消息为查询消息
 */
typedef struct dns_message {
    dns_header_t    header;
    dns_question_t *questions;
    dns_answer_t   *answers;
} dns_message_t;

/**
 * @brief 初始化DNS消息
 * @param message DNS消息
 * @return true 成功
 * @return false 失败
 */
bool dns_message_init(dns_message_t *message);
;

/**
 * @brief 清空DNS消息
 * @param message DNS消息
 * @return true 成功
 * @return false 失败
 */
bool dns_message_clear(dns_message_t *message);
;

/**
 * @brief 添加DNS查询
 * @param message DNS消息
 * @param question DNS查询
 * @return true 成功
 * @return false 失败
 */
bool dns_message_add_question(dns_message_t *message, dns_question_t *question);
;

/**
 * @brief 添加DNS响应
 * @param message DNS消息
 * @param answer DNS响应
 * @return true 成功
 * @return false 失败
 */
bool dns_message_add_response(dns_message_t *message, dns_answer_t *answer);
;

/**
 * @brief 序列化DNS消息
 * @param message DNS消息
 * @param buffer 序列化后的缓冲区
 * @param buffer_size 缓冲区大小
 * @return int 序列化后的字节数，如果返回0，则表示失败
 */
int dns_message_serialize(const dns_message_t *message, uint8_t *buffer, size_t buffer_size);
;

/**
 * @brief 反序列化DNS消息
 * @param message DNS消息
 * @param data 反序列化后的缓冲区
 * @param data_len 缓冲区大小
 * @return int 反序列化消耗的字节数，如果返回0，则表示失败
 */
int dns_message_deserialize(dns_message_t *message, const uint8_t *data, size_t data_len);
;

/**
 * @brief 将DNS消息打印为字符串
 * @param message DNS消息
 * @param buffer 字符串缓冲区
 * @param buffer_size 缓冲区大小
 * @return const char* 把钱输出的字符串，如果返回NULL，则表示失败
 */
const char *dns_message_to_string(const dns_message_t *message, char *buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif
