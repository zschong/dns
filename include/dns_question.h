#pragma once

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// DNS查询问题结构
typedef struct {
    char *qname;   // 查询名称
    uint16_t qtype;   // 查询类型
    uint16_t qclass;  // 查询类
} dns_question_t;
;

/**
 * @brief 初始化DNS查询问题
 * @param[out] query DNS查询问题结构
 * @return bool 初始化成功返回true，否则返回false
 */
bool dns_question_init(dns_question_t *query);
;

/**
 * @brief 清空DNS查询问题
 * @param[out] query DNS查询问题结构
 * @return bool 释放成功返回true，否则返回false
 */
bool dns_question_clear(dns_question_t *query);
;

/**
 * @brief 初始化DNS查询问题
 * @param[out] query DNS查询问题结构
 * @param[in] domain_name 查询域名
 * @return void
 */
bool dns_question_set_qname(dns_question_t *query, const char *domain_name);
;

/**
 * @brief 设置DNS查询问题的类型
 * @param[out] query DNS查询问题结构
 * @param[in] qtype 查询类型
 * @return void
 * */
bool dns_question_set_qtype(dns_question_t *query, uint16_t qtype);
;

/**
 * @brief 设置DNS查询问题的类
 * @param[out] query DNS查询问题结构
 * @param[in] qclass 查询类
 * @return void
 * */
bool dns_question_set_qclass(dns_question_t *query, uint16_t qclass);
;

/**
 * @brief 获取DNS查询问题的名称
 * @param[in] query DNS查询问题结构
 * @return const uint8_t* 查询名称
 * */
const char *dns_question_get_qname(const dns_question_t *query);
;

/**
 * @brief 获取DNS查询问题的类型
 * @param[in] query DNS查询问题结构
 * @return uint16_t 查询类型
 * */
uint16_t dns_question_get_qtype(const dns_question_t *query);
;

/**
 * @brief 获取DNS查询问题的类
 * @param[in] query DNS查询问题结构
 * @return uint16_t 查询类
 * */
uint16_t dns_question_get_qclass(const dns_question_t *dns_question_t);
;

/**
 * @brief 获取DNS查询问题的长度
 * @param[in] query DNS查询问题结构
 * @return uint32_t 问题的长度
 */
uint32_t dns_question_length(const dns_question_t *query);
;

/**
 * @brief 比较两个DNS查询问题是否相等
 * @param[in] query1 DNS查询问题结构
 * @param[in] query2 DNS查询问题结构
 * @return bool 相等返回true，否则返回false
 * */
bool dns_question_equal(const dns_question_t *query1, const dns_question_t *query2);
;

/**
 * @brief 序列化DNS查询问题
 * @param[in] query DNS查询问题结构
 * @param[out] buf 输出缓冲区
 * @param[in] buf_size 输出缓冲区大小
 * @return int 序列化填充的字节数，否则返回-1
 */
int dns_question_serialize(const dns_question_t *query, uint8_t *buf, uint16_t buf_size);
;

/**
 * @brief 反序列化DNS查询问题
 * @param[out] query DNS查询问题结构
 * @param[in] src 输入缓冲区
 * @param[in] src_len 输入缓冲区大小
 * @return int 反序列消耗的字节数
 */
int dns_question_deserialize(dns_question_t *query, const uint8_t *src, uint16_t src_len);
;

/**
 * @brief 打印DNS查询问题
 * @param[in] query DNS查询问题结构
 * @param[out] buf 输出缓冲区
 * @param[in] buf_size 输出缓冲区大小
 * @return void
 * */
const char *dns_question_to_string(const dns_question_t *query, char *buf, uint32_t buf_size);
;