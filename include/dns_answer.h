#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns_class.h"
#include "dns_type.h"

#ifdef __cplusplus
extern "C" {
#endif

// DNS资源记录结构体
typedef struct {
    char    *rname;    // 域名，通常为压缩格式
    uint16_t rtype;    // 资源记录类型，如A记录（1）
    uint16_t rclass;   // 资源记录类，通常为IN（互联网）类，值为1
    uint32_t rttl;     // 生存时间，表示记录的缓存时间
    uint16_t rlength;  // 资源数据长度
    uint8_t *rdata;    // 资源数据，如IP地址
} dns_answer_t;
;

/**
 * @brief 初始化资源记录结构体
 * @param answer 资源记录结构体指针
 * @return bool 成功返回true，失败返回false
 * */
bool dns_answer_init(dns_answer_t *answer);

/**
 * @brief 清空资源记录结构体
 * @param answer 资源记录结构体指针
 * @return bool 成功返回true，失败返回false
 * */
bool dns_answer_clear(dns_answer_t *answer);

/**
 * @brief 设置资源记录的域名
 * @param answer 资源记录结构体指针
 * @param name 域名指针
 * @return bool 成功返回true，失败返回false
 */
bool dns_answer_set_name(dns_answer_t *answer, const char *name);

/**
 * @brief 克隆资源记录的域名
 * @param answer 资源记录结构体指针
 * @param name 域名指针
 * @return const char* 域名指针，失败返回NULL
 */
bool dns_answer_dup_name(dns_answer_t *answer, const char *name);

/**
 * @brief 设置资源记录的类型
 * @param answer 资源记录结构体指针
 * @param type 资源记录类型
 * @return bool 成功返回true，失败返回false
 */
bool dns_answer_set_type(dns_answer_t *answer, dns_type_t rtype);

/**
 * @brief 设置资源记录的生存时间
 * @param answer 资源记录结构体指针
 * @param rttl 生存时间
 * @return bool 成功返回true，失败返回false
 */
bool dns_answer_set_ttl(dns_answer_t *answer, uint32_t rttl);

/**
 * @brief 设置资源记录的类
 * @param answer 资源记录结构体指针
 * @param rclass 资源记录类
 * @return bool 成功返回true，失败返回false
 */
bool dns_answer_set_class(dns_answer_t *answer, dns_class_t rclass);

/**
 * @brief 设置资源记录的数据
 * @param answer 资源记录结构体指针
 * @param data 数据指针
 * @param length 数据长度
 * @return bool 成功返回true，失败返回false
 */
bool dns_answer_set_data(dns_answer_t *answer, const uint8_t *data, uint16_t length);
;

/**
 * @brief 获取资源记录的域名
 * @param answer 资源记录结构体指针
 * @return const char* 域名指针，失败返回NULL
 */
const char *dns_answer_get_name(const dns_answer_t *answer);
;

/**
 * @brief 获取资源记录的类型
 * @param answer 资源记录结构体指针
 * @return uint16_t 资源记录类型
 * */
uint16_t dns_answer_get_type(const dns_answer_t *answer);

/**
 * @brief 获取资源记录的类
 * @param answer 资源记录结构体指针
 * @return uint16_t 资源记录类
 * */
uint16_t dns_answer_get_class(const dns_answer_t *answer);

/**
 * @brief 获取资源记录的生存时间
 * @param answer 资源记录结构体指针
 * @return uint32_t 生存时间
 */
uint32_t dns_answer_get_ttl(const dns_answer_t *answer);

/**
 * @brief 获取资源记录的数据长度
 * @param answer 资源记录结构体指针
 * @return uint16_t 数据长度
 */
uint16_t dns_answer_get_length(const dns_answer_t *answer);

/**
 * @brief 获取资源记录的数据
 * @param answer 资源记录结构体指针
 * @return uint8_t* 数据指针
 * */
uint8_t *dns_answer_get_data(const dns_answer_t *answer);
;

/**
 * @brief 获取资源记录整体长度
 * @param answer 资源记录结构体指针
 * @return uint32_t 资源记录长度
 * */
uint32_t dns_answer_length(const dns_answer_t *answer);
;

/**
 * @brief 比较两个资源记录是否相同
 * @param answer1 资源记录结构体指针1
 * @param answer2 资源记录结构体指针2
 * @return bool 相同返回true，不同返回false
 * */
bool dns_answer_equal(const dns_answer_t *answer1, const dns_answer_t *answer2);;

/**
 * @brief 复制资源记录结构体
 * @param[out] dst 目标资源记录结构体指针
 * @param[in] src 源资源记录结构体指针
 * @return bool 成功返回true，失败返回false
 * */
bool dns_answer_copy(dns_answer_t *dst, const dns_answer_t *src);;

/**
 * @brief DNS资源记录序列化
 * @param[in] answer 资源记录结构体指针
 * @param[out] buf 缓冲区指针
 * @param[in] buf_zie 缓冲区大小
 * @return int 序列化后的数据长度，失败返回0
 */
int  dns_answer_serialize(const dns_answer_t *answer, uint8_t *buf, size_t buf_size);
;

/**
 * @brief DNS资源记录反序列化
 * @param[out] answer 资源记录结构体指针
 * @param[in] data 序列化数据
 * @param[in] data_len 数据长度
 * @return int 反序列化消耗的数据长度，失败返回0
 */
int dns_answer_deserialize(dns_answer_t *answer, const uint8_t *data, size_t data_len);
;

/**
 * @brief 将资源记录转换为字符串
 * @param answer 资源记录结构体指针
 * @param buf 字符串缓冲区指针
 * @param buf_size 字符串缓冲区大小
 * @return const char* 字符串指针
 */
const char *dns_answer_to_string(dns_answer_t *answer, char *buf, uint32_t buf_size);

#ifdef __cplusplus
}
#endif
