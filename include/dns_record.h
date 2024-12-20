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
    uint8_t *rname;    // 域名，通常为压缩格式
    uint16_t rtype;    // 资源记录类型，如A记录（1）
    uint16_t rclass;   // 资源记录类，通常为IN（互联网）类，值为1
    uint32_t rttl;     // 生存时间，表示记录的缓存时间
    uint16_t rlength;  // 资源数据长度
    uint8_t *rdata;    // 资源数据，如IP地址
} dns_record_t;
;

/**
 * @brief 初始化资源记录结构体
 * @param record 资源记录结构体指针
 * @return bool 成功返回true，失败返回false
 * */
bool dns_record_init(dns_record_t *record);

/**
 * @brief 清空资源记录结构体
 * @param record 资源记录结构体指针
 * @return bool 成功返回true，失败返回false
 * */
bool dns_record_clear(dns_record_t *record);

/**
 * @brief 设置资源记录的域名
 * @param record 资源记录结构体指针
 * @param name 域名指针
 * @return bool 成功返回true，失败返回false
 */
bool dns_record_set_name(dns_record_t *record, const char *name);

/**
 * @brief 设置资源记录的类型
 * @param record 资源记录结构体指针
 * @param type 资源记录类型
 * @return bool 成功返回true，失败返回false
 */
bool dns_record_set_type(dns_record_t *record, dns_type_t rtype);

/**
 * @brief 设置资源记录的生存时间
 * @param record 资源记录结构体指针
 * @param rttl 生存时间
 * @return bool 成功返回true，失败返回false
 */
bool dns_record_set_ttl(dns_record_t *record, uint32_t rttl);

/**
 * @brief 设置资源记录的类
 * @param record 资源记录结构体指针
 * @param rclass 资源记录类
 * @return bool 成功返回true，失败返回false
 */
bool dns_record_set_class(dns_record_t *record, dns_class_t rclass);

/**
 * @brief 设置资源记录的数据
 * @param record 资源记录结构体指针
 * @param data 数据指针
 * @param length 数据长度
 * @return bool 成功返回true，失败返回false
 */
bool dns_record_set_data(dns_record_t *record, const uint8_t *data, uint16_t length);
;

/**
 * @brief 获取资源记录的域名
 * @param record 资源记录结构体指针
 * @return const char* 域名指针，失败返回NULL
 */
const char *dns_record_get_name(const dns_record_t *record);
;

/**
 * @brief 获取资源记录的类型
 * @param record 资源记录结构体指针
 * @return uint16_t 资源记录类型
 * */
uint16_t dns_record_get_type(const dns_record_t *record);

/**
 * @brief 获取资源记录的类
 * @param record 资源记录结构体指针
 * @return uint16_t 资源记录类
 * */
uint16_t dns_record_get_class(const dns_record_t *record);

/**
 * @brief 获取资源记录的生存时间
 * @param record 资源记录结构体指针
 * @return uint32_t 生存时间
 */
uint32_t dns_record_get_ttl(const dns_record_t *record);

/**
 * @brief 获取资源记录的数据长度
 * @param record 资源记录结构体指针
 * @return uint16_t 数据长度
 */
uint16_t dns_record_get_length(const dns_record_t *record);

/**
 * @brief 获取资源记录的数据
 * @param record 资源记录结构体指针
 * @return uint8_t* 数据指针
 * */
uint8_t *dns_record_get_data(const dns_record_t *record);
;

/**
 * @brief 获取资源记录整体长度
 * @param record 资源记录结构体指针
 * @return uint32_t 资源记录长度
 * */
uint32_t dns_record_length(const dns_record_t *record);
;

/**
 * @brief 比较两个资源记录是否相同
 * @param record1 资源记录结构体指针1
 * @param record2 资源记录结构体指针2
 * @return bool 相同返回true，不同返回false
 * */
bool dns_record_equal(const dns_record_t *record1, const dns_record_t *record2);

/**
 * @brief DNS资源记录序列化
 * @param[in] record 资源记录结构体指针
 * @param[out] buf 缓冲区指针
 * @param[in] buf_zie 缓冲区大小
 * @return int 序列化后的数据长度，失败返回0
 */
int dns_record_serialize(const dns_record_t *record, uint8_t *buf, size_t buf_size);
;

/**
 * @brief DNS资源记录反序列化
 * @param[out] record 资源记录结构体指针
 * @param[in] data 序列化数据
 * @param[in] data_len 数据长度
 * @return int 反序列化消耗的数据长度，失败返回0
 */
int dns_record_deserialize(dns_record_t *record, const uint8_t *data, size_t data_len);
;

/**
 * @brief 将资源记录转换为字符串
 * @param record 资源记录结构体指针
 * @param buf 字符串缓冲区指针
 * @param buf_size 字符串缓冲区大小
 * @return const char* 字符串指针
 */
const char *dns_record_to_string(dns_record_t *record, char *buf, uint32_t buf_size);

#ifdef __cplusplus
}
#endif
