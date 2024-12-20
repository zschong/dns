#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief DNS 域名编码
 * @param[in] name 域名
 * @param[out] buf 编码后的数据
 * @param[in] buf_len buf长度
 * @return 编码后的数据, 返回NULL表示编码失败
 */
const char *dns_name_encode(const char *name, char *buf, size_t buf_len);

/**
 * @brief DNS 域名解码
 * @param[in] data 编码后的数据
 * @param[out] buf 解码后的数据
 * @param[in] buf_size buf长度
 * @return 解码后的数据, 返回NULL表示编码失败
 */
const char *dns_name_decode(const char *data, char *buf, size_t buf_size);

/**
 * @brief DNS 域名编码数据打印到字符串
 * @param[in] name 域名
 * @param[out] buf 编码后的数据
 * @param[in] buf_len buf长度
 * @return 编码后的数据, 返回NULL表示编码失败
 */
const char *dns_name_encoded_string(const char *name, char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif
