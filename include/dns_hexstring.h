#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>


/**
 * @brief 把数据打印成16进制字符串
 * 
 * @param[in]  data 数据
 * @param[in]  len 数据长度
 * @param[out] buf 输出缓冲区
 * @param[in]  buf_size 输出缓冲区大小
 * @return const char* 返回得到的字符串
 */
const char* dns_hexstring(const uint8_t *data, size_t len, char *buf, size_t buf_size);

#ifdef __cplusplus
}
#endif