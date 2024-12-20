#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>


/**
 * @brief 把数值打印成二进制字符串
 * 
 * @param[in]  val 数值指针
 * @param[in]  val_size 数值大小
 * @param[out] buf 输出缓冲区
 * @param[in]  buf_size 输出缓冲区大小
 * @return const char* 返回得到的2进制字符串
 */
const char* dns_value_binstring(const uint8_t *val, uint32_t val_size, char *buf, size_t buf_size);

/**
 * @brief 把数据打印成二进制字符串
 * 
 * @param[in]  array 字节数组
 * @param[in]  arr_size 字节数组大小
 * @param[out] buf 输出缓冲区
 * @param[in]  buf_size 输出缓冲区大小
 * @return const char* 返回得到的2进制字符串
 */
const char* dns_array_binstring(const uint8_t *array, uint32_t arr_size, char *buf, size_t buf_size);

#ifdef __cplusplus
}
#endif