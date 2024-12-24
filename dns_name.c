#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns_name.h"

const char *dns_name_encode(const char *name, char *buf, size_t buf_len)
{
    if (NULL == name || NULL == buf) {
        return NULL;
    }

    const int name_len = strlen(name) + 1;
    if (buf_len < name_len) {
        return NULL;
    }

    // 预留一个字节用于存放长度
    memcpy(buf + 1, name, name_len);
    buf[name_len] = 0;

    uint8_t    *ptr   = (uint8_t *)buf;
    const char *begin = name;

    for (char *dot = strchr(begin, '.'); dot != NULL; dot = strchr(begin, '.')) {
        // 调整长度字段为实际长度
        *ptr = dot - begin;

        // 跳到下一个'.'位置
        ptr += *ptr + 1;

        // 跳到'.'后的第一个字符
        begin = dot + 1;

        // 先赋值为剩余长度，最后再根据实际长度调整
        *ptr = strlen(begin);
    }

    return buf;
}

const char *dns_name_decode(const char *data, char *buf, size_t buf_size)
{
    if (NULL == data || NULL == buf) {
        return NULL;
    }

    size_t data_len = strlen(data);
    if (buf_size < data_len) {
        return NULL;
    }

    char *dst = buf;
    for (uint8_t *src = (uint8_t *)data; *src != 0; src += *src + 1) {
        memcpy(dst, src + 1, *src);
        dst += *src;
        *dst++ = '.';
    }
    
    if (dst > buf) {
        *(dst-1) = 0;
    }

    return buf;
}

const char *dns_name_encoded_string(const char *name, char *buf, size_t buf_len)
{
    if (NULL == name || NULL == buf) {
        return NULL;
    }

    const int name_len = strlen(name);
    if (buf_len < name_len * 3) {
        printf("buf_len too small\n");
        return NULL;
    }

    char  *dst     = buf;
    size_t dst_len = buf_len;

    memset(buf, 0, buf_len);
    for (uint8_t *src = (uint8_t *)name; *src != 0; src += *src + 1) {
        // 打印长度
        int len = snprintf(dst, dst_len, "%d", *src);
        if (len < 1) {
            printf("snprintf failed\n");
            return NULL;
        }

        // 移动目标指针
        dst += len;
        dst_len -= len;

        // 复制数据， src位置保存长度
        memcpy(dst, src + 1, *src);

        // 移动目标指针 *src 个字节
        dst += *src;
        dst_len -= *src;
    }

    return buf;
}

#ifdef DNS_NAME_TEST
int main(void)
{
    char *name           = "www.baidu.com";
    char  encoded[256]     = {0};
    char  orig[256]      = {0};
    char  encoded_buf[256] = {0};

    dns_name_encode(name, encoded, sizeof(encoded));
    dns_name_decode(encoded, orig, sizeof(orig));
    dns_name_encoded_string(encoded, encoded_buf, sizeof(encoded_buf));

    printf("encoded:");
    for (int i = 0; i < strlen(encoded); i++) {
        printf("%c", encoded[i]);
    }
    printf("\n");
    printf("orig:%s\n", orig);
    printf("encoded string:%s\n", encoded_buf);

    return 0;
}
#endif  // DNS_NAME_TEST