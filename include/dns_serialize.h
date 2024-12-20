#pragma once
#include <stdint.h>
#include <string.h>

// 假设的 dns_header_t 结构体定义
typedef struct {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t questions_count;
    uint16_t answers_count;
    uint16_t authorities_count;
    uint16_t additional_count;
} dns_header_t;

int dns_header_serialize(dns_header_t *header, uint8_t *buf, uint32_t buf_size) {
    // DNS头部固定为12字节
    const uint32_t dns_header_size = 12;
    if (buf_size < dns_header_size) {
        // 缓冲区太小，无法容纳DNS头部
        return -1;
    }

    // 序列化transaction_id
    buf[0] = (uint8_t)(header->transaction_id >> 8);
    buf[1] = (uint8_t)(header->transaction_id & 0xFF);

    // 序列化flags
    buf[2] = (uint8_t)(header->flags >> 8);
    buf[3] = (uint8_t)(header->flags & 0xFF);

    // 序列化questions_count
    buf[4] = (uint8_t)(header->questions_count >> 8);
    buf[5] = (uint8_t)(header->questions_count & 0xFF);

    // 序列化answers_count
    buf[6] = (uint8_t)(header->answers_count >> 8);
    buf[7] = (uint8_t)(header->answers_count & 0xFF);

    // 序列化authorities_count
    buf[8] = (uint8_t)(header->authorities_count >> 8);
    buf[9] = (uint8_t)(header->authorities_count & 0xFF);

    // 序列化additional_count
    buf[10] = (uint8_t)(header->additional_count >> 8);
    buf[11] = (uint8_t)(header->additional_count & 0xFF);

    // 返回序列化后的长度
    return dns_header_size;
}

// 示例使用
int main() {
    dns_header_t header = {
        .transaction_id = 0x1234,
        .flags = 0x8180,
        .questions_count = 1,
        .answers_count = 0,
        .authorities_count = 0,
        .additional_count = 0
    };
    uint8_t buf[12];
    int serialized_size = dns_header_serialize(&header, buf, sizeof(buf));

    if (serialized_size > 0) {
        printf("Serialized DNS header:\n");
        for (int i = 0; i < serialized_size; i++) {
            printf("%02X ", buf[i]);
        }
        printf("\n");
    } else {
        printf("Failed to serialize DNS header.\n");
    }

    return 0;
}
