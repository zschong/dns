# DNS_Header_flags
```c
#include <stdio.h>
#include <string.h>

/**
 * 
 * +-----+---------+-----+-----+-----+-----+-------+--------+
 * |QR(1)|opcode(4)|AA(1)|TC(1)|RD(1)|RA(1)|zero(3)|rcode(4)|
 * +-----+---------+-----+-----+-----+-----+-------+--------+
 * */
// DNS头部标志的位字段结构体
typedef struct {
    unsigned int qr     : 1; // 查询/响应标志（0为查询，1为响应）
    unsigned int opcode : 4; // 操作码（0为标准查询，其他值表示特殊操作）
    unsigned int aa     : 1; // 权威答案标志（1表示权威答案）
    unsigned int tc     : 1; // 截断标志（1表示消息被截断）
    unsigned int rd     : 1; // 递归 Desired 标志（1表示请求递归查询）
    unsigned int ra     : 1; // 递归 Available 标志（1表示服务器支持递归查询）
    unsigned int z      : 3; // 保留位（必须为0）
    unsigned int rcode  : 4; // 响应代码（0为无错误，其他值表示错误类型）
} dns_flags_t;

char* dns_flags_to_string(dns_flags_t flags, char* buffer, size_t buffer_size) {
    if (buffer_size < 256) {
        return NULL; // 如果缓冲区太小，则返回NULL
    }

    // 初始化缓冲区
    buffer[0] = '\0';

    // 格式化每个字段的状态并追加到缓冲区
    sprintf(buffer + strlen(buffer), "QR (Query/Response)      : %u (%s)\n", flags.qr    , flags.qr ? "Response" : "Query"                            );
    sprintf(buffer + strlen(buffer), "OPCODE                   : %u (%s)\n", flags.opcode, flags.opcode == 0 ? "Standard query" : "Non-standard query");
    sprintf(buffer + strlen(buffer), "AA (Authoritative Answer): %u (%s)\n", flags.aa    , flags.aa ? "Yes" : "No"                                    );
    sprintf(buffer + strlen(buffer), "TC (Truncated)           : %u (%s)\n", flags.tc    , flags.tc ? "Yes" : "No"                                    );
    sprintf(buffer + strlen(buffer), "RD (Recursion Desired)   : %u (%s)\n", flags.rd    , flags.rd ? "Yes" : "No"                                    );
    sprintf(buffer + strlen(buffer), "RA (Recursion Available) : %u (%s)\n", flags.ra    , flags.ra ? "Yes" : "No"                                    );
    sprintf(buffer + strlen(buffer), "Z (Reserved)             : %u\n"     , flags.z                                                                  ); 
    sprintf(buffer + strlen(buffer), "RCODE (Response Code)    : %u (%s)\n", flags.rcode , flags.rcode == 0 ? "No error" : "Error"                    );

    return buffer;
}

int main() {
    unsigned short flags_value = 0x8180;
    dns_flags_t flags;
    char flags_string[256]; // 缓冲区用于存储标志字符串

    // 将16位标志值分解到位字段结构体中
    flags.qr     = (flags_value & 0x8000) >> 15; // 设置查询/响应标志
    flags.opcode = (flags_value & 0x7800) >> 11; // 设置操作码
    flags.aa     = (flags_value & 0x0400) >> 10; // 设置权威答案标志
    flags.tc     = (flags_value & 0x0200) >> 9 ; // 设置截断标志
    flags.rd     = (flags_value & 0x0100) >> 8 ; // 设置递归 Desired 标志
    flags.ra     = (flags_value & 0x0080) >> 7 ; // 设置递归 Available 标志
    flags.z      = (flags_value & 0x0070) >> 4 ; // 设置保留位
    flags.rcode  = (flags_value & 0x000F)      ; // 设置响应代码

    // 获取标志字符串
    dns_flags_to_string(flags, flags_string, sizeof(flags_string));
    printf("%s", flags_string); // 打印标志字符串
    return 0;
}
```