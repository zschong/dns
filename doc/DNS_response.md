# DNS 回复报文
```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h> // 用于htons和htonl函数

// DNS报文头部结构体
typedef struct {
    uint16_t transaction_id; // 事务ID，用于匹配请求和响应
    uint16_t flags         ; // 标志字段，包含多个子字段
    uint16_t questions     ; // 问题数，表示查询部分的问题数量
    uint16_t answer_rrs    ; // 回答资源记录数，表示回答部分的数量
    uint16_t authority_rrs ; // 授权资源记录数，表示授权部分的数量
    uint16_t additional_rrs; // 附加资源记录数，表示附加部分的数量
} dns_header_t;

// DNS查询部分结构体
typedef struct {
    uint8_t  *name; // 域名，以点分十进制表示，以null结尾
    uint16_t type ; // 查询类型，如A记录（1）
    uint16_t class; // 查询类，通常为IN（互联网）类，值为1
} dns_question_t;

// DNS资源记录结构体
typedef struct {
    uint8_t  *name   ; // 域名，通常为压缩格式
    uint16_t type    ; // 资源记录类型，如A记录（1）
    uint16_t class   ; // 资源记录类，通常为IN（互联网）类，值为1
    uint32_t ttl     ; // 生存时间，表示记录的缓存时间
    uint16_t rdlength; // 资源数据长度
    uint8_t  *rdata  ; // 资源数据，如IP地址
} dns_answer_t;

// 位域结构体用于表示flags字段
typedef struct {
    uint16_t rcode  : 4; // 响应代码，0表示没有错误
    uint16_t z      : 3; // 保留字段，必须为0
    uint16_t ra     : 1; // 递归可用，0表示递归不可用
    uint16_t rd     : 1; // 期望递归，1表示请求递归查询
    uint16_t tc     : 1; // 报文截断，0表示报文未截断
    uint16_t aa     : 1; // 权威回答，1表示权威回答
    uint16_t opcode : 4; // 操作码，0表示标准查询
    uint16_t qr     : 1; // 查询/响应标志，1表示响应
} dns_flags_t;

int main() {
    // 创建一个DNS报文头部实例
    dns_header_t header;
    memset(&header, 0, sizeof(header)); // 初始化所有字段为0

    // 设置事务ID
    header.transaction_id = htons(0x1234); // 示例事务ID，应与请求报文中的事务ID相同

    // 设置flags字段的各个位域
    dns_flags_t flags;
    flags.qr     = 1; // QR=1，表示这是一个响应报文
    flags.opcode = 0; // OPCODE=0，标准查询
    flags.aa     = 1; // AA=1，表示这是一个权威回答
    flags.tc     = 0; // TC=0，报文未截断
    flags.rd     = 1; // RD=1，表示请求了递归查询
    flags.ra     = 0; // RA=0，表示递归不可用
    flags.z      = 0; // Z=0，保留字段，必须为0
    flags.rcode  = 0; // RCODE=0，无错误

    // 将位域结构体复制到header的flags字段
    memcpy(&header.flags, &flags, sizeof(flags));

    // 设置问题、回答、授权和附加资源记录数
    header.questions      = htons(1); // 1个查询问题
    header.answer_rrs     = htons(1); // 1个回答记录
    header.authority_rrs  = htons(0); // 请求中无授权记录
    header.additional_rrs = htons(0);// 请求中无附加记录

    // 创建查询部分（省略实现，与之前相同）

    // 创建回答部分
    dns_answer_t answer;

    // 假设我们已经有了压缩的域名指针，通常是指向请求中的域名
    // 这里为了简化，我们直接使用一个示例压缩格式
    // 压缩格式通常是一个两字节的指针，前两个最高位为11，表示这是一个指针
    // 后14位表示偏移量，这里假设偏移量为0x0C（12），指向请求中的域名
    uint8_t compressedName[] = {0xC0, 0x0C}; // 压缩的域名指针
    answer.name = compressedName;

    // 设置资源记录类型为A记录（1）
    answer.type = htons(0x0001);

    // 设置资源记录类为IN（互联网）类，值为1
    answer.class = htons(0x0001);

    // 设置生存时间（TTL），例如3600秒
    answer.ttl = htonl(3600);

    // 设置资源数据长度，对于A记录，IP地址长度为4字节
    answer.rdlength = htons(0x0004);

    // 设置资源数据，例如IP地址为192.168.1.1
    uint8_t ipAddr[] = {192, 168, 1, 1};
    answer.rdata = ipAddr;

    // 打印DNS报文（省略实现，与之前相同）

    // 这里我们只是构建了DNS报文的结构，实际发送和接收需要使用socket编程
    // 以下代码仅为示例，不包含实际的socket操作

    return 0;
}
```