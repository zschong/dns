# DNS 请求报文
```c
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

// DNS报文头部结构
typedef struct {
    uint16_t transaction_id; // 事务ID，用于匹配请求和响应

    // 标志字段，使用位字段方式定义
    struct {
        uint16_t rd     : 1; // 递归查询标志（Recursion Desired）
        uint16_t tc     : 1; // 截断标志（Truncation Flag）
        uint16_t aa     : 1; // 权威回答标志（Authoritative Answer）
        uint16_t opcode : 4; // 操作码（Opcode）
        uint16_t qr     : 1; // 查询/响应标志（Query/Response Flag）
        uint16_t rcode  : 4; // 响应码（Response Code）
        uint16_t cd     : 1; // 检查禁用标志（Checking Disabled）
        uint16_t ad     : 1; // 真实数据标志（Authentic Data）
        uint16_t z      : 1; // 保留位，必须为0
        uint16_t ra     : 1; // 递归可用标志（Recursion Available）
    } flags;

    uint16_t questions     ; // 问题数，表示查询问题区域的数量
    uint16_t answer_rrs    ; // 回答资源记录数，响应中为回答区域的数量
    uint16_t authority_rrs ; // 授权资源记录数，响应中为授权区域的数量
    uint16_t additional_rrs; // 附加资源记录数，响应中为附加区域的数量
} DNS_Header;

// DNS查询问题结构
typedef struct {
    uint8_t  *qname ; // 查询名称，即域名
    uint16_t  qtype ; // 查询类型，例如A记录（1）、AAAA记录（28）等
    uint16_t  qclass; // 查询类，通常为IN（互联网）类，值为1
} DNS_Query;

int main() {
    // 创建DNS报文头部
    DNS_Header header;
    header.transaction_id = htons(0x1234); // 随机选择一个事务ID

    // 设置flags位字段
    header.flags.rd     = 1; // 请求递归查询
    header.flags.tc     = 0; // 不设置截断标志
    header.flags.aa     = 0; // 不设置权威回答标志
    header.flags.opcode = 0; // 标准查询操作码
    header.flags.qr     = 0; // 这是一个查询报文
    header.flags.rcode  = 0; // 无错误响应码
    header.flags.cd     = 0; // 不设置检查禁用标志
    header.flags.ad     = 0; // 不设置真实数据标志
    header.flags.z      = 0; // 保留位，必须为0
    header.flags.ra     = 0; // 不设置递归可用标志

    header.questions      = htons(0x0001); // 一个查询问题
    header.answer_rrs     = htons(0x0000); // 没有回答资源记录
    header.authority_rrs  = htons(0x0000); // 没有授权资源记录
    header.additional_rrs = htons(0x0000); // 没有附加资源记录

    // 创建DNS查询问题
    DNS_Query question;
    // 域名转换为DNS格式，例如www.example.com转换为3www7example3com0
    uint8_t qname[] = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    question.qname  = qname        ;
    question.qtype  = htons(0x0001); // 查询类型为A记录
    question.qclass = htons(0x0001); // 查询类为IN类

    // 打印DNS请求报文（省略实现，与之前相同）

    // 这里我们只是构建了DNS请求报文的结构，实际发送和接收需要使用socket编程
    // 以下代码仅为示例，不包含实际的socket操作

    return 0;
}
```