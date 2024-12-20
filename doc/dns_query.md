# dns_query_t 操作接口
```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

// DNS查询问题结构
typedef struct {
    uint8_t *qname; // 查询名称
    uint16_t qtype; // 查询类型
    uint16_t qclass; // 查询类
} dns_query_t;

// 函数声明
void            dns_query_set_qname(dns_query_t *query, const char *domainName);
void            dns_query_set_qtype(dns_query_t *query, uint16_t qtype);
void            dns_query_set_qclass(dns_query_t *query, uint16_t qclass);
const uint8_t*  dns_query_get_qname(const dns_query_t *query);
uint16_t        dns_query_get_qtype(const dns_query_t *query);
uint16_t        dns_query_get_qclass(const dns_query_t *query);
void            dns_query_print(const dns_query_t *query);

// 函数定义
void dns_query_set_qname(dns_query_t *query, const char *domainName) {
    static uint8_t qname[256]; // 假设域名不超过255个字符
    uint8_t *ptr = qname;
    const char *token = domainName;
    while (*token) {
        const char *dot = strchr(token, '.');
        if (NULL == dot) {
            dot = token + strlen(token);
        }
        *ptr++ = (uint8_t)(dot - token); // 标签长度
        memcpy(ptr, token, dot - token); // 标签内容
        ptr += dot - token;
        token = (*dot) ? dot + 1 : dot;
    }
    *ptr = 0; // 结束符

    query->qname = qname;
}

void dns_query_set_qtype(dns_query_t *query, uint16_t qtype) {
    query->qtype = htons(qtype);
}

void dns_query_set_qclass(dns_query_t *query, uint16_t qclass) {
    query->qclass = htons(qclass);
}

const uint8_t* dns_query_get_qname(const dns_query_t *query) {
    return query->qname;
}

uint16_t dns_query_get_qtype(const dns_query_t *query) {
    return ntohs(query->qtype);
}

uint16_t dns_query_get_qclass(const dns_query_t *query) {
    return ntohs(query->qclass);
}

int main() {
    // 创建DNS查询问题
    dns_query_t query;
    dns_query_set_qname(&query, "www.example.com");
    dns_query_set_qtype(&query, 0x0001); // A记录
    dns_query_set_qclass(&query, 0x0001); // IN类

    // 打印DNS查询问题
    dns_query_print(&query);

    // 这里我们只是构建了DNS查询问题的结构，实际发送和接收需要使用socket编程
    // 以下代码仅为示例，不包含实际的socket操作

    return 0;
}
```