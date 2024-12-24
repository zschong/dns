# dns_question_qname
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// DNS查询结构体
typedef struct {
    unsigned char *qname; // 查询名称
    unsigned short qtype; // 查询类型
    unsigned short qclass; // 查询类
} dns_question_t;

// 函数原型声明
void  dns_question_set_qname(dns_question_t *question, const char *domain_name);
char* dns_question_get_qname(const dns_question_t *question);
void  dns_question_free_qname(unsigned char *qname);

// 主函数
int main() {
    dns_question_t question;
    const char *domain_name = "www.example.com";
    
    dns_question_set_qname(&question, domain_name);
    
    // 获取并打印转换后的QNAME
    char *decoded_domain_name = dns_question_get_qname(&question);
    printf("Decoded domain name: %s\n", decoded_domain_name);
    
    // 释放分配的内存
    dns_question_free_qname(question.qname);
    free(decoded_domain_name);
    
    return 0;
}

// dns_question_set_qname函数实现
void dns_question_set_qname(dns_question_t *question, const char *domain_name) {
    if (question == NULL || domain_name == NULL) {
        return;
    }
    
    // 计算所需内存大小
    int len = strlen(domain_name);
    int qname_len = 0;
    for (int i = 0; i < len; i++) {
        if (domain_name[i] == '.') {
            qname_len++; // 为长度字节预留空间
        }
    }
    qname_len += len + 2; // 加上最后的0和每个标签的长度字节
    
    // 分配内存
    question->qname = (unsigned char *)malloc(qname_len);
    if (question->qname == NULL) {
        return;
    }
    
    // 转换域名格式
    int pos = 0;
    for (int i = 0; i < len; i++) {
        int start = i;
        while (i < len && domain_name[i] != '.') {
            i++;
        }
        int label_len = i - start;
        question->qname[pos++] = label_len; // 设置标签长度
        memcpy(question->qname + pos, domain_name + start, label_len); // 复制标签
        pos += label_len;
    }
    question->qname[pos] = 0; // 设置结束标记
}

// dns_question_get_qname函数实现
char* dns_question_get_qname(const dns_question_t *question) {
    if (question == NULL || question->qname == NULL) {
        return NULL;
    }
    
    // 计算解码后的域名长度
    int len = 0;
    for (int i = 0; question->qname[i] != 0; ) {
        int label_len = question->qname[i];
        len += label_len + 1; // 加上标签长度和点号
        i += label_len + 1;
    }
    
    // 分配内存
    char *domain_name = (char *)malloc(len);
    if (domain_name == NULL) {
        return NULL;
    }
    
    // 解码QNAME
    int pos = 0;
    for (int i = 0; question->qname[i] != 0; ) {
        int label_len = question->qname[i];
        memcpy(domain_name + pos, question->qname + i + 1, label_len); // 复制标签
        pos += label_len;
        domain_name[pos++] = '.'; // 添加点号
        i += label_len + 1;
    }
    domain_name[pos - 1] = '\0'; // 设置字符串结束标记
    
    return domain_name;
}

// dns_question_free_qname函数实现
void dns_question_free_qname(unsigned char *qname) {
    if (qname != NULL) {
        free(qname);
    }
}
```