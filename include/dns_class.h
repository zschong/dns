#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// 定义DNS记录类的枚举
typedef enum {
    DNS_CLASS_IN  = 1  , // Internet
    DNS_CLASS_CS  = 2  , // CSNET, 已不再使用
    DNS_CLASS_CH  = 3  , // CHAOS, 主要用于网络诊断和机器信息
    DNS_CLASS_HS  = 4  , // Hesiod, 用于DNS为基础的目录服务
    DNS_CLASS_ANY = 255  // 任意类, 用于查询所有类的记录
} dns_class_t;


// 根据DNS记录类返回类名
const char* dns_class_name(dns_class_t qclass);

#ifdef __cplusplus
}
#endif