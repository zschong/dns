# DNS_Query_qclass
```c

// 定义DNS记录类的枚举
typedef enum {
    DNS_CLASS_IN  = 1  , // Internet
    DNS_CLASS_CS  = 2  , // CSNET, 已不再使用
    DNS_CLASS_CH  = 3  , // CHAOS, 主要用于网络诊断和机器信息
    DNS_CLASS_HS  = 4  , // Hesiod, 用于DNS为基础的目录服务
    DNS_CLASS_ANY = 255  // 任意类, 用于查询所有类的记录
} dns_class_t;

const char* dns_class_name(int qclass) 
{
    switch (qclass) {
        case 1:
            return "IN (Internet)";
        case 2:
            return "CS (CSNET, obsolete)";
        case 3:
            return "CH (CHAOS)";
        case 4:
            return "HS (Hesiod)";
        case 254:
            return "NONE (None)";
        case 255:
            return "ANY (Any class)";
        default:
            return "UNKNOWN (Unknown class)";
    }
}

int main() 
{
    // 示例：打印所有DNS记录类类型的名称
    dns_class_t classes[] = {
        DNS_CLASS_IN, 
        DNS_CLASS_CS, 
        DNS_CLASS_CH, 
        DNS_CLASS_HS, 
        DNS_CLASS_ANY
    };

    for (int i = 0; i < sizeof(classes) / sizeof(classes[0]); ++i) {
        printf("DNS Record Class Type: %d - %s\n", classes[i], get_dns_class_name(classes[i]));
    }

    return 0;
}
```
在这个实现中，`dns_class_name`函数使用`switch`语句来根据`qclass`的值返回相应的字符串。每个`case`标签对应一个DNS查询类，返回的字符串包含了查询类的缩写和其含义。
DNS查询类（QCLASS）的常见取值包括：
- `IN` (1): Internet类，最常用的查询类。
- `CS` (2): CSNET类，已过时。
- `CH` (3): CHAOS类，用于CHAOS网络协议。
- `HS` (4): Hesiod类，用于Hesiod名称服务系统。
- `NONE` (254): 用于某些特殊操作，如DNSSEC。
- `ANY` (255): 任何类，用于查询所有类的记录。
如果`qclass`的值不在已定义的`case`标签中，函数将返回"UNKNOWN (Unknown class)"。
这个实现提供了基本的DNS查询类到字符串的转换，可以根据需要扩展更多的查询类。
