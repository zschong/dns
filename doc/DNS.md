# DNS 请求流程

```shell
+----------------+   query    +--------------------+
|   Nameserver   |<-----------|        User        |
| 192.168.18.135 |            |   192.168.18.136   |
| (example.com.) |----------->| (user.example.com) |
+----------------+   answer   +--------------------+
```

## DNS 查询响应报文的格式
```shell
|<--    16    -->|<--    16    -->|(bit)
+----------------+----------------+---
|       ID       |      FLAG      | ^
+----------------+----------------+ |
|     QDCOUNT    |     ANCOUNT    | |
+----------------+----------------+
|     NSCOUNT    |     ARCOUNT    |
+----------------+----------------+
|             QUESTIONs           | 12bytes
+---------------------------------+
|              ANSWERs            |
+---------------------------------+
|            AUTHORITYs           | |
+---------------------------------+ |
|            ADDITIONALs          | v
+---------------------------------+---
```

### FLAG
```shell
  +-----+---------+-----+-----+-----+-----+-------+--------+
  |QR(1)|opcode(4)|AA(1)|TC(1)|RD(1)|RA(1)|zero(3)|rcode(4)|
  +-----+---------+-----+-----+-----+-----+-------+--------+
```
| 字段      | 说明                                                                                          |
| --------- | --------------------------------------------------------------------------------------------- |
| QR        | 0 表示查询报文，1 表示响应报文。|
| opcode    |0 表示标准查询，1 为反向查询，2 为服务器状态请求，3 暂无定义，4 为通知 (Notify)，5 为更新 (Update)，6-15 暂无定义
| AA        |表示 “授权回答 (authoritative answer)”。该名字服务器是授权于该域的。|
| TC        |表示 “可截断的 (truncated)”。使用 UDP 时，它表示当应答的总长度超过 512 字节时，只返回前 512 字节。|
| RD        |表示 “期望递归 (recursion desired)”。该比特能在一个查询中设置，并在响应中返回。这个标志告诉名字服务器必须处理这个查询，也称为一个递归查询。如果该位为 0，且被请求的名字服务器没有一个 授权回答，它就返回一个能解答该查询的其他名字服务器列表，这称为迭代查询。在后面的例子中，我们将看到这两种类型查询的例子。
| RA      |表示 “可用递归”。如果名字服务器支持递归查询，则在响应中将该比特设置为 1。在后面的例子中可看到大多数名字服务器都提供递归查询，除了某些根服务器。|
| zero    |必须设置为 0，预留给将来的需求|
| rcode   |表示返回码，0 为没有差错，1 为格式错误，2 为服务端失败，3 为不存在的域名，4 为无法执行，5 为请求拒绝，6 为域名异常存在 (不应存在)，7 为解析记录异常|存在 (不应存在)，8 为解析记录异 常不存在 (应存在)，9 为名字服务器不能认证该请求区域，10 为请求的域不在区域文件中|
```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// DNS报文头部结构体
typedef struct {
    uint16_t transaction_id;
    uint16_t flags         ;
    uint16_t questions     ;
    uint16_t answer_rrs    ;
    uint16_t authority_rrs ;
    uint16_t additional_rrs;
} dns_header_t;

// 位域结构体用于表示flags字段
typedef struct {
    uint16_t rcode  : 4; // 响应代码（Response code）
    uint16_t z      : 3; // 保留字段，必须为0
    uint16_t ra     : 1; // recursion available（递归可用）
    uint16_t rd     : 1; // recursion desired（期望递归）
    uint16_t tc     : 1; // truncated（报文截断）
    uint16_t aa     : 1; // authoritative answer（权威回答）
    uint16_t opcode : 4;// 操作码（Operation code）
    uint16_t qr     : 1; // 查询/响应标志（Query/Response）
} dns_flags_t;

// 函数用于打印DNS报文头部
void dns_header_print(const dns_header_t *header) {
    dns_flags_t flags;
    memcpy(&flags, &header->flags, sizeof(flags));

    printf("DNS Header:\n");
    printf("Transaction ID: 0x%04X\n"                                                                          , header->transaction_id );
    printf("Flags: 0x%04X\n"                                                                                   , header->flags          );
    printf("  QR    : %u (Query/Response: 0=Query, 1=Response)\n"                                              , flags . qr             );
    printf("  OPCODE: %u (Operation Code: 0=Standard query, 1=Inverse query, 2=Server status request, etc.)\n" , flags . opcode         );
    printf("  AA    : %u (Authoritative Answer: 0=Not authoritative, 1=Authoritative)\n"                       , flags . aa             );
    printf("  TC    : %u (Truncated: 0=Not truncated, 1=Truncated)\n"                                          , flags . tc             );
    printf("  RD    : %u (Recursion Desired: 0=No recursion, 1=Recursion desired)\n"                           , flags . rd             );
    printf("  RA    : %u (Recursion Available: 0=Recursion not available, 1=Recursion available)\n"            , flags . ra             );
    printf("  Z     : %u (Reserved: Must be 0)\n"                                                              , flags . z              );
    printf("  RCODE : %u (Response Code: 0=No error, 1=Format error, 2=Server failure, etc.)\n"                , flags . rcode          );
    printf("Questions: %u\n"                                                                                   , header->questions      );
    printf("Answer RRs: %u\n"                                                                                  , header->answer_rrs     );
    printf("Authority RRs: %u\n"                                                                               , header->authority_rrs  );
    printf("Additional RRs: %u\n"                                                                              , header->additional_rrs );
}

int main() {
    // 创建一个DNS报文头部实例
    dns_header_t header;
    memset(&header, 0, sizeof(header)); // 初始化所有字段为0

    // 设置事务ID
    header.transaction_id = 0x1234; // 示例事务ID

    // 设置flags字段的各个位域
    dns_flags_t flags;
    flags.qr     = 1; // QR=1，表示这是一个响应报文
    flags.opcode = 0; // OPCODE=0，标准查询
    flags.aa     = 1; // AA=1，表示这是一个权威回答
    flags.tc     = 0; // TC=0，表示报文未截断
    flags.rd     = 1; // RD=1，表示请求递归查询
    flags.ra     = 1; // RA=1，表示服务器支持递归查询
    flags.z      = 0; // Z=0，保留字段，必须为0
    flags.rcode  = 0; // RCODE=0，表示没有错误

    // 将位域结构体复制到header的flags字段
    memcpy(&header.flags, &flags, sizeof(flags));

    // 设置问题、回答、授权和附加资源记录数
    header.questions      = 1;
    header.answer_rrs     = 0;
    header.authority_rrs  = 0;
    header.additional_rrs = 0;

    // 打印DNS报文头部
    dns_header_print(&header);

    return 
```