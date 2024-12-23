#include <stdlib.h>
#include "dns_message.h"
#include "dns_hexstring.h"

bool dns_message_init(dns_message_t *message)
{
    if (NULL == message) {
        return false;
    }

    memset(message, 0, sizeof(dns_message_t));
    return true;
}

bool dns_message_clear(dns_message_t *message)
{
    if (NULL == message) {
        return false;
    }

    if (NULL != message->queries) {
        free(message->queries);
    }

    if (NULL != message->records) {
        free(message->records);
    }

    memset(message, 0, sizeof(dns_message_t));
    return true;
}

bool dns_message_add_query(dns_message_t *message, dns_query_t *query)
{
    if (NULL == message || NULL == query) {
        return false;
    }

    if (NULL == message->queries) {
        message->queries = (dns_query_t *)malloc(sizeof(dns_query_t));
        if (NULL == message->queries) {
            return false;
        }
        memcpy(&message->queries[0], query, sizeof(dns_query_t));
        message->header.questions_count = 1;
        return true;
    }

    size_t new_size = (message->header.questions_count + 1) * sizeof(dns_query_t);
    dns_query_t *queries = (dns_query_t *)realloc(message->queries, new_size);
    if (NULL == queries) {
        return false;
    }

    memcpy(&queries[message->header.questions_count], query, sizeof(dns_query_t));
    message->queries = queries;
    message->header.questions_count += 1;
    return true;
}

/**
 * @brief 添加DNS响应
 * @param message DNS消息
 * @param record DNS响应
 * @return true 成功
 * @return false 失败
 */
bool dns_message_add_record(dns_message_t *message, dns_record_t *record)
{
    if (NULL == message || NULL == record) {
        return false;
    }

    if (NULL == message->records) {
        message->records = (dns_record_t *)malloc(sizeof(dns_record_t));
        if (NULL == message->records) {
            return false;
        }
        memcpy(&message->records[0], record, sizeof(dns_record_t));
        message->header.answers_count = 1;
        return true;
    }

    size_t new_size = (message->header.answers_count + 1) * sizeof(dns_record_t);
    dns_record_t *records = (dns_record_t *)realloc(message->records, new_size);
    if (NULL == records) {
        return false;
    }

    memcpy(&records[message->header.answers_count], record, sizeof(dns_record_t));
    message->records = records;
    message->header.answers_count += 1;
    return true;
}

/**
 * @brief 序列化DNS消息
 * @param message DNS消息
 * @param buffer 序列化后的缓冲区
 * @param buffer_size 缓冲区大小
 * @return int 序列化后的字节数，如果返0，则表示失败
 */
int  dns_message_serialize(const dns_message_t *message, uint8_t *buffer, size_t buffer_size)
{
    if (NULL == message || NULL == buffer || buffer_size < 1) {
        return 0;
    }

    int buffer_offset = 0;
    int header_offset = dns_header_serialize(&message->header, buffer, buffer_size);
    if (header_offset < 1) {
        return 0;
    }

    buffer_offset += header_offset;
    for (int i = 0; i < message->header.questions_count; i++) {
        int query_offset = dns_query_serialize(&message->queries[i], buffer + buffer_offset, buffer_size - buffer_offset);
        if (query_offset < 1) {
            return 0;
        }
        buffer_offset += query_offset;
    }

    for (int i = 0; i < message->header.answers_count; i++) {
        int record_offset = dns_record_serialize(&message->records[i], buffer + buffer_offset, buffer_size - buffer_offset);
        if (record_offset < 1) {
            return 0;
        }
        buffer_offset += record_offset;
    }

    return buffer_offset;
}

/**
 * @brief 反序列化DNS消息
 * @param message DNS消息
 * @param data 反序列化后的缓冲区
 * @param data_len 缓冲区大小
 * @return int 反序列化消耗的字节数，如果返0，则表示失败
 */
int  dns_message_deserialize(dns_message_t *message, const uint8_t *data, size_t data_len)
{
    if (NULL == message || NULL == data || data_len < 1) {
        return 0;
    }

    int data_offset = 0;
    int header_offset = dns_header_deserialize(&message->header, data, data_len);
    if (header_offset < 1) {
        return 0;
    }

    data_offset += header_offset;
    for (int i = 0; i < message->header.questions_count; i++) {
        dns_query_t query;
        dns_query_init(&query);

        int query_offset = dns_query_deserialize(&query, data + data_offset, data_len - data_offset);
        if (query_offset < 1) {
            dns_message_clear(message);
            return 0;
        }

        if (dns_message_add_query(message, &query) == false) {
            dns_message_clear(message);
            return 0;
        }

        data_offset += query_offset;
    }

    for (int i = 0; i < message->header.answers_count; i++) {
        dns_record_t record;
        dns_record_init(&record);

        int record_offset = dns_record_deserialize(&record, data + data_offset, data_len - data_offset);
        if (record_offset < 1) {
            dns_message_clear(message);
            return 0;
        }

        if (dns_message_add_record(message, &record) == false) {
            dns_message_clear(message);
            return 0;
        }

        data_offset += record_offset;
    }

    return data_offset;
}

const char* dns_message_to_string(const dns_message_t *message, char *buffer, size_t buffer_size)
{
    if (NULL == message || NULL == buffer || buffer_size < 1) {
        return NULL;
    }

    uint8_t serialize_buf[1024];
    int serialize_len = dns_message_serialize(message, serialize_buf, sizeof(serialize_buf));
    if (serialize_len < 1) {
        return NULL;
    }

    char sirerialize_hex[1024];
    const char *str = dns_hexstring(serialize_buf, serialize_len, sirerialize_hex, sizeof(sirerialize_hex));
    if (NULL == str) {
        return NULL;
    }

    int buffer_offset = snprintf(buffer, buffer_size, "DNS Message(%d): [%s]\n", serialize_len, sirerialize_hex);
    if (buffer_offset < 1) {
        return NULL;
    }

    str = dns_header_to_string(&message->header, buffer + buffer_offset, buffer_size - buffer_offset);
    if (NULL == str) {
        return NULL;
    }

    for (int i = 0; i < message->header.questions_count; i++) {
        buffer_offset = strlen(buffer);
        str = dns_query_to_string(&message->queries[i], buffer + buffer_offset, buffer_size - buffer_offset);
        if (NULL == str) {
            return NULL;
        }
    }

    for (int i = 0; i < message->header.answers_count; i++) {
        buffer_offset = strlen(buffer);
        str = dns_record_to_string(&message->records[i], buffer + buffer_offset, buffer_size - buffer_offset);
        if (NULL == str) {
            return NULL;
        }
    }

    return str;
}

#ifdef DNS_MESSAGE_TEST
#include <stdio.h>
#include "dns_flags.h"

void test_dns_message_request(void)
{
    dns_message_t msg;
    dns_header_t *header = &msg.header;

    dns_message_init(&msg);

    dns_header_set_id(header, 0x1234);
    dns_header_set_flags(header, 0);
    dns_flags_set_qr(&header->flags, DNS_QR_QUERY);
    dns_flags_set_opcode(&header->flags, DNS_OPCODE_QUERY);
    dns_flags_set_rcode(&header->flags, DNS_RCODE_NOERROR);
    dns_header_set_question_count(header, 2);
    dns_header_set_answer_count(header, 0);
    dns_header_set_authority_count(header, 0);
    dns_header_set_additional_count(header, 0);
    
    for (int i = 0; i < 2; i++) {
        dns_query_t query;
        dns_query_init(&query);
        dns_query_set_qname(&query, "www.baidu.com");
        dns_query_set_qtype(&query, DNS_TYPE_A);
        dns_query_set_qclass(&query, DNS_CLASS_IN);
        dns_message_add_query(&msg, &query);
    }

    char info_buf[1024];
    dns_message_to_string(&msg, info_buf, sizeof(info_buf));
    printf("%s\n", info_buf);

    dns_message_clear(&msg);
}

void test_dns_message_response(void)
{
    dns_message_t msg;
    dns_header_t *header = &msg.header;

    dns_message_init(&msg);

    dns_header_set_id(header, 0x1234);
    dns_header_set_flags(header, 0);
    dns_flags_set_qr(&header->flags, DNS_QR_RESPONSE);
    dns_flags_set_opcode(&header->flags, DNS_OPCODE_QUERY);
    dns_flags_set_rcode(&header->flags, DNS_RCODE_NOERROR);
    dns_header_set_question_count(header, 0);
    dns_header_set_answer_count(header, 0);
    dns_header_set_authority_count(header, 0);
    dns_header_set_additional_count(header, 0);

    for (int i = 0; i < 2; i++) {
        dns_record_t record;
        dns_record_init(&record);
        dns_record_set_name(&record, "www.baidu.com");
        dns_record_set_type(&record, DNS_TYPE_A);
        dns_record_set_class(&record, DNS_CLASS_IN);
        dns_record_set_ttl(&record, 3600);
        dns_record_set_data(&record, "192.168.1.1", 11);
        dns_message_add_record(&msg, &record);
    }

    char info_buf[1024];
    dns_message_to_string(&msg, info_buf, sizeof(info_buf));
    printf("%s\n", info_buf);

    dns_message_clear(&msg);
}

int main()
{
    test_dns_message_request();
    test_dns_message_response();
    return 0;
}
#endif