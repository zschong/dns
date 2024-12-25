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

    for (int i = 0; i < message->header.questions_count; i++) {
        dns_question_clear(&message->questions[i]);
    }

    if (NULL != message->questions) {
        free(message->questions);
        message->questions = NULL;
    }

    for (int i = 0; i < message->header.answers_count; i++) {
        dns_answer_clear(&message->answers[i]);
    }

    if (NULL != message->answers) {
        free(message->answers);
        message->answers = NULL;
    }

    memset(message, 0, sizeof(dns_message_t));
    return true;
}

bool dns_message_add_question(dns_message_t *message, const dns_question_t *question)
{
    if (NULL == message || NULL == question) {
        return false;
    }

    // if (message->answers) {
    //     free(message->answers);
    //     message->answers = NULL;
    //     message->header.answers_count = 0;
    // }

    if (NULL == message->questions) {
        dns_question_t *questions = (dns_question_t *)malloc(sizeof(dns_question_t));
        if (NULL == questions) {
            return false;
        }
        dns_question_init(&questions[0]);
        dns_question_copy(&questions[0], question);
        message->header.questions_count = 1;
        message->questions = questions;
        return true;
    }

    size_t new_size = (message->header.questions_count + 1) * sizeof(dns_question_t);
    dns_question_t *questions = (dns_question_t *)realloc(message->questions, new_size);
    if (NULL == questions) {
        return false;
    }

    dns_question_init(&questions[message->header.questions_count]);
    dns_question_copy(&questions[message->header.questions_count], question);
    message->header.questions_count += 1;
    message->questions = questions;
    return true;
}

/**
 * @brief 添加DNS响应
 * @param message DNS消息
 * @param answer DNS响应
 * @return true 成功
 * @return false 失败
 */
bool dns_message_add_answer(dns_message_t *message, const dns_answer_t *answer)
{
    if (NULL == message || NULL == answer) {
        return false;
    }

    // if (message->questions) {
    //     free(message->questions);
    //     message->questions = NULL;
    //     message->header.questions_count = 0;
    // }

    if (NULL == message->answers) {
        dns_answer_t *answers = (dns_answer_t *)malloc(sizeof(dns_answer_t));
        if (NULL == answers) {
            return false;
        }
        dns_answer_init(&answers[0]);
        dns_answer_copy(&answers[0], answer);
        message->header.answers_count = 1;
        message->answers = answers;
        return true;
    }

    size_t new_size = (message->header.answers_count + 1) * sizeof(dns_answer_t);
    dns_answer_t *answers = (dns_answer_t *)realloc(message->answers, new_size);
    if (NULL == answers) {
        return false;
    }

    dns_answer_init(&answers[message->header.answers_count]);
    dns_answer_copy(&answers[message->header.answers_count], answer);
    message->header.answers_count += 1;
    message->answers = answers;
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
        printf("%s, %d\n", __func__, __LINE__);
        return 0;
    }

    int buffer_offset = 0;
    int header_offset = dns_header_serialize(&message->header, buffer, buffer_size);
    if (header_offset < 1) {
        printf("%s, %d\n", __func__, __LINE__);
        return 0;
    }

    buffer_offset += header_offset;
    for (int i = 0; i < message->header.questions_count; i++) {
        int question_offset = dns_question_serialize(&message->questions[i], buffer + buffer_offset, buffer_size - buffer_offset);
        if (question_offset < 1) {
            printf("%s, %d\n", __func__, __LINE__);
            return 0;
        }
        buffer_offset += question_offset;
    }

    for (int i = 0; i < message->header.answers_count; i++) {
        int answer_offset = dns_answer_serialize(&message->answers[i], buffer + buffer_offset, buffer_size - buffer_offset);
        if (answer_offset < 1) {
            printf("%s, %d\n", __func__, __LINE__);
            return 0;
        }
        buffer_offset += answer_offset;
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
        printf("%s, %d\n", __func__, __LINE__);
        return 0;
    }

    int data_offset = 0;
    int header_offset = dns_header_deserialize(&message->header, data, data_len);
    if (header_offset < 1) {
        printf("%s, %d\n", __func__, __LINE__);
        return 0;
    }

    data_offset += header_offset;
    for (int i = 0; i < message->header.questions_count; i++) {
        dns_question_t question;
        dns_question_init(&question);

        int question_offset = dns_question_deserialize(&question, data + data_offset, data_len - data_offset);
        if (question_offset < 1) {
            dns_message_clear(message);
            printf("%s, %d\n", __func__, __LINE__);
            return 0;
        }

        if (dns_message_add_question(message, &question) == false) {
            dns_message_clear(message);
            printf("%s, %d\n", __func__, __LINE__);
            return 0;
        }

        data_offset += question_offset;
    }

    for (int i = 0; i < message->header.answers_count; i++) {
        dns_answer_t answer;
        dns_answer_init(&answer);

        int answer_offset = dns_answer_deserialize(&answer, data + data_offset, data_len - data_offset);
        if (answer_offset < 1) {
            dns_message_clear(message);
            printf("%s, %d\n", __func__, __LINE__);
            return 0;
        }

        if (dns_message_add_answer(message, &answer) == false) {
            dns_message_clear(message);
            printf("%s, %d\n", __func__, __LINE__);
            return 0;
        }

        data_offset += answer_offset;
        dns_answer_clear(&answer);
    }

    return data_offset;
}

const char* dns_message_to_string(const dns_message_t *message, char *buffer, size_t buffer_size)
{
    if (NULL == message || NULL == buffer || buffer_size < 1) {
        return NULL;
    }

    size_t serialize_size = 1024;
    uint8_t *serialize_buf = (uint8_t *)malloc(serialize_size);
    if (NULL == serialize_buf) {
        printf("dns_message_to_string malloc serialize_buf failed\n");
        return NULL;
    }

    int serialize_len = dns_message_serialize(message, serialize_buf, serialize_size);
    if (serialize_len < 1) {
        printf("dns_message_to_string dns_message_serialize failed\n");
        free(serialize_buf);
        return NULL;
    }

    size_t sirerialize_hex_size = 1024;
    char *sirerialize_hex = (char *)malloc(sirerialize_hex_size);
    if (NULL == sirerialize_hex) {
        printf("dns_message_to_string malloc sirerialize_hex failed\n");
        free(serialize_buf);
        return NULL;
    }

    const char *str = dns_hexstring(serialize_buf, serialize_len, sirerialize_hex, sirerialize_hex_size);
    if (NULL == str) {
        printf("dns_message_to_string dns_hexstring failed\n");
        free(serialize_buf);
        free(sirerialize_hex);
        return NULL;
    }

    int buffer_offset = snprintf(buffer, buffer_size, "DNS Message(%d): [%s]\n", serialize_len, sirerialize_hex);
    if (buffer_offset < 1) {
        printf("dns_message_to_string snprintf failed\n");
        free(serialize_buf);
        free(sirerialize_hex);
        return NULL;
    }

    str = dns_header_to_string(&message->header, buffer + buffer_offset, buffer_size - buffer_offset);
    if (NULL == str) {
        printf("dns_message_to_string dns_header_to_string failed\n");
        free(serialize_buf);
        free(sirerialize_hex);
        return NULL;
    }

    for (int i = 0; i < message->header.questions_count; i++) {
        buffer_offset = strlen(buffer);
        str = dns_question_to_string(&message->questions[i], buffer + buffer_offset, buffer_size - buffer_offset);
        if (NULL == str) {
            printf("dns_message_to_string dns_question_to_string failed\n");
            free(serialize_buf);
            free(sirerialize_hex);
            return NULL;
        }
    }

    for (int i = 0; i < message->header.answers_count; i++) {
        buffer_offset = strlen(buffer);
        str = dns_answer_to_string(&message->answers[i], buffer + buffer_offset, buffer_size - buffer_offset);
        if (NULL == str) {
            printf("dns_message_to_string dns_answer_to_string failed\n");
            free(serialize_buf);
            free(sirerialize_hex);
            return NULL;
        }
    }
    
    free(serialize_buf);
    free(sirerialize_hex);
    return buffer;
}

#ifdef DNS_MESSAGE_TEST
#include <stdio.h>
#include "dns_flags.h"
#include "dns_hexstring.h"

#define SHOW_BUFFER_SIZE (4*1024)

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
        dns_question_t question;
        dns_question_init(&question);
        dns_question_set_qname(&question, "www.baidu.com");
        dns_question_set_qtype(&question, DNS_TYPE_A);
        dns_question_set_qclass(&question, DNS_CLASS_IN);
        dns_message_add_question(&msg, &question);
    }

    char info_buf[SHOW_BUFFER_SIZE];
    dns_message_to_string(&msg, info_buf, sizeof(info_buf));
    printf("%s\n", info_buf);

    uint8_t sirerialize_buf[SHOW_BUFFER_SIZE];
    int serialize_len = dns_message_serialize(&msg, sirerialize_buf, sizeof(sirerialize_buf));
    if (serialize_len > 0) {
        dns_message_t msg2;
        dns_message_init(&msg2);
        dns_message_deserialize(&msg2, sirerialize_buf, serialize_len);
        dns_message_to_string(&msg2, info_buf, sizeof(info_buf));
        printf("msg2 hex:\n%s\n", info_buf);
    }

    dns_message_clear(&msg);
}

void test_dns_message_anser(void)
{
    dns_message_t msg;
    dns_header_t *header = &msg.header;

    dns_message_init(&msg);

    dns_header_set_id(header, 0x1234);
    dns_header_set_flags(header, 0);
    dns_flags_set_qr(&header->flags, DNS_QR_RESPONSE);
    dns_flags_set_opcode(&header->flags, DNS_OPCODE_QUERY);
    dns_flags_set_rcode(&header->flags, DNS_RCODE_NOERROR);
    dns_header_set_question_count(header, 1);
    dns_header_set_answer_count(header, 0);
    dns_header_set_authority_count(header, 0);
    dns_header_set_additional_count(header, 0);
  
    dns_question_t question;
    dns_question_init(&question);
    dns_question_set_qname(&question, "apmode.enplus.com");
    dns_question_set_qtype(&question, DNS_TYPE_A);
    dns_question_set_qclass(&question, DNS_CLASS_IN);
    dns_message_add_question(&msg, &question);

    for (int i = 0; i < 1; i++) {
        dns_answer_t answer;
        dns_answer_init(&answer);
        // dns_answer_set_name(&answer, "apmode.enplus.com");
        dns_answer_dup_name(&answer, question.qname);
        dns_answer_set_type(&answer, DNS_TYPE_A);
        dns_answer_set_class(&answer, DNS_CLASS_IN);
        dns_answer_set_ttl(&answer, 3600);
        uint8_t ip[] = {192, 168, 4, 1};
        dns_answer_set_data(&answer, ip, sizeof(ip));
        dns_message_add_answer(&msg, &answer);
        dns_answer_clear(&answer);
    }
    dns_question_clear(&question);

    char info_buf[SHOW_BUFFER_SIZE];
    dns_message_to_string(&msg, info_buf, sizeof(info_buf));
    printf("%s\n", info_buf);

    uint8_t sirerialize_buf[SHOW_BUFFER_SIZE];
    int serialize_len = dns_message_serialize(&msg, sirerialize_buf, sizeof(sirerialize_buf));
    if (serialize_len > 0) {
        dns_message_t msg2;
        dns_message_init(&msg2);
        dns_message_deserialize(&msg2, sirerialize_buf, serialize_len);
        dns_message_to_string(&msg2, info_buf, sizeof(info_buf));
        printf("%s mst2:\n%s\n", __func__, info_buf);
    }

    dns_message_clear(&msg);
}

int main()
{
    test_dns_message_request();
    test_dns_message_anser();
    return 0;
}
#endif