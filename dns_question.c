#include <stdlib.h>
#include <string.h>
#include "dns_class.h"
#include "dns_question.h"
#include "dns_type.h"
#include "dns_name.h"
#include "dns_hexstring.h"

bool dns_question_init(dns_question_t *question)
{
    if (NULL == question) {
        return false;
    }

    question->qname = NULL;
    question->qtype = 0;
    question->qclass = 0;
    return true;
}

bool dns_question_clear(dns_question_t *question)
{
    if (NULL == question) {
        return false;
    }

    if (question->qname) {
        free(question->qname);
        question->qname = NULL;
    }

    question->qtype = 0;
    question->qclass = 0;
    return true;
}

bool dns_question_set_qname(dns_question_t *question, const char *domain_name)
{
    if (NULL == question || NULL == domain_name) {
        return false;
    }

    char buf[256] = {0};
    const char *ptr = dns_name_encode(domain_name, buf, sizeof(buf));
    if (NULL == ptr) {
        return false;
    }

    if (question->qname) {
        free(question->qname);
    }

    question->qname = strdup(buf);
    return !!question->qname;
}

bool dns_question_set_qtype(dns_question_t *question, dns_type_t qtype)
{
    if (NULL == question) {
        return false;
    }
    question->qtype = (qtype);
    return true;
}

bool dns_question_set_qclass(dns_question_t *question, dns_class_t qclass)
{
    if (NULL == question) {
        return false;
    }
    question->qclass = (qclass);
    return true;
}

const char *dns_question_get_qname(const dns_question_t *question)
{
    if (NULL == question) {
        return NULL;
    }
    return question->qname;
}

dns_type_t dns_question_get_qtype(const dns_question_t *question)
{
    if (NULL == question) {
        return 0;
    }
    return (dns_type_t)(question->qtype);
}

dns_class_t dns_question_get_qclass(const dns_question_t *question)
{
    if (NULL == question) {
        return 0;
    }
    return (dns_class_t)(question->qclass);
}

uint32_t dns_question_length(const dns_question_t *question)
{
    if (NULL == question || NULL == question->qname) {
        return 0;
    }

    uint32_t question_length = 0;
    if (question->qname) {
        question_length += strlen(question->qname) + 1;
    }
    question_length += sizeof(question->qtype);
    question_length += sizeof(question->qclass);

    return question_length;
}

bool dns_question_equal(const dns_question_t *question1, const dns_question_t *question2)
{
    if (NULL == question1 || NULL == question2) {
        printf("question1 or question2 is NULL\n");
        return false;
    }

    if (question1->qtype != question2->qtype) {
        printf("question1->qtype(%d) != question2->qtype(%d)\n", question1->qtype, question2->qtype);
        return false;
    }

    if (question1->qclass != question2->qclass) {
        printf("question1->qclass(%d) != question2->qclass(%d)\n", question1->qclass, question2->qclass);
        return false;
    }

    if (NULL == question1->qname || NULL == question2->qname) {
        printf("question1->qname or question2->qname is NULL\n");
        return false;
    }

    if (question1->qname == question2->qname) {
        return true;
    }

    if (dns_question_length(question1) != dns_question_length(question2)) {
        printf("dns_question_length(question1) != dns_question_length(question2)\n");
        return false;
    }

    return strcmp(question1->qname, question2->qname) == 0;
}

bool dns_question_copy(dns_question_t *dst, const dns_question_t *src)
{
    if (NULL == dst || NULL == src) {
        return false;
    }

    if (NULL == src->qname) {
        return false;
    }

    if (dst->qname) {
        free(dst->qname);
    }

    dst->qname = strdup(src->qname);
    dst->qtype = src->qtype;
    dst->qclass = src->qclass;
    return true;
}

int dns_question_serialize(const dns_question_t *question, uint8_t *buf, uint16_t buf_size)
{
    if (NULL == question || NULL == question->qname || NULL == buf) {
        return 0;
    }

    int question_len = dns_question_length(question);
    if (buf_size < question_len) {
        return 0;
    }

    strcpy((char*)buf, question->qname);

    uint8_t *ptr = (uint8_t*)buf;
    ptr += strlen(question->qname);
    *(ptr++) = 0; // end of name
    *(ptr++) = (question->qtype  >> 8) & 0xFF;
    *(ptr++) =  question->qtype        & 0xFF;
    *(ptr++) = (question->qclass >> 8) & 0xFF;
    *(ptr++) =  question->qclass       & 0xFF;

    return ptr - buf;
}


int dns_question_deserialize(dns_question_t *question, const uint8_t *data, uint16_t data_len)
{
    if (NULL == question || NULL == data) {
        return 0;
    }

    dns_question_clear(question);

    int name_len = strlen((char*)data) + 1;
    if (data_len < (name_len + dns_question_length(question))) {
        return 0;
    }

    question->qname = strdup((char*)data);
    if (NULL == question->qname) {
        return 0;
    }

    uint8_t *ptr = (uint8_t*)data;
    ptr += name_len;
    question->qtype  =  *(ptr++) << 8;
    question->qtype  |= *(ptr++)     ;
    question->qclass =  *(ptr++) << 8;
    question->qclass |= *(ptr++)     ;

    return ptr - data;
}

const char *dns_question_to_string(const dns_question_t *question, char *buf, uint32_t buf_size)
{
    if (NULL == question || NULL == question->qname || NULL == buf) {
        return NULL;
    }

    int question_len = dns_question_length(question);
    if (question_len < 1 || buf_size < question_len * 3) {
        return NULL;
    }

    uint8_t *serialize_buf = (uint8_t*)malloc(question_len);
    if (NULL == serialize_buf) {
        return NULL;
    }

    int serialize_len = dns_question_serialize(question, serialize_buf, question_len);
    if (serialize_len < 1) {
        free(serialize_buf);
        return NULL;
    }

    char *hexstr_buf = (char*)malloc(serialize_len * 2 + 1);
    if (NULL == hexstr_buf) {
        free(serialize_buf);
        return NULL;
    }

    const char *hexstr = dns_hexstring(serialize_buf, serialize_len, hexstr_buf, serialize_len * 2 + 1);
    if (NULL == hexstr) {
        free(serialize_buf);
        free(hexstr_buf);
        return NULL;
    }

    char name_unencoded[256] = {0};
    char name_encoded[256] = {0};
    snprintf(buf,
             buf_size,
             "DNS Question(%d): [%s]\n"
             "  |-qname  : %s - %s\n"
             "  |-qtype  : %u - %s\n"
             "  |-qclass : %u - %s\n",
             question_len,
             hexstr_buf,
             dns_name_encoded_string(question->qname, name_encoded, sizeof(name_encoded)),
             dns_name_decode(question->qname, name_unencoded, sizeof(name_unencoded)),
             question->qtype,
             dns_type_name(question->qtype),
             question->qclass,
             dns_class_name(question->qclass));

    free(serialize_buf);
    free(hexstr_buf);
    
    return buf;
}

#ifdef DNS_QUERY_TEST
int main(int argc, char **argv)
{
    dns_question_t question;
    char        buf[1024];

    memset(&question, 0, sizeof(question));

    dns_question_set_qname(&question, "a.looooooooooong.example.com");
    dns_question_set_qtype(&question, DNS_TYPE_A);
    dns_question_set_qclass(&question, DNS_CLASS_IN);

    dns_question_to_string(&question, buf, sizeof(buf));
    printf("%s\n", buf);
    uint8_t serialize_buf[1024];
    int     serialize_len = dns_question_serialize(&question, serialize_buf, sizeof(serialize_buf));
    dns_question_t question2;
    dns_question_init(&question2);
    dns_question_deserialize(&question2, serialize_buf, serialize_len);
    dns_question_to_string(&question2, buf, sizeof(buf));
    printf("%s\n", buf);
    printf("%s\n", dns_question_equal(&question, &question2) ? "question == qeury2" : "question != question2");

    return 0;
}
#endif