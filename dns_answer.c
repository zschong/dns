#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "dns_name.h"
#include "dns_answer.h"
#include "dns_hexstring.h"

bool dns_answer_init(dns_answer_t *answer)
{
    if (NULL == answer) {
        return false;
    }

    memset(answer, 0, sizeof(dns_answer_t));
    return true;
}

bool dns_answer_clear(dns_answer_t *answer)
{
    if (NULL == answer) {
        return false;
    }

    if (answer->rname) {
        free(answer->rname);
        answer->rname = NULL;
    }

    if (answer->rdata) {
        free(answer->rdata);
        answer->rdata = NULL;
    }

    memset(answer, 0, sizeof(dns_answer_t));
    return true;
}

bool dns_answer_set_name(dns_answer_t *answer, const char *name)
{
    if (NULL == answer || NULL == name) {
        return false;
    }

    size_t rname_len = strlen(name) + 1;
    char  *rname     = (char *)malloc(rname_len);
    if (NULL == rname) {
        return false;
    }

    if (dns_name_encode(name, rname, rname_len) == NULL) {
        free(rname);
        return false;
    }

    if (answer->rname) {
        free(answer->rname);
        answer->rname = NULL;
    }

    answer->rname = rname;
    return true;
}

bool dns_answer_dup_name(dns_answer_t *answer, const char *name)
{
    if (NULL == answer || NULL == name) {
        return false;
    }

    size_t rname_len = strlen(name) + 1;
    char  *rname     = (char *)malloc(rname_len);
    if (NULL == rname) {
        return false;
    }

    if (answer->rname) {
        free(answer->rname);
        answer->rname = NULL;
    }

    snprintf(rname, rname_len, "%s", name);
    answer->rname = rname;
    return true;
}

bool dns_answer_set_type(dns_answer_t *answer, dns_type_t rtype)
{
    if (NULL == answer) {
        return false;
    }

    answer->rtype = rtype;
    return true;
}

bool dns_answer_set_class(dns_answer_t *answer, dns_class_t rclass)
{
    if (NULL == answer) {
        return false;
    }

    switch(rclass) {
        case DNS_CLASS_IN:
        case DNS_CLASS_CS:
        case DNS_CLASS_CH:
        case DNS_CLASS_HS:
        case DNS_CLASS_ANY:
            answer->rclass = rclass;
            break;
        default:
            return false;
    }

    return true;
}

bool dns_answer_set_ttl(dns_answer_t *answer, uint32_t ttl)
{
    if (NULL == answer) {
        return false;
    }

    answer->rttl = ttl;
    return true;
}

bool dns_answer_set_data(dns_answer_t *answer, const uint8_t *data, uint16_t length)
{
    if (NULL == answer || NULL == data || length < 1) {
        printf("%s, %d\n", __func__, __LINE__);
        return false;
    }

    uint8_t *rdata = (uint8_t *)malloc(length);
    if (NULL == rdata) {
        printf("%s, %d\n", __func__, __LINE__);
        return false;
    }
    memcpy(rdata, data, length);

    if (answer->rdata) {
        free(answer->rdata);
        answer->rdata = NULL;
    }

    answer->rdata   = rdata;
    answer->rlength = length;
    return true;
}

const char* dns_answer_get_name(const dns_answer_t *answer)
{
    if (NULL == answer) {
        return NULL;
    }

    return answer->rname;
}

uint16_t dns_answer_get_type(const dns_answer_t *answer)
{
    if (NULL == answer) {
        return 0;
    }

    return answer->rtype;
}

uint16_t dns_answer_get_class(const dns_answer_t *answer)
{
    if (NULL == answer) {
        return 0;
    }

    return answer->rclass;
}

uint32_t dns_answer_get_ttl(const dns_answer_t *answer)
{
    if (NULL == answer) {
        return 0;
    }

    return answer->rttl;
}

uint16_t dns_answer_get_length(const dns_answer_t *answer)
{
    if (NULL == answer) {
        return 0;
    }

    return answer->rlength;
}

uint8_t *dns_answer_get_data(const dns_answer_t *answer)
{
    if (NULL == answer) {
        return NULL;
    }

    return answer->rdata;
}

uint32_t dns_answer_length(const dns_answer_t *answer)
{
    if (NULL == answer) {
        return 0;
    }

    uint32_t answer_length = 0;
    if (answer->rname) {
        answer_length = strlen(answer->rname) + 1;
    }
    answer_length += sizeof(answer->rtype);
    answer_length += sizeof(answer->rclass);
    answer_length += sizeof(answer->rttl);
    answer_length += sizeof(answer->rlength);
    answer_length += answer->rlength;

    return answer_length;
}

bool dns_answer_equal(const dns_answer_t *answer1, const dns_answer_t *answer2)
{
    if (NULL == answer1 || NULL == answer2) {
        printf("%s, %d\n", __func__, __LINE__);
        return false;
    }

    if (answer1->rtype != answer2->rtype
    || answer1->rclass != answer2->rclass
    || answer1->rttl != answer2->rttl
    || answer1->rlength != answer2->rlength
    || dns_answer_length(answer1) != dns_answer_length(answer2)
    || memcmp(answer1->rdata, answer2->rdata, answer1->rlength) != 0
    || strcmp(answer1->rname, answer2->rname) != 0) {
        printf("%s, %d\n", __func__, __LINE__);
        return false;
    }

    return true;
}

bool dns_answer_copy(dns_answer_t *dst, const dns_answer_t *src)
{
    if (NULL == dst || NULL == src) {
        printf("%s, %d\n", __func__, __LINE__);
        return false;
    }

    dns_answer_clear(dst);
    dst->rname = strdup(src->rname);
    dst->rtype = src->rtype;
    dst->rclass = src->rclass;
    dst->rttl = src->rttl;
    dst->rlength = src->rlength;
    dst->rdata = (uint8_t *)malloc(src->rlength);
    if (NULL == dst->rdata) {
        printf("%s, %d\n", __func__, __LINE__);
        dns_answer_clear(dst);
        return false;
    }
    memcpy(dst->rdata, src->rdata, src->rlength);

    return true;
}

int dns_answer_serialize(const dns_answer_t *answer, uint8_t *buf, size_t buf_size)
{
    if (NULL == answer || NULL == buf) {
        printf("%s, %d\n", __func__, __LINE__);
        return 0;
    }

    int name_len = strlen(answer->rname);
    int answer_len = dns_answer_length(answer);
    if (buf_size < answer_len) {
        printf("%s, %d\n", __func__, __LINE__);
        return 0;
    }

    uint8_t *ptr = buf;
    memcpy(ptr, answer->rname, name_len);
    ptr += name_len;
    *(ptr++) = 0; // end of name
    *(ptr++) = (answer->rtype   >> 8 ) & 0xFF;
    *(ptr++) = (answer->rtype   >> 0 ) & 0xFF;
    *(ptr++) = (answer->rclass  >> 8 ) & 0xFF;
    *(ptr++) = (answer->rclass  >> 0 ) & 0xFF;
    *(ptr++) = (answer->rttl    >> 24) & 0xFF;
    *(ptr++) = (answer->rttl    >> 16) & 0xFF;
    *(ptr++) = (answer->rttl    >> 8 ) & 0xFF;
    *(ptr++) = (answer->rttl    >> 0 ) & 0xFF;
    *(ptr++) = (answer->rlength >> 8 ) & 0xFF;
    *(ptr++) = (answer->rlength >> 0 ) & 0xFF;
    memcpy(ptr, answer->rdata, answer->rlength);
    ptr += answer->rlength;

    return ptr - buf;
}

int dns_answer_deserialize(dns_answer_t *answer, const uint8_t *data, size_t data_len)
{
    if (NULL == answer || NULL == data) {
        printf("%s, %d\n", __func__, __LINE__);
        return 0;
    }

    dns_answer_clear(answer);
    int answer_len = dns_answer_length(answer);
    if (data_len < answer_len) {
        return 0;
    }

    int name_len = strlen((const char *)data);
    if (name_len > 0) {
        answer->rname = strdup((char*)data);
        if (NULL == answer->rname) {
            printf("%s, %d\n", __func__, __LINE__);
            return 0;
        }
    }

    const uint8_t *ptr = data + name_len + 1;
    answer->rtype   =  *(ptr++) << 8 ;
    answer->rtype   |= *(ptr++)      ;
    answer->rclass  =  *(ptr++) << 8 ;
    answer->rclass  |= *(ptr++)      ;
    answer->rttl    =  *(ptr++) << 24;
    answer->rttl    |= *(ptr++) << 16;
    answer->rttl    |= *(ptr++) << 8 ;
    answer->rttl    |= *(ptr++)      ;
    answer->rlength =  *(ptr++) << 8 ;
    answer->rlength |= *(ptr++)      ;
    if (answer->rlength > 0) {
        if (dns_answer_set_data(answer, ptr, answer->rlength) == false) {
            return 0;
        }
    }
    ptr += answer->rlength;

    return ptr - data;
}

const char *dns_answer_to_string(dns_answer_t *answer, char *buf, uint32_t buf_size)
{
    if (NULL == answer) {
        printf("%s, %d\n", __func__, __LINE__);
        return NULL;
    }

    int answer_len = dns_answer_length(answer);
    int hexstr_len = (answer_len * 2 + 1);
    char *hexstr_buf = (char*)malloc(hexstr_len);
    if (NULL == hexstr_buf) {
        printf("%s, %d\n", __func__, __LINE__);
        return NULL;
    }

    uint8_t *serialize_buf = (uint8_t*)malloc(answer_len);
    if (NULL == serialize_buf) {
        free(hexstr_buf);
        return NULL;
    }

    int serialize_len = dns_answer_serialize(answer, serialize_buf, answer_len);
    if (serialize_len != answer_len) {
        free(hexstr_buf);
        free(serialize_buf);
        printf("%s, %d\n", __func__, __LINE__);
        return NULL;
    }
    const char *hexstr = dns_hexstring(serialize_buf, answer_len, hexstr_buf, hexstr_len);
    if (NULL == hexstr) {
        free(hexstr_buf);
        free(serialize_buf);
        printf("%s, %d\n", __func__, __LINE__);
        return NULL;
    }

    size_t data_hex_size = 256;
    char *data_hex = (char*)malloc(data_hex_size);
    if (NULL == data_hex) {
        free(hexstr_buf);
        free(serialize_buf);
        printf("%s, %d\n", __func__, __LINE__);
        return NULL;
    }

    size_t name_size = 256;
    char *name = (char*)malloc(name_size);
    if (NULL == name) {
        free(hexstr_buf);
        free(serialize_buf);
        free(data_hex);
        printf("%s, %d\n", __func__, __LINE__);
        return NULL;
    }

    char *decode_name = (char*)malloc(name_size);
    if (NULL == decode_name) {
        free(hexstr_buf);
        free(serialize_buf);
        free(data_hex);
        free(name);
        printf("%s, %d\n", __func__, __LINE__);
        return NULL;
    }

    snprintf(buf, buf_size, 
            "DNS Answer(%d): [%s]\n"
            "  |-Name   : %s - %s\n" 
            "  |-Type   : %u - %s\n"
            "  |-Class  : %u - %s\n"
            "  |-TTL    : %u - seconds\n"
            "  |-Length : %u - bytes\n" 
            "  |-Data   : [%s]\n",
            answer_len,
            hexstr_buf,
            dns_name_encoded_string(answer->rname, name, name_size),
            dns_name_decode(answer->rname, decode_name, name_size),
            answer->rtype,
            dns_type_name(answer->rtype ),
            answer->rclass,
            dns_class_name(answer->rclass),
            dns_answer_get_ttl(answer),
            dns_answer_get_length (answer),
            dns_hexstring(answer->rdata, answer->rlength, data_hex, data_hex_size));

    free(serialize_buf);
    free(hexstr_buf);
    free(data_hex);
    free(name);
    free(decode_name);
    return buf;
}

// #define DNS_RECORD_TEST
#ifdef DNS_RECORD_TEST
#include <stdio.h>

int main()
{
    dns_answer_t answer;

    if (dns_answer_init(&answer) == false) {
        printf("dns_answer_init failed\n");
        return 1;
    }

    if (dns_answer_set_name(&answer, "www.baidu.com") == false) {
        printf("dns_answer_set_name failed\n");
        return 1;
    }

    if (dns_answer_set_type(&answer, DNS_TYPE_A) == false) {
        printf("dns_answer_set_type failed\n");
        return 1;
    }

    if (dns_answer_set_class(&answer, DNS_CLASS_IN) == false) {
        printf("dns_answer_set_class failed\n");
        return 1;
    }

    if (dns_answer_set_ttl(&answer, 300) == false) {
        printf("dns_answer_set_ttl failed\n");
        return 1;
    }

    uint8_t ip[] = {192, 168, 1, 1};
    if (dns_answer_set_data(&answer, ip, sizeof(ip)) == false) {
        printf("dns_answer_set_data failed\n");
        return 1;
    }

    char buf[1024];
    const char *str = dns_answer_to_string(&answer, buf, sizeof(buf));
    printf("answer:%s\n", str ? str:"NULL");
    uint8_t data[1024];
    int len = dns_answer_serialize(&answer, data, sizeof(data));
    dns_answer_t answer2;
    dns_answer_init(&answer2);
    len = dns_answer_deserialize(&answer2, (uint8_t *)data, len);
    str = dns_answer_to_string(&answer2, buf, sizeof(buf));
    printf("answer2:%s\n", str ? str:"NULL");

    printf("%s\n", dns_answer_equal(&answer, &answer2) ? "answer1 == answer2" : "answer1 != answer2");
    return 0;
}
#endif // DNS_RECORD_TEST