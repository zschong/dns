#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "dns_name.h"
#include "dns_answer.h"
#include "dns_hexstring.h"

bool dns_answer_init(dns_answer_t *record)
{
    if (record == NULL) {
        return false;
    }

    memset(record, 0, sizeof(dns_answer_t));
    return true;
}

bool dns_answer_clear(dns_answer_t *record)
{
    if (record == NULL) {
        return false;
    }

    if (record->rname) {
        free(record->rname);
        record->rname = NULL;
    }

    if (record->rdata) {
        free(record->rdata);
        record->rdata = NULL;
    }

    memset(record, 0, sizeof(dns_answer_t));
    return true;
}

bool dns_answer_set_name(dns_answer_t *record, const char *name)
{
    if (NULL == record || NULL == name) {
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

    if (record->rname) {
        free(record->rname);
        record->rname = NULL;
    }

    record->rname = rname;
    return true;
}

bool dns_answer_set_type(dns_answer_t *record, dns_type_t rtype)
{
    if (record == NULL) {
        return false;
    }

    record->rtype = rtype;
    return true;
}

bool dns_answer_set_class(dns_answer_t *record, dns_class_t rclass)
{
    if (record == NULL) {
        return false;
    }

    switch(rclass) {
        case DNS_CLASS_IN:
        case DNS_CLASS_CS:
        case DNS_CLASS_CH:
        case DNS_CLASS_HS:
        case DNS_CLASS_ANY:
            record->rclass = rclass;
            break;
        default:
            return false;
    }

    return true;
}

bool dns_answer_set_ttl(dns_answer_t *record, uint32_t ttl)
{
    if (record == NULL) {
        return false;
    }

    record->rttl = ttl;
    return true;
}

bool dns_answer_set_data(dns_answer_t *record, const uint8_t *data, uint16_t length)
{
    if (NULL == record || NULL == data || length < 1) {
        return false;
    }

    uint8_t *rdata = (uint8_t *)malloc(length);
    if (NULL == rdata) {
        return false;
    }
    memcpy(rdata, data, length);

    if (record->rdata) {
        free(record->rdata);
        record->rdata = NULL;
    }

    record->rdata     = rdata;
    record->rlength = length;
    return true;
}

const char* dns_answer_get_name(const dns_answer_t *record)
{
    if (NULL == record) {
        return NULL;
    }

    return record->rname;
}

uint16_t dns_answer_get_type(const dns_answer_t *record)
{
    if (NULL == record) {
        return 0;
    }

    return record->rtype;
}

uint16_t dns_answer_get_class(const dns_answer_t *record)
{
    if (NULL == record) {
        return 0;
    }

    return record->rclass;
}

uint32_t dns_answer_get_ttl(const dns_answer_t *record)
{
    if (NULL == record) {
        return 0;
    }

    return record->rttl;
}

uint16_t dns_answer_get_length(const dns_answer_t *record)
{
    if (NULL == record) {
        return 0;
    }

    return record->rlength;
}

uint8_t *dns_answer_get_data(const dns_answer_t *record)
{
    if (NULL == record) {
        return NULL;
    }

    return record->rdata;
}

uint32_t dns_answer_length(const dns_answer_t *record)
{
    if (NULL == record) {
        return 0;
    }

    int ptr_len = sizeof(record->rname) + sizeof(record->rdata);
    int data_len = record->rlength;
    int name_len = 0;
    if (record->rname) {
        name_len = strlen(record->rname) + 1;
    }

    return sizeof(dns_answer_t) + name_len + data_len - ptr_len;
}

bool dns_answer_equal(const dns_answer_t *record1, const dns_answer_t *record2)
{
    if (NULL == record1 || NULL == record2) {
        return false;
    }

    if (record1->rtype != record2->rtype
    || record1->rclass != record2->rclass
    || record1->rttl != record2->rttl
    || record1->rlength != record2->rlength
    || dns_answer_length(record1) != dns_answer_length(record2)
    || memcmp(record1->rdata, record2->rdata, record1->rlength) != 0
    || strcmp(record1->rname, record2->rname) != 0) {
        return false;
    }

    return true;
}

int dns_answer_serialize(const dns_answer_t *record, uint8_t *buf, size_t buf_size)
{
    if (NULL == record || NULL == buf) {
        return 0;
    }

    int name_len = strlen(record->rname) + 1;
    int record_len = dns_answer_length(record);
    if (buf_size < record_len) {
        return 0;
    }

    uint8_t *ptr = buf;
    memcpy(ptr, record->rname, name_len);
    ptr += name_len;
    *(ptr++) = (record->rtype   >> 8 ) & 0xFF;
    *(ptr++) = (record->rtype   >> 0 ) & 0xFF;
    *(ptr++) = (record->rclass  >> 8 ) & 0xFF;
    *(ptr++) = (record->rclass  >> 0 ) & 0xFF;
    *(ptr++) = (record->rttl    >> 24) & 0xFF;
    *(ptr++) = (record->rttl    >> 16) & 0xFF;
    *(ptr++) = (record->rttl    >> 8 ) & 0xFF;
    *(ptr++) = (record->rttl    >> 0 ) & 0xFF;
    *(ptr++) = (record->rlength >> 8 ) & 0xFF;
    *(ptr++) = (record->rlength >> 0 ) & 0xFF;
    memcpy(ptr, record->rdata, record->rlength);

    return record_len;
}

int dns_answer_deserialize(dns_answer_t *record, const uint8_t *data, size_t data_len)
{
    if (NULL == record || NULL == data) {
        return 0;
    }

    dns_answer_clear(record);
    int record_len = dns_answer_length(record);
    if (data_len < record_len) {
        return 0;
    }

    int name_len = strlen((const char *)data) + 1;
    if (name_len > 1) {
        record->rname = strdup((char*)data);
        if (NULL == record->rname) {
            return 0;
        }
    }

    const uint8_t *ptr = data + name_len;
    record->rtype   =  *(ptr++) << 8 ;
    record->rtype   |= *(ptr++)      ;
    record->rclass  =  *(ptr++) << 8 ;
    record->rclass  |= *(ptr++)      ;
    record->rttl    =  *(ptr++) << 24;
    record->rttl    |= *(ptr++) << 16;
    record->rttl    |= *(ptr++) << 8 ;
    record->rttl    |= *(ptr++)      ;
    record->rlength =  *(ptr++) << 8 ;
    record->rlength |= *(ptr++)      ;
    if (record->rlength > 0) {
        if (dns_answer_set_data(record, ptr, record->rlength) == false) {
            return 0;
        }
    }

    return ptr - data;
}

const char *dns_answer_to_string(dns_answer_t *record, char *buf, uint32_t buf_size)
{
    if (NULL == record) {
        return NULL;
    }

    int record_len = dns_answer_length(record);
    int hexstr_len = (record_len * 2 + 1);
    char *hexstr_buf = (char*)malloc(hexstr_len);
    if (NULL == hexstr_buf) {
        return NULL;
    }

    uint8_t *serialize_buf = (uint8_t*)malloc(record_len);
    if (NULL == serialize_buf) {
        free(hexstr_buf);
        return NULL;
    }

    int serialize_len = dns_answer_serialize(record, serialize_buf, record_len);
    if (serialize_len != record_len) {
        free(hexstr_buf);
        free(serialize_buf);
        return NULL;
    }
    const char *hexstr = dns_hexstring(serialize_buf, record_len, hexstr_buf, hexstr_len);
    if (NULL == hexstr) {
        free(hexstr_buf);
        free(serialize_buf);
        return NULL;
    }

    size_t data_hex_size = 256;
    uint8_t *data_hex = (uint8_t*)malloc(data_hex_size);
    if (NULL == data_hex) {
        free(hexstr_buf);
        free(serialize_buf);
        return NULL;
    }

    size_t name_size = 256;
    char *name = (char*)malloc(name_size);
    if (NULL == name) {
        free(hexstr_buf);
        free(serialize_buf);
        free(data_hex);
        return NULL;
    }

    snprintf(buf, buf_size, 
            "DNS Record(%d): [%s]\n"
            "  |-Name  : %s\n" 
            "  |-Type  : %u - %s\n"
            "  |-Class : %u - %s\n"
            "  |-TTL   : %u\n"
            "  |-Length: %u\n" 
            "  |-Data  : [%s]\n",
            record_len,
            hexstr_buf,
            dns_name_encoded_string(record->rname, name, name_size),
            record->rtype,
            dns_type_name(record->rtype ),
            record->rclass,
            dns_class_name(record->rclass),
            dns_answer_get_ttl(record),
            dns_answer_get_length (record),
            dns_hexstring(record->rdata, record->rlength, data_hex, data_hex_size));

    free(serialize_buf);
    free(hexstr_buf);
    free(data_hex);
    free(name);
    return buf;
}

// #define DNS_RECORD_TEST
#ifdef DNS_RECORD_TEST
#include <stdio.h>

int main()
{
    dns_answer_t record;

    if (dns_answer_init(&record) == false) {
        printf("dns_answer_init failed\n");
        return 1;
    }

    if (dns_answer_set_name(&record, "www.baidu.com") == false) {
        printf("dns_answer_set_name failed\n");
        return 1;
    }

    if (dns_answer_set_type(&record, DNS_TYPE_A) == false) {
        printf("dns_answer_set_type failed\n");
        return 1;
    }

    if (dns_answer_set_class(&record, DNS_CLASS_IN) == false) {
        printf("dns_answer_set_class failed\n");
        return 1;
    }

    if (dns_answer_set_ttl(&record, 300) == false) {
        printf("dns_answer_set_ttl failed\n");
        return 1;
    }

    if (dns_answer_set_data(&record, (uint8_t *)"www.baidu.com", 14) == false) {
        printf("dns_answer_set_data failed\n");
        return 1;
    }

    char buf[1024];
    const char *str = dns_answer_to_string(&record, buf, sizeof(buf));
    printf("record:%s\n", str ? str:"NULL");
    uint8_t data[1024];
    int len = dns_answer_serialize(&record, data, sizeof(data));
    dns_answer_t record2;
    dns_answer_init(&record2);
    len = dns_answer_deserialize(&record2, (uint8_t *)data, len);
    str = dns_answer_to_string(&record2, buf, sizeof(buf));
    printf("record2:%s\n", str ? str:"NULL");

    printf("%s\n", dns_answer_equal(&record, &record2) ? "record1 == record2" : "record1 != record2");
    return 0;
}
#endif // DNS_RECORD_TEST