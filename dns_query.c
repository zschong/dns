#include <stdlib.h>
#include <string.h>
#include "dns_class.h"
#include "dns_query.h"
#include "dns_type.h"
#include "dns_name.h"
#include "dns_hexstring.h"

bool dns_query_init(dns_query_t *query)
{
    if (NULL == query) {
        return false;
    }

    query->qname = NULL;
    query->qtype = 0;
    query->qclass = 0;
    return true;
}

bool dns_query_clear(dns_query_t *query)
{
    if (NULL == query) {
        return false;
    }

    if (query->qname) {
        free(query->qname);
        query->qname = NULL;
    }

    query->qtype = 0;
    query->qclass = 0;
    return true;
}

bool dns_query_set_qname(dns_query_t *query, const char *domain_name)
{
    if (NULL == query || NULL == domain_name) {
        return false;
    }

    char buf[256] = {0};
    const char *ptr = dns_name_encode(domain_name, buf, sizeof(buf));
    if (NULL == ptr) {
        return false;
    }

    if (query->qname) {
        free(query->qname);
    }

    query->qname = strdup(buf);
    return !!query->qname;
}

bool dns_query_set_qtype(dns_query_t *query, uint16_t qtype)
{
    if (NULL == query) {
        return false;
    }
    query->qtype = (qtype);
    return true;
}

bool dns_query_set_qclass(dns_query_t *query, uint16_t qclass)
{
    if (NULL == query) {
        return false;
    }
    query->qclass = (qclass);
    return true;
}

const char *dns_query_get_qname(const dns_query_t *query)
{
    if (NULL == query) {
        return NULL;
    }
    return query->qname;
}

uint16_t dns_query_get_qtype(const dns_query_t *query)
{
    if (NULL == query) {
        return 0;
    }
    return (query->qtype);
}

uint16_t dns_query_get_qclass(const dns_query_t *query)
{
    if (NULL == query) {
        return 0;
    }
    return (query->qclass);
}

uint32_t dns_query_length(const dns_query_t *query)
{
    if (NULL == query || NULL == query->qname) {
        return 0;
    }

    return strlen(query->qname) + sizeof(dns_query_t) - sizeof(void*);
}

bool dns_query_equal(const dns_query_t *query1, const dns_query_t *query2)
{
    if (NULL == query1 || NULL == query2) {
        printf("query1 or query2 is NULL\n");
        return false;
    }

    if (query1->qtype != query2->qtype) {
        printf("query1->qtype(%d) != query2->qtype(%d)\n", query1->qtype, query2->qtype);
        return false;
    }

    if (query1->qclass != query2->qclass) {
        printf("query1->qclass(%d) != query2->qclass(%d)\n", query1->qclass, query2->qclass);
        return false;
    }

    if (NULL == query1->qname || NULL == query2->qname) {
        printf("query1->qname or query2->qname is NULL\n");
        return false;
    }

    if (query1->qname == query2->qname) {
        return true;
    }

    if (dns_query_length(query1) != dns_query_length(query2)) {
        printf("dns_query_length(query1) != dns_query_length(query2)\n");
        return false;
    }

    return strcmp(query1->qname, query2->qname) == 0;
}

int dns_query_serialize(const dns_query_t *query, uint8_t *buf, uint16_t buf_size)
{
    if (NULL == query || NULL == query->qname || NULL == buf) {
        return 0;
    }

    int query_len = dns_query_length(query);
    if (buf_size < query_len) {
        return 0;
    }

    strcpy((char*)buf, query->qname);

    uint8_t *ptr = (uint8_t*)buf;
    ptr += strlen(query->qname);
    *(ptr++) = (query->qtype  >> 8) & 0xFF;
    *(ptr++) =  query->qtype        & 0xFF;
    *(ptr++) = (query->qclass >> 8) & 0xFF;
    *(ptr++) =  query->qclass       & 0xFF;

    return ptr - buf;
}


int dns_query_deserialize(dns_query_t *query, const uint8_t *data, uint16_t data_len)
{
    if (NULL == query || NULL == data) {
        return 0;
    }

    dns_query_clear(query);

    int name_len = strlen((char*)data);
    if (data_len < (name_len + dns_query_length(query))) {
        return 0;
    }

    query->qname = strdup((char*)data);
    if (NULL == query->qname) {
        return 0;
    }

    uint8_t *ptr = (uint8_t*)data;
    ptr += name_len;
    query->qtype  =  *(ptr++) << 8;
    query->qtype  |= *(ptr++)     ;
    query->qclass =  *(ptr++) << 8;
    query->qclass |= *(ptr++)     ;

    return true;
}

const char *dns_query_to_string(const dns_query_t *query, char *buf, uint32_t buf_size)
{
    if (NULL == query || NULL == query->qname || NULL == buf) {
        return NULL;
    }

    int query_len = dns_query_length(query);
    if (query_len < 1 || buf_size < query_len * 3) {
        return NULL;
    }

    uint8_t *serialize_buf = (uint8_t*)malloc(query_len);
    if (NULL == serialize_buf) {
        return NULL;
    }

    int serialize_len = dns_query_serialize(query, serialize_buf, query_len);
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
             "dns_query(%d): [%s]\n"
             "  |-encoded: %s\n"
             "  |-qname  : %s\n"
             "  |-qtype  : %s\n"
             "  |-qclass : %s\n",
             query_len,
             hexstr_buf,
             dns_name_encoded_string(query->qname, name_encoded, sizeof(name_encoded)),
             dns_name_decode(query->qname, name_unencoded, sizeof(name_unencoded)),
             dns_type_name(query->qtype),
             dns_class_name(query->qclass));

    free(serialize_buf);
    free(hexstr_buf);
    
    return buf;
}

#ifdef DNS_QUERY_TEST
int main(int argc, char **argv)
{
    dns_query_t query;
    char        buf[1024];

    memset(&query, 0, sizeof(query));

    dns_query_set_qname(&query, "a.looooooooooong.example.com");
    dns_query_set_qtype(&query, DNS_TYPE_A);
    dns_query_set_qclass(&query, DNS_CLASS_IN);

    dns_query_to_string(&query, buf, sizeof(buf));
    printf("%s\n", buf);
    uint8_t serialize_buf[1024];
    int     serialize_len = dns_query_serialize(&query, serialize_buf, sizeof(serialize_buf));
    dns_query_t query2;
    dns_query_init(&query2);
    dns_query_deserialize(&query2, serialize_buf, serialize_len);
    dns_query_to_string(&query2, buf, sizeof(buf));
    printf("%s\n", buf);
    printf("%s\n", dns_query_equal(&query, &query2) ? "query == qeury2" : "query != query2");

    return 0;
}
#endif