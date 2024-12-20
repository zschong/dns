#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dns_binstring.h"
#include "dns_flags.h"
#include "dns_header.h"
#include "dns_hexstring.h"

bool dns_header_init(dns_header_t *header)
{
    if (NULL == header) {
        return false;
    }

    header->id                = 0;
    header->flags             = 0;
    header->questions_count   = 0;
    header->answers_count     = 0;
    header->authorities_count = 0;
    header->additional_count  = 0;

    return true;
}

bool dns_header_set_id(dns_header_t *header, uint16_t id)
{
    if (NULL == header) {
        return false;
    }

    header->id = id;

    return true;
}

bool dns_header_set_flags(dns_header_t *header, uint16_t flags)
{
    if (NULL == header) {
        return false;
    }

    header->flags = flags;

    return true;
}

bool dns_header_set_question_count(dns_header_t *header, uint16_t questions_count)
{
    if (NULL == header) {
        return false;
    }

    header->questions_count = questions_count;

    return true;
}

bool dns_header_set_answer_count(dns_header_t *header, uint16_t answers_count)
{
    if (NULL == header) {
        return false;
    }

    header->answers_count = answers_count;

    return true;
}

bool dns_header_set_authority_count(dns_header_t *header, uint16_t authorities_count)
{
    if (NULL == header) {
        return false;
    }

    header->authorities_count = authorities_count;

    return true;
}

bool dns_header_set_additional_count(dns_header_t *header, uint16_t additional_count)
{
    if (NULL == header) {
        return false;
    }

    header->additional_count = additional_count;

    return true;
}

uint16_t dns_header_get_id(dns_header_t *header)
{
    if (NULL == header) {
        return 0;
    }

    return header->id;
}

uint16_t dns_header_get_flags(dns_header_t *header)
{
    if (NULL == header) {
        return 0;
    }

    return header->flags;
}

uint16_t dns_header_get_question_count(dns_header_t *header)
{
    if (NULL == header) {
        return 0;
    }

    return header->questions_count;
}

uint16_t dns_header_get_answer_count(dns_header_t *header)
{
    if (NULL == header) {
        return 0;
    }

    return header->answers_count;
}

uint16_t dns_header_get_authority_count(dns_header_t *header)
{
    if (NULL == header) {
        return 0;
    }

    return header->authorities_count;
}

uint16_t dns_header_get_additional_count(dns_header_t *header)
{
    if (NULL == header) {
        return 0;
    }

    return header->additional_count;
}

uint32_t dns_header_serialize(const dns_header_t *header, uint8_t *buf, uint32_t buf_size)
{
    if (NULL == header || NULL == buf || buf_size < sizeof(dns_header_t)) {
        return 0;
    }

    uint8_t *ptr = buf;

    *(ptr++) = (header->id                >> 8) & 0xFF;
    *(ptr++) =  header->id                      & 0xFF;
    *(ptr++) = (header->flags             >> 8) & 0xFF;
    *(ptr++) =  header->flags                   & 0xFF;
    *(ptr++) = (header->questions_count   >> 8) & 0xFF;
    *(ptr++) =  header->questions_count         & 0xFF;
    *(ptr++) = (header->answers_count     >> 8) & 0xFF;
    *(ptr++) =  header->answers_count           & 0xFF;
    *(ptr++) = (header->authorities_count >> 8) & 0xFF;
    *(ptr++) =  header->authorities_count       & 0xFF;
    *(ptr++) = (header->additional_count  >> 8) & 0xFF;
    *(ptr++) =  header->additional_count        & 0xFF;

    return ptr - buf;
}

uint32_t dns_header_deserialize(dns_header_t *header, const uint8_t *data, uint16_t len)
{
    if (NULL == header || data == NULL || len == 0) {
        return 0;
    }

    const uint8_t *ptr = data;

    header->id                =  *(ptr++) << 8;
    header->id                |= *(ptr++)     ;
    header->flags             =  *(ptr++) << 8;
    header->flags             |= *(ptr++)     ;
    header->questions_count   =  *(ptr++) << 8;
    header->questions_count   |= *(ptr++)     ;
    header->answers_count     =  *(ptr++) << 8;
    header->answers_count     |= *(ptr++)     ;
    header->authorities_count =  *(ptr++) << 8;
    header->authorities_count |= *(ptr++)     ;
    header->additional_count  =  *(ptr++) << 8;
    header->additional_count  |= *(ptr++)     ;

    return ptr - data;
}

const char *dns_header_to_string(dns_header_t *header, char *buf, uint32_t buf_size)
{
    if (NULL == header || buf == NULL || buf_size == 0) {
        return NULL;
    }
    char flags_buf[512];
    char hexbuf[256];

    dns_flags_to_string(header->flags, flags_buf, sizeof(flags_buf));
    snprintf(buf,
             buf_size,
             "DNS Header:[%s]\n"
             "  ID              : %d\n"
             "  Questions       : %d\n"
             "  Answer RRs      : %d\n"
             "  Authority RRs   : %d\n"
             "  Additional RRs  : %d\n"
             "  Flags           : \n"
             "%s",
             dns_hexstring((uint8_t *)header, sizeof(dns_header_t), hexbuf, sizeof(hexbuf)),
             header->id,
             header->questions_count,
             header->answers_count,
             header->authorities_count,
             header->additional_count,
             flags_buf);

    return buf;
}

#ifdef DNS_HEADER_TEST
#include <stdio.h>
#include <string.h>

int main(void)
{
    dns_header_t header;

    dns_header_init(&header);

    dns_flags_set_qr    (&header.flags, DNS_QR_QUERY     );
    dns_flags_set_opcode(&header.flags, DNS_OPCODE_QUERY );
    dns_flags_set_aa    (&header.flags, DNS_AA_NO        );
    dns_flags_set_tc    (&header.flags, DNS_TC_NO        );
    dns_flags_set_rd    (&header.flags, DNS_RD_YES       );
    dns_flags_set_ra    (&header.flags, DNS_RA_NO        );
    dns_flags_set_rcode (&header.flags, DNS_RCODE_NOERROR);

    header.id                = 1234;
    header.questions_count   = 1;
    header.answers_count     = 0;
    header.authorities_count = 0;
    header.additional_count  = 0;

    char buf[1024];
    dns_header_to_string(&header, buf, sizeof(buf));
    printf("%s\n", buf);

    char hexstr[256];
    int len = dns_header_serialize(&header, buf, sizeof(buf));
    dns_hexstring((uint8_t*)buf, len, hexstr, sizeof(hexstr));
    printf("DNS Header Serialize:[%s]\n", hexstr);

    return 0;
}
#endif  // DNS_HEADER_TEST