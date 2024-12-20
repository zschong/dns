#include <stdio.h>
#include "dns_hexstring.h"

const char* dns_hexstring(const uint8_t *data, size_t len, char *buf, size_t buf_size)
{
    if (NULL == data || len < 1 || NULL == buf || buf_size < (2 * len + 1)) {
        printf("%s Invalid parameters\n", __func__);
        return NULL;
    }

    const char *hexstr = "0123456789ABCDEF";
    char *ptr = buf;

    for (size_t i = 0; i < len; i++) {
        *(ptr++) = hexstr[data[i] >> 4];
        *(ptr++) = hexstr[data[i] & 0x0f];
    }
    ptr[0] = '\0';

    return buf;
}

#ifdef DNS_HEXSTRING_TEST
int main(void)
{
    uint8_t data[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    char buf[20];

    dns_hexstring(data, sizeof(data), buf, sizeof(buf));
    printf("%s\n", buf);
    
    return 0;
}
#endif