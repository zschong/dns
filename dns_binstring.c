#include <stdio.h>
#include <string.h>

#include "dns_binstring.h"

const char *dns_value_binstring(const uint8_t *val, uint32_t val_size, char *buf, size_t buf_size)
{
    if (NULL == val || NULL == buf || val_size < 1 || buf_size < (val_size * 9 + 1)) {
        printf("dns_value_binstring Error: Invalid parameters\n");
        return NULL;
    }

    char    *ptr   = buf;
    uint64_t value = 0;
    switch (val_size) {
    case 1:
        value = (uint64_t)(*(uint8_t *)val);
        break;
    case 2:
        value = (uint64_t)(*(uint16_t *)val);
        break;
    case 4:
        value = (uint64_t)(*(uint32_t *)val);
        break;
    case 8:
        value = *(uint64_t *)val;
        break;
    default:
        printf("dns_value_binstring Error: Invalid val_size\n");
        return NULL;
    }

    for (int i = (val_size * 8) - 1; i >= 0; i--) {
        *(ptr++) = (0x01 & (value >> i)) ? '1' : '0';
        if ((ptr - buf) % 5 == 4 && i > 0) {
            *(ptr++) = i % 8 == 0 ? ' ' : ',';
        }
    }
    *ptr = '\0';

    return buf;
}

const char *dns_array_binstring(const uint8_t *array, uint32_t arr_size, char *buf, size_t buf_size)
{
    if (NULL == array || NULL == buf || arr_size < 1 || buf_size < (arr_size * 9 + 1)) {
        printf("dns_array_binstring Error: Invalid parameters\n");
        return NULL;
    }

    char *ptr = buf;

    for (int i = 0; i < arr_size; i++) {
        const char *bin = dns_value_binstring(array + i, 1, ptr, buf_size - (ptr - buf));
        if (NULL == bin) {
            printf("dns_array_binstring Error: dns_value_binstring failed at i=%d\n", i);
            return NULL;
        }

        ptr += strlen(bin);
        if (i < arr_size - 1) {
            *(ptr++) = ' ';
        }
    }

    return buf;
}

#ifdef DNS_BINSTRING_TEST
#include <string.h>

int main(void)
{
    uint8_t  val1 = 0x12;
    uint16_t val2 = 0x1234;
    uint32_t val3 = 0x12345678;
    uint64_t val4 = 0x1234567890abcdef;
    char    *arr  = "hello world";
    char     buf[1024];

#define DNS_VALUE_BINSTRING_TEST(val, size) \
        do {\
            const char *str = dns_value_binstring((uint8_t *)&val, size, buf, sizeof(buf));\
            printf("%16lX: [%s]\n", (uint64_t)val, str ? str : "NULL"); \
        } while (0)

    DNS_VALUE_BINSTRING_TEST(val1, 1);
    DNS_VALUE_BINSTRING_TEST(val2, 2);
    DNS_VALUE_BINSTRING_TEST(val3, 4);
    DNS_VALUE_BINSTRING_TEST(val4, 8);
    
    const char *str = dns_array_binstring((uint8_t *)arr, strlen(arr), buf, sizeof(buf));
    printf("%16s: [%s]\n", arr, str ? str : "NULL"); \

    return 0;
}
#endif