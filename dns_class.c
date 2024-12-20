#include "dns_class.h"


const char* dns_class_name(dns_class_t qclass) 
{
    switch (qclass) {
        case DNS_CLASS_IN:
            return "IN (Internet)";
        case DNS_CLASS_CS:
            return "CS (CSNET, obsolete)";
        case DNS_CLASS_CH:
            return "CH (CHAOS)";
        case DNS_CLASS_HS:
            return "HS (Hesiod)";
        case DNS_CLASS_ANY:
            return "ANY (Any class)";
        default:
            return "UNKNOWN (Unknown class)";
    }
}