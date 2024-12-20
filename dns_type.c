#include "dns_type.h"

const char* dns_type_name(dns_type_t qtype)
{
    switch (qtype) {
    case DNS_TYPE_A:
        return "A (Address record)";
    case DNS_TYPE_NS:
        return "NS (Name server record)";
    case DNS_TYPE_CNAME:
        return "CNAME (Canonical name record)";
    case DNS_TYPE_SOA:
        return "SOA (Start of authority record)";
    case DNS_TYPE_MX:
        return "MX (Mail exchange record)";
    case DNS_TYPE_TXT:
        return "TXT (Text record)";
    case DNS_TYPE_AAAA:
        return "AAAA (IPv6 address record)";
    case DNS_TYPE_PTR:
        return "PTR (Pointer record)";
    case DNS_TYPE_SRV:
        return "SRV (Service locator record)";
    case DNS_TYPE_NSEC:
        return "NSEC (Next secure record)";
    case DNS_TYPE_DNSKEY:
        return "DNSKEY (DNS key record)";
    case DNS_TYPE_RRSIG:
        return "RRSIG (Resource record signature)";
    case DNS_TYPE_NSEC3:
        return "NSEC3 (Next secure record version 3)";
    case DNS_TYPE_NSEC3PARAM:
        return "NSEC3PARAM (NSEC3 parameters)";
    case DNS_TYPE_TLSA:
        return "TLSA (TLSA record)";
    case DNS_TYPE_SPF:
        return "SPF (Sender policy framework record)";
    case DNS_TYPE_SVCB:
        return "SVCB (Service binding record)";
    case DNS_TYPE_HTTPS:
        return "HTTPS (HTTPS record)";
    case DNS_TYPE_OPT:
        return "OPT (Option record)";
    case DNS_TYPE_APL:
        return "APL (Address prefix list record)";
    case DNS_TYPE_DS:
        return "DS (Delegation signer record)";
    case DNS_TYPE_SSHFP:
        return "SSHFP (SSH key fingerprint record)";
    case DNS_TYPE_IPSECKEY:
        return "IPSECKEY (IPsec key record)";
    case DNS_TYPE_DHCID:
        return "DHCID (DHCP identifier record)";
    case DNS_TYPE_NAPTR:
        return "NAPTR (Name authority pointer record)";
    case DNS_TYPE_KX:
        return "KX (Key exchange record)";
    case DNS_TYPE_CERT:
        return "CERT (Certificate record)";
    case DNS_TYPE_DNAME:
        return "DNAME (DNAME record)";
    case DNS_TYPE_SINK:
        return "SINK (SINK record)";
    case DNS_TYPE_A6:
        return "A6 (IPv6 address record)";
    default:
        return "UNKNOWN (Unknown record type)";
    }
}