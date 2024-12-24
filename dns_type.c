#include "dns_type.h"

const char* dns_type_name(dns_type_t qtype)
{
    switch (qtype) {
    case DNS_TYPE_A:
        return "A (Address answer)";
    case DNS_TYPE_NS:
        return "NS (Name server answer)";
    case DNS_TYPE_CNAME:
        return "CNAME (Canonical name answer)";
    case DNS_TYPE_SOA:
        return "SOA (Start of authority answer)";
    case DNS_TYPE_MX:
        return "MX (Mail exchange answer)";
    case DNS_TYPE_TXT:
        return "TXT (Text answer)";
    case DNS_TYPE_AAAA:
        return "AAAA (IPv6 address answer)";
    case DNS_TYPE_PTR:
        return "PTR (Pointer answer)";
    case DNS_TYPE_SRV:
        return "SRV (Service locator answer)";
    case DNS_TYPE_NSEC:
        return "NSEC (Next secure answer)";
    case DNS_TYPE_DNSKEY:
        return "DNSKEY (DNS key answer)";
    case DNS_TYPE_RRSIG:
        return "RRSIG (Resource answer signature)";
    case DNS_TYPE_NSEC3:
        return "NSEC3 (Next secure answer version 3)";
    case DNS_TYPE_NSEC3PARAM:
        return "NSEC3PARAM (NSEC3 parameters)";
    case DNS_TYPE_TLSA:
        return "TLSA (TLSA answer)";
    case DNS_TYPE_SPF:
        return "SPF (Sender policy framework answer)";
    case DNS_TYPE_SVCB:
        return "SVCB (Service binding answer)";
    case DNS_TYPE_HTTPS:
        return "HTTPS (HTTPS answer)";
    case DNS_TYPE_OPT:
        return "OPT (Option answer)";
    case DNS_TYPE_APL:
        return "APL (Address prefix list answer)";
    case DNS_TYPE_DS:
        return "DS (Delegation signer answer)";
    case DNS_TYPE_SSHFP:
        return "SSHFP (SSH key fingerprint answer)";
    case DNS_TYPE_IPSECKEY:
        return "IPSECKEY (IPsec key answer)";
    case DNS_TYPE_DHCID:
        return "DHCID (DHCP identifier answer)";
    case DNS_TYPE_NAPTR:
        return "NAPTR (Name authority pointer answer)";
    case DNS_TYPE_KX:
        return "KX (Key exchange answer)";
    case DNS_TYPE_CERT:
        return "CERT (Certificate answer)";
    case DNS_TYPE_DNAME:
        return "DNAME (DNAME answer)";
    case DNS_TYPE_SINK:
        return "SINK (SINK answer)";
    case DNS_TYPE_A6:
        return "A6 (IPv6 address answer)";
    default:
        return "UNKNOWN (Unknown answer type)";
    }
}