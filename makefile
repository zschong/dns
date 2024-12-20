CC := gcc
CFLAGS := -Iinclude -g
DNS_FLAGS_SRC  := dns_flags_get.c\
				  dns_flags_set.c\
				  dns_flags_stringify.c
DNS_HEAD_SRC   := dns_header.c
DNS_TYPE_SRC   := dns_type.c
DNS_CLASS_SRC  := dns_class.c
DNS_QUERY_SRC  := dns_query.c
DNS_RECORD_SRC := dns_record.c
DNS_NAME_SRC   := dns_name.c
DNS_HEX_SRC    := dns_hexstring.c
DNS_BIN_SRC    := dns_binstring.c

dns_flags.exe: $(DNS_FLAGS_SRC)
	$(CC) $(CFLAGS) $+ -o $@ -DDNS_FLAGS_STRINGIFY_TEST

dns_header.exe: $(DNS_HEAD_SRC) $(DNS_FLAGS_SRC) $(DNS_HEX_SRC) $(DNS_BIN_SRC)
	$(CC) $(CFLAGS) $+ -o $@ -DDNS_HEADER_TEST

dns_query.exe: $(DNS_QUERY_SRC) $(DNS_TYPE_SRC) $(DNS_CLASS_SRC) $(DNS_NAME_SRC) $(DNS_HEX_SRC)
	$(CC) $(CFLAGS) $+ -o $@ -DDNS_QUERY_TEST

dns_record.exe: $(DNS_RECORD_SRC) $(DNS_TYPE_SRC) $(DNS_CLASS_SRC) $(DNS_NAME_SRC) $(DNS_HEX_SRC)
	$(CC) $(CFLAGS) $+ -o $@ -DDNS_RECORD_TEST

dns_name.exe: $(DNS_NAME_SRC)
	$(CC) $(CFLAGS) $+ -o $@ -DDNS_NAME_TEST

dns_hexstring.exe: $(DNS_HEX_SRC)
	$(CC) $(CFLAGS) $+ -o $@ -DDNS_HEXSTRING_TEST

dns_binstring.exe: $(DNS_BIN_SRC)
	$(CC) $(CFLAGS) $+ -o $@ -DDNS_BINSTRING_TEST

clean:
	rm *.exe -rf
