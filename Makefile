all:
	sed -i "s/asn1_time_to_tm/_x509lint_asn1_time_to_tm/g" *.c
	sed -i "s/asn1_time_to_tm/_x509lint_asn1_time_to_tm/g" *.h
	go build
	sed -i "s/_x509lint_asn1_time_to_tm/asn1_time_to_tm/g" *.c
	sed -i "s/_x509lint_asn1_time_to_tm/asn1_time_to_tm/g" *.h

update:
	rm -rf x509lint
	git clone https://github.com/kroeckx/x509lint
	cp x509lint/asn1_time.c .
	cp x509lint/asn1_time.h .
	cp x509lint/checks.c .
	cp x509lint/checks.h .
	cp x509lint/messages.c .
	cp x509lint/messages.h .
	rm -rf x509lint

clean:
	rm -rf x509lint
