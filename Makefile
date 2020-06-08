all:
	go build

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
