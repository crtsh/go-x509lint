all:
	rm -rf x509lint
	git clone https://github.com/kroeckx/x509lint
	ln -s x509lint/asn1_time.c
	ln -s x509lint/asn1_time.h
	ln -s x509lint/checks.c
	ln -s x509lint/checks.h
	ln -s x509lint/messages.c
	ln -s x509lint/messages.h
	go build

clean:
	rm -rf x509lint
	rm -f asn1_time.c asn1_time.h checks.c checks.h messages.c messages.h
