package x509lint

import (
	"strings"
	"unsafe"
)

/*
#cgo LDFLAGS: -lcrypto
#include <stdlib.h>
#include <string.h>
#include "messages.h"
#include "checks.h"
*/
import "C"

func Init() {
	C.check_init()
}

func Check(cert_der []byte, cert_type int) []string {
	C.check((*C.uchar)(unsafe.Pointer(&cert_der[0])), (C.ulong)(len(cert_der)), C.DER, (C.CertType)(cert_type))
	return strings.Split(C.GoString(C.get_messages()), "\n")
}

func Finish() {
	C.check_finish()
}

/*func main() {
	C.check_init()

	cert, err := ioutil.ReadFile("example.cer")
	if err != nil {
		fmt.Printf("ERROR: %v", err)
	}

	cert_type := C.SubscriberCertificate

	C.check((*C.uchar)(unsafe.Pointer(&cert[0])), (C.ulong)(len(cert)), C.DER, (C.CertType)(cert_type))

	messages := C.GoString(C.get_messages())
	fmt.Printf(messages)

	C.check_finish()
}
*/
