/* go-x509lint - Go wrapper for github.com/kroeckx/x509lint
 * Written by Rob Stradling
 * Copyright (C) 2018 COMODO CA Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package x509lint

import (
	"unsafe"
)

/*
#cgo LDFLAGS: -lcrypto
#include <stdlib.h>
#include "messages.h"
#include "checks.h"
*/
import "C"

func Init() {
	C.check_init()
}

func Check(cert_der []byte, cert_type int) string {
	C.check((*C.uchar)(unsafe.Pointer(&cert_der[0])), (C.ulong)(len(cert_der)), C.DER, (C.CertType)(cert_type))
	messages := C.get_messages()
	defer C.free(unsafe.Pointer(messages))
	return C.GoString(messages)
}

func Finish() {
	C.check_finish()
}
