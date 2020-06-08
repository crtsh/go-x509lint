#ifndef _CHECKS_H_
#define _CHECKS_H_

#include <stdint.h>

typedef enum { SubscriberCertificate, IntermediateCA, RootCA } CertType;
typedef enum { PEM, DER } CertFormat;

/* This should never happen in certificates, and violates a MUST */
#define ERR_INVALID                            0
#define ERR_ISSUER_ORG_NAME                    1
#define ERR_ISSUER_COUNTRY                     2
#define ERR_SUBJECT_ADDR                       3
#define ERR_SUBJECT_ORG_NO_PLACE               4
#define ERR_SUBJECT_NO_ORG_PLACE               5
#define ERR_INVALID_ENCODING                   6
#define ERR_STRING_WITH_NUL                    7
#define ERR_INVALID_NAME_ENTRY_TYPE            8
#define ERR_NON_PRINTABLE                      9
#define ERR_SUBJECT_COUNTRY                   10
#define ERR_DOMAIN_WITH_ORG                   11
#define ERR_ORGANIZATION_WITHOUT_ORG          12
#define ERR_NO_POLICY                         13
#define ERR_NO_SUBJECT_ALT_NAME               14
#define ERR_NOT_VERSION3                      15
#define ERR_INVALID_URL                       16
#define ERR_LONGER_60_MONTHS                  17
#define ERR_COUNTRY_SIZE                      18
#define ERR_INVALID_TIME_FORMAT               19
#define ERR_DUPLICATE_EXTENSION               20
#define ERR_INVALID_CRL_DIST_POINT            21
#define ERR_INVALID_DISPLAY_TEXT_TYPE         22
#define ERR_INVALID_DISPLAY_TEXT_LENGTH       23
#define ERR_INVALID_TYPE_USER_NOTICE          24
#define ERR_INVALID_POLICY_QUALIFIER_ID       25
#define ERR_INDIVIDUAL_WITHOUT_NAME           26
#define ERR_INDIVIDUAL_WITHOUT_COUNTRY        27
#define ERR_EV_WITHOUT_ORGANIZATION           28
#define ERR_EV_WITHOUT_BUSINESS               29
#define ERR_EV_WITHOUT_JURISDICTION_COUNTRY   30
#define ERR_EV_WITHOUT_NUMBER                 31
#define ERR_DOMAIN_WITH_STREET                32
#define ERR_DOMAIN_WITH_LOCALITY              33
#define ERR_DOMAIN_WITH_STATE                 34
#define ERR_DOMAIN_WITH_POSTAL                35
#define ERR_ORGANIZATION_WITHOUT_COUNTRY      36
#define ERR_COMMON_NAME_SIZE                  37
#define ERR_LOCALITY_NAME_SIZE                38
#define ERR_STATE_NAME_SIZE                   39
#define ERR_ORGANIZATION_NAME_SIZE            40
#define ERR_ORGANIZATIONAL_UNIT_NAME_SIZE     41
#define ERR_SERIAL_NUMBER_SIZE                42
#define ERR_POSTAL_CODE_SIZE                  43
#define ERR_EMAIL_SIZE                        44
#define ERR_GIVEN_NAME_SIZE                   45
#define ERR_SURNAME_SIZE                      46
#define ERR_STREET_ADDRESS_SIZE               47
#define ERR_AIA_CRITICAL                      48
#define ERR_NO_OCSP_HTTP                      49
#define ERR_NO_AIA                            50
#define ERR_SAN_TYPE                          51
#define ERR_GEN_NAME_TYPE                     52
#define ERR_EV_LONGER_27_MONTHS               53
#define ERR_SAN_WITHOUT_NAME                  54
#define ERR_IP_FAMILY                         55
#define ERR_CN_NOT_IN_SAN                     56
#define ERR_BUSINESS_CATEGORY_SIZE            57
#define ERR_DN_QUALIFIER_SIZE                 58
#define ERR_URL_WITH_NUL                      59
#define ERR_POST_OFFICE_BOX_SIZE              60
#define ERR_IP_IN_DNSNAME                     61
#define ERR_SERIAL_NOT_POSITIVE               62
#define ERR_SERIAL_TOO_LARGE                  63
#define ERR_ASN1_INTEGER_NOT_MINIMAL          64
#define ERR_RSA_SIZE_2048                     65
#define ERR_RSA_EXP_NOT_ODD                   66
#define ERR_RSA_EXP_3                         67
#define ERR_RSA_SMALL_FACTOR                  68
#define ERR_EC_AT_INFINITY                    69
#define ERR_EC_POINT_NOT_ON_CURVE             70
#define ERR_EC_INVALID_GROUP_ORDER            71
#define ERR_EC_INCORRECT_ORDER                72
#define ERR_EC_NON_ALLOWED_CURVE              73
#define ERR_UNKNOWN_PUBLIC_KEY_TYPE           74
#define ERR_SUBJECT_POSTAL                    75
#define ERR_DOMAIN_WITH_NAME                  76
#define ERR_NAME_NO_IV_POLICY                 77
#define ERR_ROOT_CA_WITH_EKU                  78
#define ERR_EMPTY_EKU                         79
#define ERR_MISSING_EKU                       80
#define ERR_DOMAINCOMPONENT_SIZE              81
#define ERR_UNSTRUCTUREDNAME_SIZE             82
#define ERR_TELETEX_WITH_ESCAPE               83
#define ERR_POLICY_BR                         84
#define ERR_RSA_MODULUS_NEGATIVE              85
#define MAX_ERR                               ERR_RSA_MODULUS_NEGATIVE

/* This violates a SHOULD (or MUST with exception that can't be checked) */
#define WARN_NON_PRINTABLE_STRING      0
#define WARN_LONGER_39_MONTHS          1
#define WARN_CHECKED_AS_SUBSCRIBER     2
#define WARN_CHECKED_AS_CA             3
#define WARN_CRL_RELATIVE              4
#define WARN_NO_ISSUING_CERT_HTTP      5
#define WARN_DUPLICATE_SAN             6
#define WARN_EV_LONGER_12_MONTHS       7
#define WARN_UNKNOWN_EKU               8
#define WARN_RSA_EXP_RANGE             9
#define WARN_POLICY_QUALIFIER_NOT_CPS 10
#define WARN_EXPLICIT_TEXT_ENCODING   11
#define WARN_NO_EKU                   12
#define WARN_NO_CN                    13
#define WARN_TLS_CLIENT_DNS           14
#define MAX_WARN                      WARN_TLS_CLIENT_DNS

/* Certificate is valid, but contains things like deprecated or not checked. */
#define INF_SUBJECT_CN                    0
#define INF_STRING_NOT_CHECKED            1        /* Software doesn't know how to check it yet. */
#define INF_CRL_NOT_URL                   2
#define INF_UNKNOWN_VALIDATION            3        /* Software doesn't know OID yet. */
#define INF_NAME_ENTRY_LENGTH_NOT_CHECKED 4        /* Software doesn't know how to check size yet. */
#define MAX_INF                           INF_NAME_ENTRY_LENGTH_NOT_CHECKED

extern uint32_t errors[];
extern uint32_t warnings[];
extern uint32_t info[];

void check_init();
void check(unsigned char *cert_buffer, size_t cert_len, CertFormat format, CertType type);
int GetBit(uint32_t *val, int bit);
void check_finish();


#endif

