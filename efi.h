#ifndef EFI_H
#define EFI_H

#include <stdint.h>

typedef uint64_t UINTN;
typedef int64_t INTN;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef UINTN EFI_STATUS;
typedef unsigned char BOOLEAN;
typedef unsigned short CHAR16;

#define EFI_MAX_BIT     0x8000000000000000ULL

//
// Set the upper bit to indicate EFI Error.
//
#define EFIERR(a)                 (EFI_MAX_BIT | (a))

#define EFIWARN(a)                (a)
#define EFI_ERROR(a)              (((INTN) (a)) < 0)

#define EFI_SUCCESS               0
#define EFI_LOAD_ERROR            EFIERR (1)
#define EFI_INVALID_PARAMETER     EFIERR (2)
#define EFI_UNSUPPORTED           EFIERR (3)
#define EFI_BAD_BUFFER_SIZE       EFIERR (4)
#define EFI_BUFFER_TOO_SMALL      EFIERR (5)
#define EFI_NOT_READY             EFIERR (6)
#define EFI_DEVICE_ERROR          EFIERR (7)
#define EFI_WRITE_PROTECTED       EFIERR (8)
#define EFI_OUT_OF_RESOURCES      EFIERR (9)
#define EFI_VOLUME_CORRUPTED      EFIERR (10)
#define EFI_VOLUME_FULL           EFIERR (11)
#define EFI_NO_MEDIA              EFIERR (12)
#define EFI_MEDIA_CHANGED         EFIERR (13)
#define EFI_NOT_FOUND             EFIERR (14)
#define EFI_ACCESS_DENIED         EFIERR (15)
#define EFI_NO_RESPONSE           EFIERR (16)
#define EFI_NO_MAPPING            EFIERR (17)
#define EFI_TIMEOUT               EFIERR (18)
#define EFI_NOT_STARTED           EFIERR (19)
#define EFI_ALREADY_STARTED       EFIERR (20)
#define EFI_ABORTED               EFIERR (21)
#define EFI_ICMP_ERROR            EFIERR (22)
#define EFI_TFTP_ERROR            EFIERR (23)
#define EFI_PROTOCOL_ERROR        EFIERR (24)
#define EFI_INCOMPATIBLE_VERSION  EFIERR (25)
#define EFI_SECURITY_VIOLATION    EFIERR (26)
#define EFI_CRC_ERROR             EFIERR (27)
#define EFI_END_OF_MEDIA          EFIERR (28)
#define EFI_END_OF_FILE           EFIERR (31)
#define EFI_INVALID_LANGUAGE      EFIERR (32)

#define EFI_WARN_UNKNOWN_GLYPH    EFIWARN (1)
#define EFI_WARN_DELETE_FAILURE   EFIWARN (2)
#define EFI_WARN_WRITE_FAILURE    EFIWARN (3)
#define EFI_WARN_BUFFER_TOO_SMALL EFIWARN (4)


///
/// Attributes of variable.
///
#define EFI_VARIABLE_NON_VOLATILE                            0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                      0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS                          0x00000004
///
/// This attribute is identified by the mnemonic 'HR'
/// elsewhere in this specification.
///
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD                   0x00000008
///
/// Attributes of Authenticated Variable
///
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS   0x00000020
#define EFI_VARIABLE_APPEND_WRITE                            0x00000040
///
/// NOTE: EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS is deprecated and should be considered reserved.
///
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS              0x00000010

/* All the access bits */
#define EFI_VAR_ACCESS (EFI_VARIABLE_RUNTIME_ACCESS | \
                        EFI_VARIABLE_BOOTSERVICE_ACCESS | \
                        EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS | \
                        EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)

#endif
