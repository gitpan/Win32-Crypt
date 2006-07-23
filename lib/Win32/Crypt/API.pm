package Win32::Crypt::API;

use strict;
use warnings;
use base qw/Exporter Win32::API::Interface/;

use vars qw/$VERSION @EXPORT_OK %EXPORT_TAGS/;
$VERSION = '0.00_004';

my %consts;

BEGIN {
    %consts = (
        CERT_STORE_PROV_MEMORY          => 'Memory',
        CERT_STORE_PROV_FILENAME        => 'File',
        CERT_STORE_PROV_SYSTEM          => 'System',
        CERT_STORE_PROV_PKCS7           => 'PKCS7',
        CERT_STORE_PROV_SERIALIZED      => 'Serialized',
        CERT_STORE_PROV_COLLECTION      => 'Collection',
        CERT_STORE_PROV_SYSTEM_REGISTRY => 'SystemRegistry',
        CERT_STORE_PROV_PHYSICAL        => 'Physical',
        CERT_STORE_PROV_SMART_CARD      => 'SmartCard',
        CERT_STORE_PROV_LDAP            => 'Ldap',

        X509_ASN_ENCODING   => 0x00000001,
        X509_NDR_ENCODING   => 0x00000002,
        PKCS_7_ASN_ENCODING => 0x00010000,
        PKCS_7_NDR_ENCODING => 0x00020000,

        CERT_STORE_NO_CRYPT_RELEASE_FLAG            => 0x00000001,
        CERT_STORE_SET_LOCALIZED_NAME_FLAG          => 0x00000002,
        CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG => 0x00000004,
        CERT_STORE_DELETE_FLAG                      => 0x00000010,
        CERT_STORE_UNSAFE_PHYSICAL_FLAG             => 0x00000020,
        CERT_STORE_SHARE_STORE_FLAG                 => 0x00000040,
        CERT_STORE_SHARE_CONTEXT_FLAG               => 0x00000080,
        CERT_STORE_MANIFOLD_FLAG                    => 0x00000100,
        CERT_STORE_ENUM_ARCHIVED_FLAG               => 0x00000200,
        CERT_STORE_UPDATE_KEYID_FLAG                => 0x00000400,
        CERT_STORE_BACKUP_RESTORE_FLAG              => 0x00000800,
        CERT_STORE_READONLY_FLAG                    => 0x00008000,
        CERT_STORE_OPEN_EXISTING_FLAG               => 0x00004000,
        CERT_STORE_CREATE_NEW_FLAG                  => 0x00002000,
        CERT_STORE_MAXIMUM_ALLOWED_FLAG             => 0x00001000,

        CERT_SYSTEM_STORE_UNPROTECTED_FLAG => 0x40000000,
        CERT_SYSTEM_STORE_LOCATION_MASK    => 0x00FF0000,
        CERT_SYSTEM_STORE_RELOCATE_FLAG    => 0x80000000,

        CERT_REGISTRY_STORE_REMOTE_FLAG     => 0x10000,
        CERT_REGISTRY_STORE_SERIALIZED_FLAG => 0x20000,
        CERT_REGISTRY_STORE_CLIENT_GPT_FLAG => 0x80000000,
        CERT_REGISTRY_STORE_LM_GPT_FLAG     => 0x01000000,

        CERT_SYSTEM_STORE_LOCATION_SHIFT                => 16,
        CERT_SYSTEM_STORE_CURRENT_USER_ID               => 1,
        CERT_SYSTEM_STORE_LOCAL_MACHINE_ID              => 2,
        CERT_SYSTEM_STORE_CURRENT_SERVICE_ID            => 4,
        CERT_SYSTEM_STORE_SERVICES_ID                   => 5,
        CERT_SYSTEM_STORE_USERS_ID                      => 6,
        CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID  => 7,
        CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID => 8,
        CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID   => 9,

        CERT_LDAP_STORE_SIGN_FLAG           => 0x10000,
        CERT_LDAP_STORE_AREC_EXCLUSIVE_FLAG => 0x20000,
        CERT_LDAP_STORE_OPENED_FLAG         => 0x40000,

        CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG                  => 0x1,
        CERT_PHYSICAL_STORE_OPEN_DISABLE_FLAG                => 0x2,
        CERT_PHYSICAL_STORE_REMOTE_OPEN_DISABLE_FLAG         => 0x4,
        CERT_PHYSICAL_STORE_INSERT_COMPUTER_NAME_ENABLE_FLAG => 0x8,

        CERT_STORE_ADD_NEW                                 => 1,
        CERT_STORE_ADD_USE_EXISTING                        => 2,
        CERT_STORE_ADD_REPLACE_EXISTING                    => 3,
        CERT_STORE_ADD_ALWAYS                              => 4,
        CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES => 5,
        CERT_STORE_ADD_NEWER                               => 6,
        CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES            => 7,

        E_INVALIDARG                       => 0x80070057,
        CRYPT_E_MSG_ERROR                  => 0x80091001,
        CRYPT_E_UNKNOWN_ALGO               => 0x80091002,
        CRYPT_E_OID_FORMAT                 => 0x80091003,
        CRYPT_E_INVALID_MSG_TYPE           => 0x80091004,
        CRYPT_E_UNEXPECTED_ENCODING        => 0x80091005,
        CRYPT_E_AUTH_ATTR_MISSING          => 0x80091006,
        CRYPT_E_HASH_VALUE                 => 0x80091007,
        CRYPT_E_INVALID_INDEX              => 0x80091008,
        CRYPT_E_ALREADY_DECRYPTED          => 0x80091009,
        CRYPT_E_NOT_DECRYPTED              => 0x8009100A,
        CRYPT_E_RECIPIENT_NOT_FOUND        => 0x8009100B,
        CRYPT_E_CONTROL_TYPE               => 0x8009100C,
        CRYPT_E_ISSUER_SERIALNUMBER        => 0x8009100D,
        CRYPT_E_SIGNER_NOT_FOUND           => 0x8009100E,
        CRYPT_E_ATTRIBUTES_MISSING         => 0x8009100F,
        CRYPT_E_STREAM_MSG_NOT_READY       => 0x80091010,
        CRYPT_E_STREAM_INSUFFICIENT_DATA   => 0x80091011,
        CRYPT_I_NEW_PROTECTION_REQUIRED    => 0x00091012,
        CRYPT_E_BAD_LEN                    => 0x80092001,
        CRYPT_E_BAD_ENCODE                 => 0x80092002,
        CRYPT_E_FILE_ERROR                 => 0x80092003,
        CRYPT_E_NOT_FOUND                  => 0x80092004,
        CRYPT_E_EXISTS                     => 0x80092005,
        CRYPT_E_NO_PROVIDER                => 0x80092006,
        CRYPT_E_SELF_SIGNED                => 0x80092007,
        CRYPT_E_DELETED_PREV               => 0x80092008,
        CRYPT_E_NO_MATCH                   => 0x80092009,
        CRYPT_E_UNEXPECTED_MSG_TYPE        => 0x8009200A,
        CRYPT_E_NO_KEY_PROPERTY            => 0x8009200B,
        CRYPT_E_NO_DECRYPT_CERT            => 0x8009200C,
        CRYPT_E_BAD_MSG                    => 0x8009200D,
        CRYPT_E_NO_SIGNER                  => 0x8009200E,
        CRYPT_E_PENDING_CLOSE              => 0x8009200F,
        CRYPT_E_REVOKED                    => 0x80092010,
        CRYPT_E_NO_REVOCATION_DLL          => 0x80092011,
        CRYPT_E_NO_REVOCATION_CHECK        => 0x80092012,
        CRYPT_E_REVOCATION_OFFLINE         => 0x80092013,
        CRYPT_E_NOT_IN_REVOCATION_DATABASE => 0x80092014,
        CRYPT_E_INVALID_NUMERIC_STRING     => 0x80092020,
        CRYPT_E_INVALID_PRINTABLE_STRING   => 0x80092021,
        CRYPT_E_INVALID_IA5_STRING         => 0x80092022,
        CRYPT_E_INVALID_X500_STRING        => 0x80092023,
        CRYPT_E_NOT_CHAR_STRING            => 0x80092024,
        CRYPT_E_FILERESIZED                => 0x80092025,
        CRYPT_E_SECURITY_SETTINGS          => 0x80092026,
        CRYPT_E_NO_VERIFY_USAGE_DLL        => 0x80092027,
        CRYPT_E_NO_VERIFY_USAGE_CHECK      => 0x80092028,
        CRYPT_E_VERIFY_USAGE_OFFLINE       => 0x80092029,
        CRYPT_E_NOT_IN_CTL                 => 0x8009202A,
        CRYPT_E_NO_TRUSTED_SIGNER          => 0x8009202B,
        CRYPT_E_MISSING_PUBKEY_PARA        => 0x8009202C,
        CRYPT_E_OSS_ERROR                  => 0x80093000,

        ERROR_NOT_ENOUGH_MEMORY => 8,
        ERROR_INVALID_PARAMETER => 87,
        ERROR_BUSY              => 107,
        ERROR_MORE_DATA         => 234,
        ERROR_NO_MORE_ITEMS     => 259,

        NTE_BAD_SIGNATURE       => 0x80090006,
        NTE_BAD_FLAGS           => 0x80090009,
        NTE_NO_MEMORY           => 0x8009000E,
        NTE_EXISTS              => 0x8009000F,
        NTE_BAD_PROV_TYPE       => 0x80090014,
        NTE_BAD_KEYSET          => 0x80090016,
        NTE_PROV_TYPE_NOT_DEF   => 0x80090017,
        NTE_PROV_TYPE_ENTRY_BAD => 0x80090018,
        NTE_KEYSET_NOT_DEF      => 0x80090019,
        NTE_KEYSET_ENTRY_BAD    => 0x8009001A,
        NTE_PROV_TYPE_NO_MATCH  => 0x8009001B,
        NTE_SIGNATURE_FILE_BAD  => 0x8009001C,
        NTE_PROVIDER_DLL_FAIL   => 0x8009001D,
        NTE_PROV_DLL_NOT_FOUND  => 0x8009001E,
        NTE_BAD_KEYSET_PARAM    => 0x8009001F,
        NTE_FAIL                => 0x80090020,

        CERT_STORE_CTRL_COMMIT_FORCE_FLAG             => 0x1,
        CERT_STORE_CTRL_COMMIT_CLEAR_FLAG             => 0x2,
        CERT_STORE_CTRL_INHIBIT_DUPLICATE_HANDLE_FLAG => 0x1,

        PP_ENUMALGS            => 1,
        PP_ENUMCONTAINERS      => 2,
        PP_IMPTYPE             => 3,
        PP_NAME                => 4,
        PP_VERSION             => 5,
        PP_CONTAINER           => 6,
        PP_CHANGE_PASSWORD     => 7,
        PP_KEYSET_SEC_DESCR    => 8,   # get/set security descriptor of keyset
        PP_CERTCHAIN           => 9,   # for retrieving certificates from tokens
        PP_KEY_TYPE_SUBTYPE    => 10,
        PP_PROVTYPE            => 16,
        PP_KEYSTORAGE          => 17,
        PP_APPLI_CERT          => 18,
        PP_SYM_KEYSIZE         => 19,
        PP_SESSION_KEYSIZE     => 20,
        PP_UI_PROMPT           => 21,
        PP_ENUMALGS_EX         => 22,
        PP_ENUMMANDROOTS       => 25,
        PP_ENUMELECTROOTS      => 26,
        PP_KEYSET_TYPE         => 27,
        PP_ADMIN_PIN           => 31,
        PP_KEYEXCHANGE_PIN     => 32,
        PP_SIGNATURE_PIN       => 33,
        PP_SIG_KEYSIZE_INC     => 34,
        PP_KEYX_KEYSIZE_INC    => 35,
        PP_UNIQUE_CONTAINER    => 36,
        PP_SGC_INFO            => 37,
        PP_USE_HARDWARE_RNG    => 38,
        PP_KEYSPEC             => 39,
        PP_ENUMEX_SIGNING_PROT => 40,
        PP_CRYPT_COUNT_KEY_USE => 41,

        CRYPT_FIRST    => 1,
        CRYPT_NEXT     => 2,
        CRYPT_SGC_ENUM => 4,

        CRYPT_IMPL_HARDWARE  => 1,
        CRYPT_IMPL_SOFTWARE  => 2,
        CRYPT_IMPL_MIXED     => 3,
        CRYPT_IMPL_UNKNOWN   => 4,
        CRYPT_IMPL_REMOVABLE => 8,

        CRYPT_SEC_DESCR => 0x00000001,
        CRYPT_PSTORE    => 0x00000002,
        CRYPT_UI_PROMPT => 0x00000004,

        CRYPT_FLAG_PCT1    => 0x0001,
        CRYPT_FLAG_SSL2    => 0x0002,
        CRYPT_FLAG_SSL3    => 0x0004,
        CRYPT_FLAG_TLS1    => 0x0008,
        CRYPT_FLAG_IPSEC   => 0x0010,
        CRYPT_FLAG_SIGNING => 0x0020,

        CRYPT_SGC     => 0x0001,
        CRYPT_FASTSGC => 0x0002,

        PP_CLIENT_HWND         => 1,
        PP_CONTEXT_INFO        => 11,
        PP_KEYEXCHANGE_KEYSIZE => 12,
        PP_SIGNATURE_KEYSIZE   => 13,
        PP_KEYEXCHANGE_ALG     => 14,
        PP_SIGNATURE_ALG       => 15,
        PP_DELETEKEY           => 24,

        PROV_RSA_FULL      => 1,
        PROV_RSA_SIG       => 2,
        PROV_DSS           => 3,
        PROV_FORTEZZA      => 4,
        PROV_MS_EXCHANGE   => 5,
        PROV_SSL           => 6,
        PROV_RSA_SCHANNEL  => 12,
        PROV_DSS_DH        => 13,
        PROV_EC_ECDSA_SIG  => 14,
        PROV_EC_ECNRA_SIG  => 15,
        PROV_EC_ECDSA_FULL => 16,
        PROV_EC_ECNRA_FULL => 17,
        PROV_DH_SCHANNEL   => 18,
        PROV_SPYRUS_LYNKS  => 20,
        PROV_RNG           => 21,
        PROV_INTEL_SEC     => 22,
        PROV_REPLACE_OWF   => 23,
        PROV_RSA_AES       => 24,

    );

    %consts = (
        %consts,

        CERT_SYSTEM_STORE_CURRENT_USER =>
          $consts{CERT_SYSTEM_STORE_CURRENT_USER_ID}
          << $consts{CERT_SYSTEM_STORE_LOCATION_SHIFT},
        CERT_SYSTEM_STORE_LOCAL_MACHINE =>
          $consts{CERT_SYSTEM_STORE_LOCAL_MACHINE_ID}
          << $consts{CERT_SYSTEM_STORE_LOCATION_SHIFT},
        CERT_SYSTEM_STORE_CURRENT_SERVICE =>
          $consts{CERT_SYSTEM_STORE_CURRENT_SERVICE_ID}
          << $consts{CERT_SYSTEM_STORE_LOCATION_SHIFT},
        CERT_SYSTEM_STORE_SERVICES => $consts{CERT_SYSTEM_STORE_SERVICES_ID}
          << $consts{CERT_SYSTEM_STORE_LOCATION_SHIFT},
        CERT_SYSTEM_STORE_USERS => $consts{CERT_SYSTEM_STORE_USERS_ID}
          << $consts{CERT_SYSTEM_STORE_LOCATION_SHIFT},
        CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY =>
          $consts{CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID}
          << $consts{CERT_SYSTEM_STORE_LOCATION_SHIFT},
        CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY =>
          $consts{CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID}
          << $consts{CERT_SYSTEM_STORE_LOCATION_SHIFT},
        CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE =>
          $consts{CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID}
          << $consts{CERT_SYSTEM_STORE_LOCATION_SHIFT},
    );
}
use constant \%consts;

__PACKAGE__->generate(
    {
        'advapi32' => [
            [ 'CryptAcquireContext',          'PPPNN',  'I' ],
            [ 'CryptContextAddRef',           'NPN',    'I' ],
            [ 'CryptEnumProviders',           'NPNPPP', 'I' ],
            [ 'CryptEnumProviderTypes',       'NPNPPP', 'I' ],
            [ 'CryptGetDefaultProvider',      'NPNPP',  'I' ],
            [ 'CryptGetProvParam',            'NNPPN',  'I' ],
            [ 'CryptInstallDefaultContext',   'NNPNPP', 'I' ],
            [ 'CryptReleaseContext',          'NN',     'I' ],
            [ 'CryptSetProvider',             'PN',     'I' ],
            [ 'CryptSetProviderEx',           'PNPN',   'I' ],
            [ 'CryptSetProvParam',            'NNPN',   'I' ],
            [ 'CryptUninstallDefaultContext', 'NNP',    'I' ],
        ],
        'crypt32' => [

            [ 'CertAddStoreToCollection',      'NNNN',   'I' ],
            [ 'CertAddCertificateLinkToStore', 'NNNN',   'I' ],
            [ 'CertCloseStore',                'NN',     'I' ],
            [ 'CertControlStore',              'NNNP',   'I' ],
            [ 'CertDuplicateStore',            'N',      'N' ],
            [ 'CertEnumPhysicalStore',         'PNPK',   'I' ],
            [ 'CertEnumSystemStore',           'PNPK',   'I' ],
            [ 'CertEnumSystemStoreLocation',   'NPK',    'I' ],
            [ 'CertGetStoreProperty',          'NNPP',   'I' ],
            [ 'CertOpenStore',                 'PNNNP',  'N' ],
            [ 'CertOpenSystemStore',           'NP',     'N' ],
            [ 'CertRegisterPhysicalStore',     'PNPSP',  'I' ],
            [ 'CertRegisterSystemStore',       'PNSP',   'I' ],
            [ 'CertRemoveStoreFromCollection', 'NN',     'V' ],
            [ 'CertSaveStore',                 'NNNNPN', 'I' ],
            [ 'CertSetStoreProperty',          'NNNP',   'I' ],
            [ 'CertUnregisterPhysicalStore',   'PNP',    'I' ],
            [ 'CertUnregisterSystemStore',     'PN',     'I' ],
        ],
    }
);

%EXPORT_TAGS = ( consts => [ __PACKAGE__->constant_names ] );
@EXPORT_OK   = ( __PACKAGE__->constant_names );

sub constant_names {
    return keys %consts;
}

1;
