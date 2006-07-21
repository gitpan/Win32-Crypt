package Win32::Crypt::API;

use strict;
use warnings;
use base qw/Exporter Win32::API::Interface/;

use vars qw/$VERSION @EXPORT_OK %EXPORT_TAGS/;
$VERSION = '0.00_003';

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

        CERT_STORE_CTRL_COMMIT_FORCE_FLAG             => 0x1,
        CERT_STORE_CTRL_COMMIT_CLEAR_FLAG             => 0x2,
        CERT_STORE_CTRL_INHIBIT_DUPLICATE_HANDLE_FLAG => 0x1,

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
        ]
    }
);

%EXPORT_TAGS = ( consts => [ __PACKAGE__->constant_names ] );
@EXPORT_OK   = ( __PACKAGE__->constant_names );

sub constant_names {
    return keys %consts;
}

1;
