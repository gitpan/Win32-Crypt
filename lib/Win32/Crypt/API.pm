package Win32::Crypt::API;

use strict;
use warnings;
use base qw/Exporter Win32::API::Interface/;

use vars qw/$VERSION @EXPORT_OK %EXPORT_TAGS/;
$VERSION = '0.00_002';

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

%EXPORT_TAGS = ( consts => [ keys %consts ] );
@EXPORT_OK   = ( keys %consts );

1;
