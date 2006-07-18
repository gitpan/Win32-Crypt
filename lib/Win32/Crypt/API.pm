package Win32::Crypt::API;

use strict;
use warnings;
use base qw/Exporter Win32::API::Interface/;

use vars qw/$VERSION @EXPORT_OK %EXPORT_TAGS/;
$VERSION = '0.00_001';

__PACKAGE__->generate(
    {
        'crypt32' => [
            [ 'CertAddStoreToCollection',      'NNNN',   'I' ],
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

=head1 NAME

Win32::Crypt::API - Perl interface to functions that assist in working
with Microsoft's CryptoAPI

=head1 SYNOPSIS

    use Win32::Crypt::API;

    my $capi = Win32::Crypt::API->new;

=head1 DESCRIPTION

Application programming interface that enables application
developers to add authentication, encoding, and encryption to Win32-based
applications.

=head1 METHODS

=head2 new

    my $capi = Win32::Crypt::API->new;

=head1 CERTIFICATE STORE FUNCTIONS

A user site can, over time, collect many certificates. Typically, a site has
certificates for the user of the site, and other certificates describing those
individuals and entities with whom the user communicates. For each entity,
there can be more than one certificate. For each individual certificate, there
should be a chain of verifying certificates that provides a trail back to a
trusted root certificate. Certificate stores and their related functions
provide functionality to store, retrieve, enumerate, verify, and use the
information stored in the certificates.

The following functions are used to work with the certificate stores,
themselves.

=head2 CertAddStoreToCollection

=head2 CertCloseStore

=head2 CertControlStore

=head2 CertDuplicateStore

=head2 CertEnumPhysicalStore

=head2 CertEnumSystemStore

=head2 CertEnumSystemStoreLocation

=head2 CertGetStoreProperty

=head2 CertOpenStore

=head2 CertOpenSystemStore

=head2 CertRegisterPhysicalStore

=head2 CertRegisterSystemStore

=head2 CertRemoveStoreFromCollection

=head2 CertSaveStore

=head2 CertSetStoreProperty

=head2 CertUnregisterPhysicalStore

=head2 CertUnregisterSystemStore

=head1 AUTHOR

Sascha Kiefer, L<esskar@cpan.org>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 Sascha Kiefer

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
