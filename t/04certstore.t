use Test::More tests => 3;

use strict;
use warnings;

use Win32::Crypt::API;

my $api;
ok($api = Win32::Crypt::API->new, 'new');

my $certstore;
ok($certstore = $api->CertOpenStore("System", 0, 0, 1 << 16, "MY"), 'CertOpenStore');
ok($api->CertCloseStore($certstore, 0), 'CertCloseStore');

# print STDERR join("\n", "\n", sort $api->constant_names );