use strict;
use Module::Build;

my $build = Module::Build->new(
    create_makefile_pl => 'traditional',
    license            => 'perl',
    module_name        => 'Win32::Crypt',
    dist_version_from  => 'lib/Win32/Crypt/API.pm',
    requires           => { 'Win32::API::Interface' => 0.01, constant => 1.05 },
    reccomends         => {},
    create_readme      => 1,
    sign               => 0,
);
$build->create_build_script;
