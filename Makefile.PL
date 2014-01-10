use inc::Module::Install;

name        'Store-Digest';
all_from    'lib/Store/Digest.pm';
readme_from 'lib/Store/Digest/HTTP.pm';
author      q{Dorian Taylor <dorian@cpan.org>};
license     'apache';

requires 'BerkeleyDB'               => '0.51';
requires 'DateTime'                 => '0.70';
requires 'DateTime::Format::HTTP'   => '0.40';
requires 'File::Copy'               => '2.21';
requires 'File::MimeInfo::Magic'    => '0.15';
requires 'HTTP::Negotiate'          => '6.00';
requires 'MIME::Base32'             => '1.02';
requires 'Math::BigInt'             => '1.997';
requires 'Moose'                    => '2.0604';
requires 'MooseX::Params::Validate' => '0.18';
requires 'MooseX::Types'            => '0.35';
requires 'Path::Class'              => '0.24';
requires 'Plack'                    => '1.0005';
requires 'URI::ni'                  => '0.03';
requires 'XML::LibXML::LazyBuilder' => '0.05';

build_requires 'Test::More';

auto_install;

WriteAll;

