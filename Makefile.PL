use inc::Module::Install;

name     'Store-Digest';
all_from 'lib/Store/Digest.pm';
author   q{Dorian Taylor <dorian@cpan.org>};
license  'apache';

requires 'BerkeleyDB'               => '0.51';
requires 'XML::LibXML::LazyBuilder' => '0.05';

build_requires 'Test::More';

auto_install;

WriteAll;

