use inc::Module::Install;

name     'Store-Digest';
all_from 'lib/Store/Digest.pm';
author   q{Dorian Taylor <dorian@cpan.org>};
license  'apache';

build_requires 'Test::More';

auto_install;

WriteAll;

