package Store::Digest::HTTP;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Moose;
use namespace::autoclean;

=head1 NAME

Store::Digest::HTTP - Map HTTP methods and URI space to Store::Digest

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

    use Store::Digest::HTTP;

    my $sd = Store::Digest::HTTP->new;

    my $response = $sd->handle($request);

=head1 METHODS

=head2 function1

=cut

sub function1 {
}

=head2 function2

=cut

sub function2 {
}

# objects:

# GET/HEAD

# PROPFIND

# PROPPATCH

# PUT

# DELETE

# collections:

# GET/HEAD

# PROPFIND

# stats:

# GET/HEAD

# PROPFIND

# / -> /.well-known/[dn]i/

# /{digest-algo}/

# a collection

#

=head1 AUTHOR

Dorian Taylor, C<< <dorian at cpan.org> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2012 Dorian Taylor.

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License.  You may
obtain a copy of the License at
L<http://www.apache.org/licenses/LICENSE-2.0>.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.  See the License for the specific language governing
permissions and limitations under the License.


=cut

__PACKAGE__->meta->make_immutable;

1; # End of Store::Digest::HTTP
