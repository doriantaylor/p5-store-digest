package Store::Digest::Role::Driver;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Moose::Role;
use namespace::autoclean;

use MooseX::Params::Validate ();

use MooseX::Types::Moose qw(Str);
use Store::Digest::Types qw(FiniteHandle DateTime RFC3066 DigestURI
                            ContentType Token StoreObject);

use DateTime;

=head1 NAME

Store::Digest::Role::Driver - Driver role for Store::Digest

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

    package Store::Digest::Driver::Mine;

    with 'Store::Digest::Role::Driver';

    # do your thing

=head1 DESCRIPTION

This module does everything common to L<Store::Digest> drivers.

=cut

around add => sub {
    my $orig = shift;

    # jimmy this to accept either an object or a filehandle as a sole
    # argument
    if ($_[1] and ref $_[1]) {
    }

    my ($self, %p) = MooseX::Params::Validate::validated_hash(
        \@_,
        content  => {
            isa      => FiniteHandle,
            optional => 0,
        },
        mtime    => {
            isa      => DateTime,
            optional => 1,
            coerce   => 1,
            default  => sub { DateTime->now },
        },
        type     => {
            isa      => ContentType,
            optional => 1,
        },
        language => {
            isa      => RFC3066,
            optional => 1,
        },
        charset  => {
            isa      => Token,
            optional => 1,
        },
        encoding => {
            isa      => Token,
            optional => 1,
        },
    );

    $self->$orig(%p);
};

# around get => sub {
#     my $orig = shift;
#     my ($self, $digest, $algo, $radix) =
#         MooseX::Params::Validate::pos_validated_list(
#             \@_,
#             { is => Str|DigestURI },        # digest or ni: URI
#             { is => Token, optional => 1 }, # optional algorithm
#             { is => Token, optional => 1 }, # optional radix
#         );

#     unless (Scalar::Util::blessed($digest)) {
#         $digest = URI::ni->from_digest($digest, $algo, undef, $radix);
#     }

#     #warn unpack("H*", $digest->digest);

#     $self->$orig($digest->digest, $digest->algorithm);
# };

around [qw(get remove forget)] => sub {
    my $orig = shift;
    my ($self, $digest, $algo, $radix) =
        MooseX::Params::Validate::pos_validated_list(
            \@_,
            { is => Str|DigestURI|StoreObject }, # digest, object or ni: URI
            { is => Token, optional => 1 },      # optional algorithm
            { is => Token, optional => 1 },      # optional radix
        );

    # XXX: this can be blessed as a URI::ni and still messed up
    unless (Scalar::Util::blessed($digest)) {
        $digest = URI::ni->from_digest($digest, $algo, undef, $radix);
    }

    $self->$orig($digest);
};

=head1 AUTHOR

Dorian Taylor, C<< <dorian at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-store-digest at
rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Store-Digest>.  I
will be notified, and then you'll automatically be notified of
progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Store::Digest::Driver

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Store-Digest>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Store-Digest>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Store-Digest>

=item * Search CPAN

L<http://search.cpan.org/dist/Store-Digest/>

=back

=head1 SEE ALSO

L<Store::Digest>

=head1 LICENSE AND COPYRIGHT

Copyright 2012 Dorian Taylor.

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License.  You may
obtain a copy of the License at
L<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing
permissions and limitations under the License.

=cut

#__PACKAGE__->meta->make_immutable;

1; # End of Store::Digest::Role::Driver
