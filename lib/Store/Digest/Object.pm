package Store::Digest::Object;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Carp 'verbose';

use Moose;
use namespace::autoclean;

use MooseX::Types::Moose qw(Maybe);
use Store::Digest::Types qw(FiniteHandle DigestHash
                            NonNegativeInt MimeType Token DateTime);

=head1 NAME

Store::Digest::Object - One distinct Store::Digest data object

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

    my $dataobj = $store->get('sha-256' => $key);

    my $fh = $dataobj->content;


=head1 METHODS

This class exists to encapsulate the metadata relevant to a
L<Store::Digest> data object. It is not instantiated directly. All
methods are read-only accessors.

=head2 content

Returns a filehandle or equivalent, pointing to the object's content,
open in read-only mode. Unless the object has been deleted, then this
will be C<undef>.

=cut

has content => (
    is       => 'ro',
    required => 0,
    isa      => Maybe[FiniteHandle],
);

=head2 digest

    my $uri = $dataobj->digest('sha-1');

    my @algos = $dataobj->digest;

Returns a L<URI::di> object for the relevant digest algorithm. Will
croak if an invalid digest algorithm is supplied. While valid digest
algorithms are specified at creation time, you can retrieve them by
calling this method with no arguments.

=cut

has _digests => (
    is       => 'ro',
    isa      => DigestHash,
    required => 1,
    init_arg => 'digests',
);

sub digest {
    my ($self, $digest) = @_;
    my $d = $self->_digests;
    unless (defined $digest) {
        my @k = sort keys %$d;
        return wantarray ? @k : \@k;
    }

    # lowercase it
    $digest = lc $digest;

    # hee hee self-reference
    Carp::croak("No digest named $digest, only " . join ' ' , $self->digest)
          unless defined $d->{$digest};

    # clone the URI so that it can't be messed with
    $d->{$digest}->clone;
}

=head2 size

Returns the byte size of the object. Note that for deleted objects,
this will be whatever the size of the object was before it was
deleted.

=cut

has size => (
    is       => 'ro',
    isa      => NonNegativeInt,
    required => 1,
);

=head2 type

Returns the MIME type

=cut

has type => (
    is       => 'ro',
    isa      => MimeType,
    required => 1,
);

=head2 charset

Returns the character set (e.g. C<utf-8>) of the data object if known.

=cut

has charset => (
    is       => 'ro',
    isa      => Maybe[Token],
    required => 0,
);

=head2 language

Returns the natural language in
L<http://tools.ietf.org/html/rfc5646|RFC 5646> format, if it was
supplied.

=cut

has language => (
    is       => 'ro',
    isa      => Maybe[Token],
    required => 0,
);

=head2 encoding

Returns the I<transfer encoding>, of the data object if known,
(e.g. C<gzip> or C<deflate>, I<not> the L</charset>).

=cut

has encoding => (
    is       => 'ro',
    isa      => Maybe[Token],
    required => 0,
);

=head2 ctime

Returns the timestamp at which the object was I<added> to
the store, from the point of view of the system.

=cut

has ctime => (
    is       => 'ro',
    isa      => DateTime,
    required => 1,
);

=head2 mtime

Returns the timestamp that was supplied as the modification time of
the object from the point of view of the I<user>, if different from
L</ctime>.

=cut

has mtime => (
    is       => 'ro',
    isa      => Maybe[DateTime],
    required => 0,
);

=head2 dtime

Returns the system timestamp at which the object was I<deleted>, if
applicable.

=cut

has dtime => (
    is       => 'ro',
    isa      => Maybe[DateTime],
    required => 0,
);

=head1 AUTHOR

Dorian Taylor, C<< <dorian at cpan.org> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2012 Dorian Taylor.

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License. You may
obtain a copy of the License at
L<http://www.apache.org/licenses/LICENSE-2.0>.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.  See the License for the specific language governing
permissions and limitations under the License.


=cut

__PACKAGE__->meta->make_immutable;

1; # End of Store::Digest::Object
