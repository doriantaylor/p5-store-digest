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

    my $sd = Store::Digest::HTTP->new(store => $store);

    # $request is a HTTP::Request, Plack::Request, Catalyst::Request
    # or Apache2::RequestRec. $response is a Plack::Response.

    my $response = $sd->respond($request);

=head1 DESCRIPTION

This module provides a reference implementation for an HTTP interface
to L<Store::Digest>, a content-addressable storage system based on
L<RFC 6920|http://tools.ietf.org/html/rfc6920> and named information
(C<ni:>) URIs and their HTTP expansions. It is intended to provide a
generic, content-based storage mechanism for opaque data objects,
either uploaded by users, or the results of computations. The goal of
this system is to act as a holding tank for both permanent storage and
temporary caching, with its preservation/expiration policy handled out
of scope.

This module is designed with only a robust set of essential
functionality, with the expectation that it will be used as a
foundation for far more elaborate systems. Indeed, this module is
conceived primarily as an internal Web service which is only
accessible by trusted clients, even though through use it may be found
to exhibit value as a public resource.

=head1 SECURITY

This module has I<no concept> of access control, authentication or
authorization. Those concepts have been intentionally left out of
scope. There are more than enough existing mechanisms available to
protect, for instance, writing to and deleting from the store.
Preventing unauthorized reads is a little bit trickier.

The locations of the indexes can obviously be protected from
unauthorized reading through straight-forward authentication
rules. The contents of the store, however, will require an
authorization system which is considerably more sophisticated.

=head2 Scanning/Trawling

With the default SHA-256 digest algorithm, this (or any other)
implementation will keel over long before the distance between hash
values becomes short enough that a brute force scan will be
feasible. That won't stop people from trying. Likewise, by default,
L<Store::Digest> computes (and this module exposes) shorter digests
like MD5 for the express purpose of matching objects to hashes in the
event that that's all you've got. If you don't want this behaviour,
you can use external access control mechanisms to wall off entire
digest algorithms, or consider disabling the computation of those
algorithms altogether (since in that case they're only costing you).

A persistent danger pertaining to the feasibility of scanning, and
this is untested, is if some algorithm or other I<peaks>,
statistically, around certain values. This would drastically reduce
the effort required to score arbitrary hits, though they I<would> be
arbitrary.

For all other intents and purposes, the likelihood that an attacker
could correctly guess the location of a sensitive piece of data,
I<especially> without setting off alarm bells, is infinitesimal.

=head2 I<Go Fish> attacks

If an attacker has a particular data object, he/she can ask the system
if it has that object as well, simply by generating a digest and
crafting a C<GET> request for it. This scenario is obviously
completely inconsequential, I<except> for the rare case wherein you
need to be able to repudiate having some knowledge or other, at which
point it could be severely damaging.

=head2 Locking down individual objects

The objects in the store should be seen as I<representations>:
I<images> of information. It is entirely conceivable, if not expressly
anticipated, that two abstract resources, one public and one
confidential, could have I<identical> literal representations, with
identical cryptographic signatures. This would amount to I<one> object
being stored, presumably with I<two> (or more) references to it
inscribed in some higher-level system. The difference between what is
confidential, and what is public, is in the context. As such, access
control to concrete I<representations> should be mediated by access
control to abstract I<resources>, in some other part of the system.

=cut

my %DISPATCH;

=head1 RESOURCE TYPES

All resources respond to C<OPTIONS> requests, which list available
methods. Requests for resources for methods that have not been
specified will result in a L<405 Method Not Allowed> response.

=head2 Store contents: opaque data objects

These resources are identified by their full digest value. By default,
that means these URI paths:

    /.well-known/[dn]i/{algorithm}/{digest}
    /{algorithm}/{digest}

...where C<{algorithm}> is an active digest algorithm in the store,
and C<{digest}> is a complete, C<base64url> I<or> hexadecimal-encoded
cryptographic digest. If the digest is hexadecimal, the request will
be redirected (C<301> for C<GET>/C<HEAD>, C<307> for the rest) to its
C<base64url> equivalent.

=cut

$DISPATCH{object} = {};

=head3 C<GET>/C<HEAD>

When successful, this method returns the content of the identified
object. If the object has been deleted from the store, the response
will be C<410 Gone>. If it was never there in the first place, C<404
Not Found>. If the C<Accept-*> headers explicitly reject any of the
properties of the object, the response will properly be C<406 Not
Acceptable>.

Since these resources only have one representation which by definition
cannot be modified, the C<If-*> headers respond appropriately. The
ETag of the object is equivalent to its C<ni:> URI (in double quotes,
as per L<RFC 2616|http://tools.ietf.org/html/rfc2616>).

If the request includes a C<Range> header, the appropriate range will
be returned via C<206 Partial Content>. Note however that at this
time, multiple or non-byte ranges are not implemented, and such
requests will be met with a C<501 Not Implemented> error.

=cut

$DISPATCH{object}{GET} = sub {
};

=head3 C<PUT>

A store object responds to C<PUT> requests, primarily for the purpose
of symmetry, but it is also applicable to verifying arbitrary data
objects against supplied digests. That is, the URI of the C<PUT>
request B<must> match the actual digest of the object's contents in
the given algorithm. A mismatch between digest and content is
interpreted as an attempt to C<PUT> the object in question in the
wrong place, and is treated as C<403 Forbidden>.

If, however, the digest matches, the response will be either C<204 No
Content> or C<201 Created>, depending on whether or not the object was
already in the store. A C<PUT> request with a C<Range> header makes no
sense in this context and is therefore not implemented, and will
appropriately respond with C<501 Not Implemented>.

Any C<Date> header supplied with the request will become the C<mtime>
of the stored object, and will be reflected in the C<Last-Modified>
header in subsequent requests.

=cut

$DISPATCH{object}{PUT} = sub {
};

=head3 C<DELETE>

B<Note:> This module has I<no> concept of access control.

This request, as expected, unquestioningly deletes a store object,
provided one is present at the requested URI. If it is, the response
is C<204 No Content>. If not, the response is either C<404 Not Found>
or C<410 Gone>, depending on whether or not there ever was an object
at that location.

=cut

$DISPATCH{object}{DELETE} = sub {
};

=head3 C<PROPFIND>

A handler for the C<PROPFIND> request method is supplied to provide
direct access to the metadata of the objects in the store. Downstream
WebDAV applications can therefore use this module as a storage
back-end while only needing to interface at the level of HTTP and/or
WebDAV.

=cut

$DISPATCH{object}{PROPFIND} = sub {
};

=head3 C<PROPPATCH>

B<Note:> This module has I<no> concept of access control.

The C<PROPPATCH> method is supplied, first for parity with the
C<PROPFIND> method, but also so that automated agents, such as syntax
validators, can directly update the objects' metadata with their
findings.

Here are the DAV properties which are currently editable:

=over 4

=item C<creationdate>

This property sets the C<mtime> of the stored object, I<not> the
C<ctime>. The C<ctime> of a L<Store::Digest::Object> is the time it
was I<added> to the store, I<not> the modification time of the object
supplied when it was uploaded. Furthermore, per L<RFC
4918|http://tools.ietf.org/html/rfc4918>, the C<getlastmodified>
property SHOULD be considered I<protected>. As such, the meanings of
the C<creationdate> and C<getlastmodified> properties are inverted
from their intuitive values.

(XXX: is this dumb? Will I regret it?)

=item C<getcontentlanguage>

This property permits the data object to be annotated with one or more
L<RFC 3066 (5646)|http://tools.ietf.org/html/rfc5646> language tags.

=item C<getcontenttype>

This property permits automated agents to update the content type, and
when applicable, the character set of the object. This is useful for
providing an interface for storing the results of an asynchronous
verification of the store's contents through a trusted mechanism,
instead of relying on the claim of whoever uploaded the object that
these values match their contents.

=back

=cut

$DISPATCH{object}{PROPPATCH} = sub {
};

=head2 Individual metadata

This is a read-only hypertext resource intended primarily as the
response content to a C<POST> of a new storage object, such that the
caller can retrieve the digest value and other useful metadata. It
also doubles as a user interface for successive manual uploads, both
as interstitial feedback and as a control surface.

=cut

$DISPATCH{meta} = {};

=head3 C<GET>/C<HEAD>

    .../{algorithm}/{digest}?meta=true # not sure which of these yet
    .../{algorithm}/{digest};meta      # ... can't decide

Depending on the C<Accept> header, this resource will either return
RDFa-embedded (X)HTML, RDF/XML or Turtle (or JSON-LD, or whatever).
The HTML version includes a rudimentary interface to the
C<multipart/form-data> C<POST> target.

=cut

$DISPATCH{meta}{GET} = sub {
};

# the content-type of these GET handlers must be overrideable by query
# parameter, no?

# sure, 

=head2 Partial matches

Partial matches are read-only resources that return a list of links to
stored objects. The purpose is to provide an interface for retrieving
an object from the store when only the first few characters of its
digest are known. These resources are mapped under the following URI
paths by default:

    /.well-known/[dn]i/{algorithm}/{partial-digest}
    /.well-known/[dn]i/{partial-digest}
    /{algorithm}/{partial-digest}
    /{partial-digest}

...where C<{algorithm}> is an active digest algorithm in the store,
and C<{partial-digest}> is an I<in>complete, C<base64url> or
hexadecimal-encoded cryptographic digest, that is, one that is
I<shorter> than the appropriate length for the given algorithm. If the
path is given with no algorithm, the length of the digest content
doesn't matter, and all algorithms will be searched.

=head3 C<GET>/C<HEAD>

A C<GET> request will return a simple web page containing a list of
links to the matching objects. If exactly one object matches, the
response will be C<302 Found> (in case additional objects match in the
future). If no objects match, the response will be C<404 Not
Found>. If multiple objects match, this response will be returned with
a C<300 Multiple Choices> status, to reinforce the transient nature of
the resource.

B<TODO>: find or make an appropriate collection vocab, then implement
RDFa, RDF/XML, N3/Turtle, and JSON-LD variants.

=cut

$DISPATCH{partial}{GET} = sub {
};

=head3 C<PROPFIND>

B<TODO>: A C<PROPFIND> response, if it even makes sense to implement,
will almost certainly be contingent on whatever vocab I decide on.

=cut

$DISPATCH{partial}{PROPFIND} = sub {
};

=head2 Resource collections

These collections exist for diagnostic purposes, so that during
development we may examine the contents of the store without any
apparatus besides a web browser. By default, the collections are bound
to the following URI paths:

    /.well-known/[dn]i/{algorithm}/
    /{algorithm}/

The only significance of the C<{algorithm}> in the URI path is as a
residual sorting parameter, to be used only after the contents of the
store have been sorted by all other specified parameters. Otherwise
the results are the same for all digest algorithms. The default
sorting behaviour is to ascend lexically, first by type, then
modification time (then tiebreak by whatever other means remain).

=cut

$DISPATCH{collection} = {};

=head3 C<GET>/C<HEAD>

These resources are bona fide collections and will reflect the
convention by redirecting via C<301 Moved Permanently> to a path with
a trailing slash C</>. (Maybe?)

This is gonna have to respond to filtering, sort order and pagination.

(optional application/atom+xml variant?)

Here are the available parameters:

=over 4

=item C<tz> (ISO 8601 time zone)

Resolve date parameters against this time zone rather than the default
(UTC).

    tz=-0800

(XXX: use Olson rather than ISO-8601 so we don't have to screw around
with daylight savings? whynotboth.gif?)

=item C<boundary>

Absolute offset of bounding record, starting with 1. One value present
sets the upper bound; two values define an absolute range:

    boundary=100              # 1-100
    boundary=1&boundary=100   # same thing
    boundary=101&boundary=200 # 101-200

=item C<sort> (Filter parameter name)

One or more instances of this parameter, in the order given, override
the default sorting criterion, which is this:

    sort=type&sort=mtime

=item C<reverse> (Boolean)

Flag for specifying a reverse sort order:

    reverse=true

=item C<complement> (Filter parameter name)

Use the complement of the specified filter criteria:

    type=text/html&complement=type # everything but text/html

=back

Here are the sorting/filtering criteria:

=over 4

=item C<size>

The number of bytes, as a range. One for lower bound, two for a range:

    size=1048576     # at least a megabyte
    size=0&size=1024 # no more than a kilobyte

=item C<type>

The C<Content-Type> of the object. Enumerable:

    type=text/html&type=text/plain&type=application/xml

=item C<charset>

The character set of the object. Enumerable:

    charset=utf-8&charset=iso-8859-1&charset=windows-1252

=item C<encoding>

The C<Content-Encoding> of the object. Enumerable:

    encoding=gzip&encoding=bzip2&encoding=identity

=item C<ctime>

The I<creation> time, as in the time the object was added to the
store. One for I<lower> bound, two for range:

    ctime=2012-01-01 # everything added since January 1, 2012
    ctime=2012-01-01&ctime=2012-12-31 # only the year of 2012

Applying C<complement> to this parameter turns the one-instance form
into an I<upper> bound, and the range to mean everything I<but> its
contents. This parameter takes ISO 8601 datetime strings or subsets
thereof, or epoch seconds.

=item C<mtime>

Same syntax as C<ctime>, except concerns the modification time
supplied by the I<user> when the object was inserted into the store.

=item C<ptime>

Same as above, except concerns the latest time at which only the
I<metadata> of the object was modified.

=item C<dtime>

Same as above, except concerns the latest time the object was
I<deleted>. As should be expected, if this parameter is used, objects
which are currently present in the store will be omitted. Only the
traces of deleted objects will be shown.

=back

=cut

$DISPATCH{collection}{GET} = sub {
};

=head3 C<PROPFIND>

B<TODO>: Again, C<PROPFIND> responses, not sure how to define 'em at
this time.

=cut

$DISPATCH{collection}{PROPFIND} = sub {
};

=head2 Summary and usage statistics

This resource acts as the "home page" of this module. Here we can
observe the contents of L<Store::Digest::Stats>, such as number of
objects stored, global modification times, storage consumption ,
reclaimed, space, etc. We can also choose our preferred time zone and
digest algorithm for browsing the store's contents, as well as upload
a new file.

=cut

$DISPATCH{stats} = {};

=head3 C<GET>/C<HEAD>

Depending on the C<Accept> header, this handler returns a simple web
page or set of RDF triples.

=cut

$DISPATCH{stats}{GET} = sub {
};

=head3 C<PROPFIND>

B<TODO>: Define RDF vocab before PROPFIND.

=cut

$DISPATCH{stats}{PROPFIND} = sub {
};

=head2 C<POST> target, raw

This is a URI that only handles POST requests, which enable a thin
(e.g., API) HTTP client to upload a data object without the effort or
apparatus needed to compute its digest. Headers of interest to the
request are naturally C<Content-Type>, and C<Date>. The path of this
URI is set in the constructor, and defaults to:

    /0c17e171-8cb1-4c60-9c58-f218075ae9a9

=cut

$DISPATCH{raw} = {};

=head3 C<POST>

This response accepts the request content and attempts to store it. If
unsuccessful, it will return either C<507 Insufficient Storage> or
C<500 Internal Server Error>. If successful, the response will
redirect via C<303 See Other> to the appropriate L</Individual
metadata> resource. Note that the request body will be stored
I<as-is>, that is, I<not> interpreted like the contents of a web
form. C<multipart/form-data> request bodies will be stored literally
as such. Interpreting such request bodies is the role of next and
final resource in this list.

The contents of the following request headers are stored along with
the content of the request body:

=over 4

=item *

C<Content-Type>

=item *

C<Content-Language>

=item *

C<Content-Encoding>

=item *

C<Date>

=back

=cut

$DISPATCH{raw}{POST} = sub {
};

# in the case of POST, we have a special location for
# multipart/form-data but otherwise take raw input directly to the
# POST location

=head2 C<POST> target, multipart/form-data

This resource behaves identically to the one above, except that takes
its data from C<multipart/form-data> fields rather than headers. This
resource is designed as part of a I<rudimentary> interface for adding
objects to the store. It is intended for use during development and
explicitly I<not> for production, outside the most basic requirements.
Its default URI path, also configurable in the constructor, is:

    /12d851b7-5f71-405c-bb44-bd97b318093a

=cut

$DISPATCH{form} = {};

=head3 C<POST>

This handler expects a C<POST> request with C<multipart/form-data>
content I<only>; any other content type will result in a C<409
Conflict>. The same response will occur if the request body does not
contain a file part. Malformed request content will be met with a
C<400 Bad Request>. The handler will process I<only> the I<first> file
part found in the request body; it will ignore the field name. If
there are C<Content-Type>, C<Date>, etc. headers in the MIME subpart,
those will be stored. The file's name, if supplied, is ignored, since
mapping names to content is deliberately out of scope for
L<Store::Digest>.

=cut

$DISPATCH{form}{POST} = sub {
};

=head1 METHODS

=head2 new

    my $sdh = Store::Digest::HTTP->new(store => $store);

=over 4

=item store

This is a reference to a L<Store::Digest> object.

=cut

has store => (
    is       => 'ro',
    isa      => 'Store::Digest',
    required => 1,
);

=item base

This is the base URI path, which defaults to C</.well-known/ni/>.

=cut

has base => (
    is       => 'ro',
    isa      => 'Str',
    required => 0,
    lazy     => 1,
    default  => '/.well-known/ni/',
);

=item post_raw

This overrides the location of the raw C<POST> target, which defaults
to C</0c17e171-8cb1-4c60-9c58-f218075ae9a9>.

=cut

# XXX include some mechanism so this module can register the UUID URIs

has post_raw => (
    is       => 'ro',
    isa      => 'Str',
    required => 0,
    lazy     => 1,
    default  => '/0c17e171-8cb1-4c60-9c58-f218075ae9a9',
);

=item post_form

This overrides the location of the form-interpreted C<POST> target,
which defaults to C</12d851b7-5f71-405c-bb44-bd97b318093a>.

=cut

has post_form => (
    is       => 'ro',
    isa      => 'Str',
    required => 0,
    lazy     => 1,
    default  => '/12d851b7-5f71-405c-bb44-bd97b318093a',
);


=item param_map

Any of the URI query parameters used in this module can be remapped to
different literals using a HASH reference like so:

    # in case 'mtime' collides with some other parameter elsewhere
    { modified => 'mtime' }

=back

=cut

has param_map => (
    is       => 'ro',
    isa      => 'HashRef',
    required => 0,
    lazy     => 1,
    default  => sub { { } },
);

=head2 respond

    my $response = $sdh->respond($request);



=cut

sub respond {
    # ok this thing should be able to handle a HTTP::Request,
    # Plack::Request, Catalyst::Request, and Apache2::RequestRec

    # we only care about the method, request-uri, headers for just
    # about everything except POST and PUT (and PROPFIND/PROPPATCH).

    # We should normalize all body input to an IO handle or duck type
    # in the case of apache

    # now that that's sorted out, here's the resolver:

    # first we check for exact matches to uploader URI paths

    # then we should clip off the prefix(es)

    # if we don't positively identify a resource type, return 404

    # if the resource type does not have a handler for the request
    # method, return 405

    # otherwise eval the handler

    # if the handler raises, return 500

    # otherwise return the handler's response


    # we should return a Plack::Response. maybe?
}

=head1 TO DO

I think diff coding/instance manipulation (L<RFC
3229|http://tools.ietf.org/html/rfc3229> and L<RFC
3284|http://tools.ietf.org/html/rfc3284>) would be pretty cool. Might
be better handled by some other module,

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
