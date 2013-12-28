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

has store => (
    is       => 'ro',
    isa      => 'Store::Digest',
    required => 1,
);

=head1 SYNOPSIS

    use Store::Digest::HTTP;

    my $sd = Store::Digest::HTTP->new(store => $store);

    # $request is a HTTP::Request, Plack::Request, Catalyst::Request
    # or Apache2::RequestRec. $response is a Plack::Response.

    my $response = $sd->respond($request);

=head1 METHODS

=head2 new

=over 4

=item store

=item other stuff

=back

=head2 respond

yar

=cut

sub respond {
    # ok this thing should be able to handle a HTTP::Request,
    # Plack::Request, Catalyst::Request, and Apache2::RequestRec

    # we only care about the method, request-uri, headers for just
    # about everything except POST and PUT (and PROPFIND/PROPPATCH).

    # We should normalize all body input to an IO handle or duck type
    # in the case of apache

    # requests to the indexes should be sortable/paginated by query
    # string

    # content-type must be overrideable by query parameter

    # in the case of POST, we have a special location for
    # multipart/form-data but otherwise take raw input directly to the
    # POST location

    # we should return a Plack::Response. maybe?
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

# should everything respond to OPTIONS? yes

=head1 RESOURCE TYPES

This system has no concept of authentication or authorization.

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

=head3 C<GET>/C<HEAD>

When successful, this method returns the content of the identified
object. If the object has been deleted from the store, the response
will be C<410 Gone>. If the C<Accept-*> headers explicitly reject any
of the properties of the object, the response will properly be C<406
Not Acceptable>.

Since these resources only have one representation which by definition
cannot be modified, the C<If-*> headers respond appropriately. The
ETag of the object is equivalent to its digest URI, in double quotes,
as per RFC 2616.

If the request includes a C<Range> header, the appropriate range will
be returned via C<206 Partial Content>. Note however that at this
time, multiple or non-byte ranges are not implemented, and such
requests will be met with a C<501 Not Implemented> error.

=head3 C<PUT>

A store object responds to C<PUT> requests, primarily for the purpose
of symmetry, but it is also applicable to validating arbitrary data
objects against supplied digests. That is, the URI of the C<PUT>
request B<must> match the actual digest of the object's contents in
the given algorithm. If the digest matches, the response will be
either C<204 No Content> or C<201 Created>, depending on whether or
not the object was already in the store. A C<PUT> request with a
C<Range> header makes no sense in this context and is therefore not
implemented, and will appropriately respond with C<501 Not
Implemented>.

Any C<Date> header supplied with the request will become the C<mtime>
of the stored object, and will be reflected in the C<Last-Modified>
header in subsequent requests.

=head3 C<DELETE>

B<Note:> This module has I<no> concept of access control.

This request, as expected, unquestioningly deletes a store object,
provided one is present at the requested URI. If it is, the response
is C<204 No Content>. If not, the response is either C<404 Not Found>
or C<410 Gone>, depending on whether or not there ever was an object
at that location.

=head3 C<PROPFIND>

A handler for the C<PROPFIND> request method is supplied to provide
direct access to the metadata of the objects in the store. Downstream
WebDAV applications can therefore use this module as a storage
back-end while maintaining ignorance of any communication protocol
besides HTTP and WebDAV.

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
supplied when it was uploaded. Furthermore, per RFC 4918, the
C<getlastmodified> property SHOULD be considered I<protected>. As
such, the meanings of the C<creationdate> and C<getlastmodified>
properties are inverted from their intuitive values.

=item C<getcontentlanguage>

This property permits the data object to be annotated with one or more
RFC 3066 (5646) language tags.

=item C<getcontenttype>

This property permits automated agents to update the content type, and
when applicable, the character set of the object. This is useful for
providing an interface for storing the results of an asynchronous
verification of the store's contents through a trusted mechanism,
instead of relying on the claim of whoever uploaded the object that
these values match their contents.

=back

=head2 Individual metadata

This is a read-only hypertext resource intended primarily as the
response content to a C<POST> of a new storage object, such that the
caller can retrieve the digest value and other useful metadata. It
also doubles as a user interface for successive manual uploads, both
as interstitial feedback and as a control surface.

=head3 C<GET>/C<HEAD>

    /{algorithm}/{digest}?meta=true
    /{algorithm}/{digest};meta

Depending on the C<Accept> header, this resource will either return
RDFa-embedded (X)HTML, RDF/XML or Turtle (or JSON-LD, or whatever).
The HTML version includes a rudimentary interface to the
C<multipart/form-data> C<POST> target.

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
and C<{partial-digest}> is an I<in>complete, C<base64url>-encoded
cryptographic digest, that is, one that is I<shorter> than the
appropriate length for the given algorithm. If the path is given with
no algorithm, the length of the digest content doesn't matter.

=head3 C<GET>/C<HEAD>

A C<GET> request will return a simple web page containing a list of
links to the matching objects. If exactly one object matches, the
response will be C<302 Found> (in case additional objects match in the
future). If no objects match, the response will be C<404 Not
Found>. If multiple objects match, the response will be C<300 Multiple
Choices>, to reinforce the transient nature of the resource.

B<TODO>: find or make an appropriate collection vocab, then implement
RDFa, RDF/XML, N3/Turtle, and JSON-LD variants.

=head3 C<PROPFIND>

B<TODO>: A C<PROPFIND> response, if it even makes sense to implement,
will almost certainly be contingent on whatever vocab I decide on.

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

=head3 C<GET>/C<HEAD>

These resources are bona fide collections and will reflect the
convention by redirecting via C<301 Moved Permanently> to a path with
a trailing slash C</>. (Maybe?)

This is gonna have to respond to filtering, sort order and pagination.

(optional application/atom+xml variant?)

Here are the default parameters:

=over 4

=item C<timezone> (ISO 8601 time zone)

Resolve date parameters against this time zone rather than the default
(UTC).

    timezone=-0800

=item C<boundary>

Absolute offset of bounding record, starting with 1. One value present
sets the upper bound; two values define an absolute range:

    boundary=100              # 1-100
    boundary=1&boundary=100   # same thing
    boundary=101&boundary=200 # 101-200

=item C<sort> (Filter parameter name)

Sort 

=item C<reverse> (Boolean)

Flag for specifying a reverse sort order

=item C<complement> (Filter parameter name)

Use the complement of the specified filter criteria.

=back

Here are the sorting/filtering criteria:

=over 4

=item C<size>

=item C<type>

=item C<charset>

=item C<encoding>

=item C<ctime>

=item C<mtime>

=item C<ptime>

=item C<dtime>

=back

=head3 C<PROPFIND>

B<TODO>: Again, C<PROPFIND> responses, not sure how to define 'em at
this time.

=head2 Summary and usage statistics

This resource acts as the "home page" of this module. Here we can
observe the contents of L<Store::Digest::Stats>, such as number of
objects stored, global modification times, storage consumption ,
reclaimed, space, etc. We can also choose our preferred time zone and
digest algorithm for browsing the store's contents, as well as upload
a new file.

=head3 C<GET>/C<HEAD>

=head3 C<PROPFIND>

B<TODO>: Define RDF vocab before PROPFIND.

=head2 C<POST> target, raw

This is a URI that only handles POST requests, which enable a thin
(e.g., API) HTTP client to upload a data object without having to
waste effort computing its digest. Headers of interest to the request
are naturally C<Content-Type>, and C<Date>. The path of this URI is
set in the constructor, and defaults to:

    /0c17e171-8cb1-4c60-9c58-f218075ae9a9

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

=item C<Content-Type>

=item C<Content-Language>

=item C<Content-Encoding>

=item C<Date>

=back

=head2 C<POST> target, multipart/form-data

This resource behaves identically to the one above, except that takes
its data from C<multipart/form-data> fields rather than headers. This
resource is designed as part of a I<rudimentary> interface for adding
objects to the store. It is intended for use during development and
explicitly I<not> for production, outside the most basic requirements.
Its default URI path, also configurable in the constructor, is:

    /12d851b7-5f71-405c-bb44-bd97b318093a

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
