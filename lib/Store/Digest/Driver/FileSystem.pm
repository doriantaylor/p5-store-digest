package Store::Digest::Driver::FileSystem;

use 5.010;
use strict;
use warnings FATAL => 'all';
use utf8;

use Moose;
use namespace::autoclean;

extends 'Store::Digest::Driver';
with    'Store::Digest::Role::Driver';

use MooseX::Types::Moose qw(HashRef ArrayRef);
use Store::Digest::Types qw(Directory DateTime Token);

use Store::Digest::Object;

use BerkeleyDB qw(DB_CREATE DB_GET_BOTH DB_INIT_CDB DB_INIT_LOCK
                  DB_INIT_TXN DB_INIT_MPOOL DB_NEXT DB_SET_RANGE
                  DB_GET_BOTH);

use Path::Class  ();
use File::Copy   ();
use MIME::Base32 ();
use URI::ni      ();

use File::MimeInfo::Magic ();

# directories
use constant STORE => 'store';
use constant TEMP  => 'tmp';


# digests with byte lengths
my %DIGESTS = (
    'md5'        => 16,
#    'ripemd-160' => 20,
    'sha-1'      => 20,
    'sha-256'    => 32,
    'sha-384'    => 48,
    'sha-512'    => 64,
);

# values for empty object
my %EMPTY = (
    'md5'     => 'd41d8cd98f00b204e9800998ecf8427e',
    'sha-1'   => 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    'sha-256' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'sha-384' => '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
    'sha-512' => 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
);

# pack these down
%EMPTY = map { $_ => pack('H*', $EMPTY{$_}) } keys %EMPTY;

=head1 NAME

Store::Digest::Driver::FileSystem - File system driver for Store::Digest

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

has dir => (
    is       => 'ro',
    isa      => Directory,
    required => 1,
    coerce   => 1,
);

has _env => (
    is  => 'rw',
    isa => 'BerkeleyDB::Env',
);

has _control => (
    is  => 'rw',
    isa => 'BerkeleyDB::Hash',
);

has _entries => (
    is      => 'ro',
    isa     => HashRef,
    lazy    => 1,
    default => sub { {} },
);

has _primary => (
    is       => 'rw',
    isa      => Token,
    required => 0,
    init_arg => 'primary',
);

has _algorithms => (
    is       => 'rw',
    isa      => ArrayRef[Token],
    required => 0,
    init_arg => 'algorithms',
);

=head1 SYNOPSIS

    my $store = Store::Digest->new(
        driver  => 'FileSystem',
        options => { dir => '/var/db/store-digest' }, # or wherever
    );

=head1 METHODS

=head2 new

=cut

sub _create_dirs {
    my $self = shift;

    my $d    = $self->dir;
    my @dirs = ($d, $d->subdir(STORE), $d->subdir(TEMP));
    for my $dir (@dirs) {
        my $stat = $dir->stat;
        if ($stat) {
            Carp::croak("Can't read and/or write $dir")
                  unless (-r $stat and -w $stat);
        }
        else {
            eval {
                my $mode = 0700;
                $dir->mkpath(0, $mode);
            };
            if ($@) {
                Carp::croak("Can't create $dir: $@");
            }
        }
    }
}


sub BUILD {
    my $self = shift;

    $self->_create_dirs;

    #warn $self->dir->absolute;
    my $flags = DB_CREATE|DB_INIT_MPOOL|DB_INIT_TXN|DB_INIT_LOCK;
    my $env = BerkeleyDB::Env->new(
        -Home  => $self->dir->absolute->stringify,
        -Mode  => 0600,
        -Flags => $flags,
    ) or Carp::croak
        ("Can't create transaction environment: $BerkeleyDB::Error");

    $self->_env($env);

    my $txn = $env->txn_begin;

    # create control
    my $control = BerkeleyDB::Hash->new(
        -Env      => $env,
        -Flags    => DB_CREATE,
        -Mode     => 0600,
        -Txn      => $txn,
        -Filename => 'control',
    ) or Carp::croak
        ("Can't create/bind control database: $BerkeleyDB::Error");

    $self->_control($control);

    # control stores:

    # algorithms used
    if ($control->db_get(algorithms => my $v) == 0) {
        my @alg = sort split(/\s*,+\s*/, $v);

        for my $a (@alg) {
            Carp::croak
                  ("CONTROL DATABASE CORRUPT: $a is not a valid algorithm")
                      unless defined $DIGESTS{$a};
        }

        # make sure this is sorted for comparison below
        $v = join ',', @alg;

        if (defined (my $w = $self->_algorithms)) {
            my $x = join ',', sort map { lc $_ } @$w;
            Carp::croak("Store is already initialized with: $v")
                  unless $x eq $v;
        }

        $self->_algorithms(\@alg);
    }
    else {
        my $w = $self->_algorithms || [keys %DIGESTS];
        for my $a (@$w) {
            Carp::croak
                  ("Driver initialization failed: $a is not a valid algorithm")
                      unless defined $DIGESTS{$a};
        }
        my $v = join ',', sort map { lc $_ } @$w;

        $self->_algorithms($w);
        $control->db_put(algorithms => $v);
    }

    # primary algorithm
    if ($control->db_get(primary => my $v) == 0) {
        Carp::croak("CONTROL DATABASE CORRUPT: $v is not a valid algorithm")
              unless defined $DIGESTS{$v};
        if (defined (my $w = $self->_primary)) {
            Carp::croak
                  ("Store is already initialized with primary algorithm $v")
                      unless $v eq lc $w;
        }
        $self->_primary($v);
    }
    else {
        my $v = lc($self->_primary || 'sha-256');
        Carp::croak("Driver initialization failed: $v is not a valid algorithm")
              unless defined $DIGESTS{$v};

        Carp::croak
              ("Driver initialization failed: $v must be in algorithm list")
                  unless grep { $_ eq $v } @{$self->_algorithms};

        $self->_primary($v);
        $control->db_put(primary => $v);
    }

    # total number of known hash entries
    unless ($control->db_get(objects => my $v) == 0) {
        $control->db_put(objects => 0);
    }

    # total number of hash entries where the payloads were removed
    unless ($control->db_get(deleted => my $v) == 0) {
        $control->db_put(deleted => 0);
    }

    # total number of bytes stored
    unless ($control->db_get(bytes => my $v) == 0) {
        $control->db_put(bytes => 0);
    }


    # store-wide creation and modification times
    my $now = time;
    unless ($control->db_get(ctime => my $v) == 0) {
        $control->db_put(ctime => $now);
    }

    unless ($control->db_get(mtime => my $v) == 0) {
        $control->db_put(mtime => $now);
    }



    # create algo btrees, these enable partial matches
    for my $k (@{$self->_algorithms}) {

        my $entries = BerkeleyDB::Btree->new(
            -Env      => $env,
            -Flags    => DB_CREATE,
            -Mode     => 0600,
            -Filename => $k,
            -Txn      => $txn,
        ) or Carp::croak
            ("Can't create/bind $k database: $BerkeleyDB::Error");

        $self->_entries->{$k} = $entries;
    }

    $txn->txn_commit;

    # hashes ctime atime dtime type language encoding charset
    #$self->_entries($entries);
}

=head2 add

=cut

sub _file_for {
    my ($self, $digest) = @_;
    # digest is assumed to be binary
    my $primary = $self->_primary;
    Carp::croak("Expecting binary $primary digest")
          unless length $digest eq $DIGESTS{$primary};

    my $b32   = lc MIME::Base32::encode_rfc3548($digest);
    my @parts = unpack('a4a4a4a*', $b32);

    $self->dir->file(STORE, @parts);
}

sub _inflate {
    # digest is binary
    my ($self, $digest, $record, $file) = @_;

    unless ($file) {
        my $f = $self->_file_for($digest);
        $file = $f if -f $f;
    }

    my $pri = $self->_primary;
    my %rec = ($pri => URI::ni->from_digest($digest, $pri, undef, 256));

    for my $algo (grep { $_ ne $pri } @{$self->_algorithms}) {
        my $b = substr $record, 0, $DIGESTS{$algo};
        $rec{$algo} = URI::ni->from_digest($b, $algo, undef, 256);

        # set the offset
        $record = substr($record, $DIGESTS{$algo});
    }

    my %p;
    @p{qw(ctime mtime dtime flags type language charset encoding)}
        = unpack('NNNCZ*Z*Z*Z*', $record);

    # delete the cruft
    for my $k (qw(dtime type language charset encoding)) {
        delete $p{$k} unless $p{$k};
    }

    if ($file) {
        my $stat    = $file->stat;
        $p{size}    = $stat->size;
        $p{content} = $file->openr;
    }

    $p{digests} = \%rec;

    return Store::Digest::Object->new(%p);
}

sub add {
    my ($self, %p) = @_;

    # open transactions on all databases
    my $txn = $self->_env->txn_begin;
    $txn->Txn($self->_control, values %{$self->_entries});

    #map { $_->Txn($txn) } ($self->_control, values %{$self->_entries});

    # To prevent aborted writes, we don't write files directly. We
    # write tempfiles and then rename them, like rsync does.
    my $tmpdir = $self->dir->subdir(TEMP);
    my ($tempfh, $tempname) = $tmpdir->tempfile;
    $tempname = Path::Class::File->new($tempname);

    # create Digest objects for each algorithm
    my %state = map { $_ => Digest->new(uc $_) } @{$self->_algorithms};

    # remove this
    my $content = delete $p{content};

    # XXX make block size tunable?
    while ($content->read(my $buf, 8192)) {
        # as the block is read, pass it into each digest algorithm.
        for my $k (keys %state) {
            $state{$k}->add($buf);
        }
        # and write it back out to the tempfile
        $tempfh->syswrite($buf);
    }
    # We will have to nuke this tempfile on its own.
    $tempfh->close;
    chmod 0400, $tempname;

    # Convert these into digests now
    $p{digests} ||= {};
    for my $k (keys %state) {
        # The state resets when you take the digest value, so clone it first
        my $bin = $state{$k}->clone->digest;
        my $b64 = $state{$k}->clone->b64digest;
        my $hex = $state{$k}->clone->hexdigest;
        # don't forget to turn this into
        utf8::downgrade($bin);
        # ehh do these too
        $p{digests}{$k} = URI::ni->from_digest($state{$k}, $k);

        # and finally
        $state{$k} = [$bin, $b64, $hex];
    }

    # Now check if the file is present
    my $bin    = $state{$self->_primary}[0];
    my $target = $self->_file_for($bin);

    if (-f $target) {
        #warn "yo got $target";

        # get rid of the temporary file
        unlink $tempname;

        my $db = $self->_entries->{$self->_primary};

        my $rec = '';
        $db->db_get($bin, $rec);

        my $p = $self->_primary;
        my %rec = ($p => URI::ni->from_digest($bin, $p, undef, 256));

        #warn $rec{$p};

        for my $algo (grep { $_ ne $p } @{$self->_algorithms}) {
            my $b = substr $rec, 0, $DIGESTS{$algo};
            $rec{$algo} = URI::ni->from_digest($b, $algo, undef, 256);
            #warn $rec{$algo};

            # set the offset
            $rec = substr($rec, $DIGESTS{$algo});
        }

        my $stat = $target->stat;

        @p{qw(ctime mtime dtime flags type language charset encoding)}
            = unpack('NNNCZ*Z*Z*Z*', $rec);

        # delete the cruft
        for my $k (qw(dtime type language charset encoding)) {
            delete $p{$k} unless $p{$k};
        }

        $p{size}    = $stat->size;
        $p{content} = $target->openr;
        $p{digests} = \%rec;

        $txn->txn_commit;

        return Store::Digest::Object->new(%p);
    }
    else {
        my $parent = $target->parent;
        eval { $parent->mkpath };
        Carp::croak("Can't create container path $parent: $@") if $@;

        # ONLY IF MISSING DO YOU ADD THE FILE
        File::Copy::move($tempname, $target);

        $p{size} = $target->stat->size;
        my $now  = time;

        my $control = $self->_control;
        $control->db_get(bytes   => my $dbsize);
        $control->db_get(objects => my $objects);

        $control->db_put(bytes   => $dbsize  + $p{size});
        $control->db_put(objects => $objects + 1);
        $control->db_put(mtime   => $now);

        # get the type by magic
        $p{type} = File::MimeInfo::Magic::mimetype($target->stringify)
            unless $p{type};

        # create entry record

        # XXX wait a sec you only need the primary hash as the value
        # for the non-primary tables because all they need to do is
        # look up the primary.

        # concatenate all the hashes together
        for my $k (keys %state) {

            my $rec;

            # the entry database for the primary digest algo takes the
            # additional information about the record
            if ($k eq $self->_primary) {
                # concatenate all binary hashes sorted by algorithm, except
                # for the one which is the key
                $rec = join('', map { $state{$_}[0] }
                                grep { $_ ne $k } sort keys %state);

                my $mtime = $p{mtime}->epoch; # blob modification time
                $p{ctime} = $now;             # record creation time
                $p{dtime} = 0;                # null deletion time

                # XXX make 'checked' and 'valid' flags for type,
                # charset, encoding

                # if a charset is claimed to be utf8 or latin1 or
                # something but only contains 7-bit characters,
                # downgrade the charset to us-ascii (and lol no we are
                # not going to support ebcdic)

                #warn $p{type};

                # generate string
                my @x = map { $_ || '' } @p{qw(type language charset encoding)};
                $rec .= pack('NNNCZ*Z*Z*Z*',
                             $p{ctime}, $mtime, $p{dtime}, 0, @x);

            }
            else {
                $rec = $state{$self->_primary}[0];
            }

            my $db = $self->_entries->{$k};
            if ($db->db_put($state{$k}[0], $rec) == 0) {
                #warn "put $k";
            }
            else {
                Carp::croak($BerkeleyDB::Error);
            }
        }

        if ($txn->txn_commit == 0) {
            #warn 'lol';
        }
        else {
            Carp::croak($BerkeleyDB::Error);
        }

        # here is where you return the object otherwise
        return Store::Digest::Object->new(%p);
    }
}


sub get {
    my ($self, $digest, $algo) = @_;
    my $pri = $self->_primary;

    # open a transaction to prevent stuff from changing mid-select
    my $txn     = $self->_env->txn_begin;
    my $index   = $self->_entries->{$algo};
    my $primary = $algo eq $pri ? $index : $self->_entries->{$pri};

    $txn->Txn($index, $primary);

    my $cursor = $index->db_cursor;

    utf8::downgrade($digest);


    $digest .= ("\0" x ($DIGESTS{$algo} - length $digest));

    warn unpack('H*', $digest);

    my @obj;
    my $rec;
    my $flag = DB_SET_RANGE | DB_GET_BOTH;
    my $d    = $digest;
    while ($cursor->c_get($d, $rec, $flag) == 0) {
        warn unpack('H*', $d);
        # set this flag right away
        $flag = DB_NEXT | DB_GET_BOTH;

        my $k = $d;
        # look up the full record
        if ($algo ne $pri) {
            $k = $rec;
            $primary->db_get($k, $rec);
        }

        push @obj, $self->_inflate($k, $rec);

        $d = $digest;
    }

    $txn->txn_commit;

    warn scalar @obj;
    #require Data::Dumper;
    #warn Data::Dumper::Dumper(\@obj);

    wantarray ? @obj : \@obj;
}

# removes data
sub remove {
}

# also purges
sub forget {
}

# usage stats
sub stats {
}

# beginning to think i should index by ctime/mtime/dtime/type/encoding

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

1; # End of Store::Digest::Driver::FileSystem
