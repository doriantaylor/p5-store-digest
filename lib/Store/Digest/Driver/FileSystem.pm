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
use Store::Digest::Types qw(Directory DateTimeType Token);

use Store::Digest::Object;
use Store::Digest::Stats;

use BerkeleyDB qw(DB_CREATE DB_GET_BOTH DB_INIT_CDB DB_INIT_LOCK
                  DB_INIT_TXN DB_INIT_MPOOL DB_NEXT DB_SET_RANGE
                  DB_GET_BOTH);

use Path::Class  ();
use File::Copy   ();
use MIME::Base32 ();
use URI::ni      ();
use Math::BigInt ();

use File::MimeInfo::Magic ();

# directories
use constant STORE   => 'store';
use constant TEMP    => 'tmp';
use constant BUFSIZE => 2**13;


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
        # XXX DO NOT FORGET TO SORT THIS
        $w = [sort map { lc $_ } @$w];
        my $v = join ',', @$w;

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

sub DEMOLISH {
    my $self = shift;
    for my $db (values %{$self->_entries}) {
        $db->db_close;
    }
    $self->_control->db_close;
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

# take an object and return a record
sub _deflate {
    my ($self, $obj) = @_;

    # find the primary algorithm
    my $pri = $self->_primary;
    my $key = $obj->digest($pri)->digest;
    # create concatenated string of binary digests
    my $rec = join('', map { $obj->digest($_)->digest }
                       grep { $_ ne $pri } $obj->digest);

    # get the rest of the object's contents
    my @rec = map {
        $obj->$_ ? $obj->$_->epoch : 0 } qw(ctime mtime ptime dtime);
    push @rec, $obj->_flags;
    push @rec, map { $obj->$_ || '' } qw(type language charset encoding);
    # add them to the record
    $rec .= pack('NNNNCZ*Z*Z*Z*', @rec);

    # optionally return the key
    return wantarray ? ($rec, $key) : $rec;
}

# take a record and return an object
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
        #warn $algo;
        my $b = substr $record, 0, $DIGESTS{$algo};
        $rec{$algo} = URI::ni->from_digest($b, $algo, undef, 256);

        # set the offset
        $record = substr($record, $DIGESTS{$algo});
    }

    my %p;
    @p{qw(ctime mtime ptime dtime flags type language charset encoding)}
        = unpack('NNNNCZ*Z*Z*Z*', $record);

    # delete the cruft
    for my $k (qw(dtime type language charset encoding)) {
        delete $p{$k} unless $p{$k};
    }

    if ($file) {
        my $stat    = $file->stat;
        $p{size}    = $stat->size;
        $p{content} = sub { $file->openr };
    }

    $p{digests} = \%rec;

    return Store::Digest::Object->new(%p);
}

sub add {
    my ($self, %p) = @_;
    my $pri = $self->_primary;
    my $ctl = $self->_control;

    # open transactions on all databases
    my $txn = $self->_env->txn_begin;
    $txn->Txn($ctl, values %{$self->_entries});

    # Step 1: record digests as we read the content handle into a
    # temporary file

    # To prevent aborted writes, we don't write files directly. We
    # write tempfiles and then rename them, like rsync does.
    my $tempdir = $self->dir->subdir(TEMP);
    my ($tempfh, $tempname) = $tempdir->tempfile;
    $tempname = Path::Class::File->new($tempname);

    # create Digest objects for each algorithm
    my %state = map { $_ => Digest->new(uc $_) } @{$self->_algorithms};

    # remove this; it's confusing
    my $content = delete $p{content};

    # XXX make block size tunable?
    while ($content->read(my $buf, BUFSIZE)) {
        utf8::downgrade($buf);
        # as the block is read, pass it into each digest algorithm.
        for my $k (keys %state) {
            #warn sprintf '%s %d', $k, length $buf;
            $state{$k}->add($buf);
            #warn $state{$k}->clone->hexdigest if $k eq 'md5';
        }
        # and write it back out to the tempfile
        $tempfh->syswrite($buf);
    }

    # We will have to nuke this tempfile on our own.
    $tempfh->close;
    chmod 0400, $tempname; # XXX tunable perms?

    # Convert these into digests now
    $p{digests} ||= {};
    for my $k (keys %state) {
        $p{digests}{$k} = URI::ni->from_digest($state{$k}, $k);
    }

    # Step 2: move the file into position unless there is already a copy

    my $bin = $p{digests}{$pri}->digest;
    # don't let perl mistake the binary digest for utf8
    utf8::downgrade($bin);
    my $target = $self->_file_for($bin);

    if (-f $target) {
        unlink $tempname;
    }
    else {
        my $parent = $target->parent;
        eval { $parent->mkpath };
        Carp::croak("Can't create container path $parent: $@") if $@;

        # ONLY IF MISSING DO YOU ADD THE FILE
        File::Copy::move($tempname, $target);
    }

    # Step 2: alter database entries

    my $db  = $self->_entries->{$pri};
    my $now = time;

    # if a record is present then we're just replacing the file
    my $obj;
    my $rec = '';
    $db->db_get($bin, $rec);
    if ($rec) {
        # create an object because it's easier to deal with
        $obj = $self->_inflate($bin, $rec);
        # note this will automatically load the file even if it was
        # marked deleted, since we already moved it into the tree.

        # if there is a dtime, clear it
        if ($obj->dtime and $obj->dtime->epoch > 0) {
            $obj->dtime(undef);

            # don't forget to decrement the deleted count by 1
            $ctl->db_get(deleted => my $deleted);
            $ctl->db_put(deleted =>  --$deleted) if $deleted > 0;
            # and no matter what, we don't want this number to be negative

            # set the modification time as well
            $ctl->db_put(mtime   => $now);

            # overwrite the record
            $rec = $self->_deflate($obj);
            $db->db_put($bin, $rec);
            #$db->db_sync;
        }
    }
    else {
        # set the mappings for the other digest algorithms
        my $e = $self->_entries;
        for my $algo (grep { $_ ne $pri } @{$self->_algorithms}) {
            my $k = $p{digests}{$algo}->digest;
            utf8::downgrade($k); # dat utf8

            $e->{$algo}->db_put($k, $bin);
            #$e->{$algo}->db_sync;
        }

        # tie up loose ends re the file
        my $stat    = $target->stat;
        $p{size}    = $stat->size;
        $p{content} = $target->openr;

        # get the type by magic if it's missing
        $p{type} = File::MimeInfo::Magic::mimetype($target->stringify)
            unless $p{type};

        # ctime is required
        $p{ctime} = $now;

        # now for the control db

        # increment byte count by file size
        $ctl->db_get(bytes   => my $bytes);
        $ctl->db_put(bytes   => $bytes += $p{size});
        # increment object count by 1
        $ctl->db_get(objects => my $objects);
        $ctl->db_put(objects =>  ++$objects);
        # set the modification time
        $ctl->db_put(mtime   => $now);

        # create the new object
        $obj = Store::Digest::Object->new(%p);

        # overwrite the record
        $rec = $self->_deflate($obj);
        $db->db_put($bin, $rec);
        #$db->db_sync;
    }

    # Step 4: commit the changes

    unless ($txn->txn_commit == 0) {
        Carp::croak($BerkeleyDB::Error);
    }

    # Step 5: return the object

    return $obj;
}

sub _best_uri {
    my ($self, $obj) = @_;

    # get the algorithm list from the object
    my %algo = map { $_ => 1 } $obj->digest;

    # see if the primary is present
    my $pri = $self->_primary;
    return $obj->digest($pri) if $algo{$pri};

    # extract the first ni: URI that matches
    my $d;
    for my $a ($self->_algorithms) {
        # this will attempt to match the primary algorithm a
        # second time but fuggit
        if ($algo{$a}) {
            $d = $obj->digest($a);
            last;
        }
    }
    return $d;
}

sub _obj_to_digest {
    my ($self, $obj) = @_;
    # $digest has been sanitized to be either a ni: URI or a
    # Store::Digest::Object.
    return $obj if $obj->isa('URI::ni');
    return $self->_best_uri($obj) if $obj->isa('Store::Digest::Object');
}

sub get {
    my $self   = shift;
    my $digest = $self->_obj_to_digest(shift) or return;
    # get raw data whatnot
    my $algo = $digest->algorithm;
    my $bin  = $digest->digest;
    utf8::downgrade($bin); # JIC

    # deal with database mumbo jumbo
    my $pri     = $self->_primary;
    my $index   = $self->_entries->{$algo};
    my $primary = $algo eq $pri ? $index : $self->_entries->{$pri};

    # open a transaction to prevent stuff from changing mid-select
    my $txn     = $self->_env->txn_begin;
    $txn->Txn($index, $primary);

    my $cursor = $index->db_cursor;

    # the 'last' key is padded with 0xff up to the algo size
    my $last = $bin . (pack('C', 255) x ($DIGESTS{$algo} - length $bin));

    # pad the key too
    $bin .= ("\0" x ($DIGESTS{$algo} - length $bin));

    #warn $algo;
    #warn unpack('H*', $bin);
    #warn unpack('H*', $last);

    my @obj;
    my $rec;
    my $flag = DB_SET_RANGE | DB_NEXT | DB_GET_BOTH;
    my $d    = $bin;

    while ($cursor->c_get($d, $rec, $flag) == 0) {
        #warn unpack('H*', $d);
        # set this flag right away
        #$flag = DB_NEXT | DB_GET_BOTH;

        # exit the loop if a key is lexically greater than 'last'
        last if $d gt $last;

        my $k = $d;

        # create the 'next' key by turning it into a bigint,
        # incrementing it, then turning it back into a string

        my $hk = unpack('H*', $k);
        #warn $hk;
        my $bi = Math::BigInt->new("0x$hk") + 1;
        #warn $bi->as_hex;
        #$bi += 1;
        #warn $bi->as_hex;

        my $bh = substr($bi->as_hex, 2);
        $bh = ('0' x ($DIGESTS{$algo}*2 - length $bh)) . $bh;
        my $bb = pack 'H*', $bh;
        #warn unpack('H*', $bb);

        # look up the full record in case the requested algorithm is
        # not the primary one.
        if ($algo ne $pri) {
            $k = $rec;
            $primary->db_get($k, $rec);
        }

        push @obj, $self->_inflate($k, $rec);

        $d = $bb;
    }

    $txn->txn_commit;

    #warn scalar @obj;
    #require Data::Dumper;
    #warn Data::Dumper::Dumper(\@obj);

    # XXX this is no good
    wantarray ? @obj : \@obj;
}

# I want to be able to do partial matches for gets but not for purges.
# There is no reasonable use case for mass deletions based on a
# partial match on a cryptographic digest.

# removes payload
sub remove {
    my $self   = shift;
    my $digest = $self->_obj_to_digest(shift) or return;
    # get raw data whatnot
    my $algo = $digest->algorithm;
    my $bin  = $digest->digest;
    utf8::downgrade($bin);

    my $txn = $self->_env->txn_begin;
    $txn->Txn($self->_control, values %{$self->_entries});

    my $pri = $self->_primary;
    unless ($algo eq $pri) {
        $self->_entries->{$algo}->db_get($bin, my $val);

        # return if we can't find a match
        unless ($val) {
            $txn->txn_commit;
            return;
        }

        $bin = $val;
    }

    $self->_entries->{$pri}->db_get($bin, my $rec);
    unless ($rec) {
        $txn->txn_commit;
        return;
    }

    my $obj = $self->_inflate($bin, $rec);

    # set the dtime if not already set

    # increment deleted objects
    # delete the file
    my $file = $self->_file_for($bin);

    $obj;
}

# also purges
sub forget {
}

sub list {
    my $self = shift;
}

# usage stats
sub stats {
    my $self = shift;

    my $ctl = $self->_control;

    my %x;
    for my $k (qw(objects deleted bytes ctime mtime)) {
        $ctl->db_get($k, my $val);
        $x{$k} = $val;
    }

    # fix these
    $x{created}  = DateTime->from_epoch(epoch => delete $x{ctime});
    $x{modified} = DateTime->from_epoch(epoch => delete $x{mtime});

    Store::Digest::Stats->new(%x);
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
