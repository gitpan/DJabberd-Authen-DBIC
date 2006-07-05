package DJabberd::Authen::DBIC;
use strict;
use warnings;
use Digest;
use Carp;

use base 'DJabberd::Authen';
use DJabberd::Log;

=head1 NAME

DJabberd::Authen::DBIC - A DBIC authentication module for DJabberd

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

       <VHost mydomain.com>

               [...]

               <Plugin DJabberd::Authen::DBIC>
                       DBType          mysql || pgsql || ...
                       DBName          mydbname
                       DBHost          192.168.12.35   # optional
                       DBPort          6723                    # optional
                       DBUserName      adbuser   #optional 
                       DBPassword      somepass  #optional 
                       DBUsernameColumn     djusername
                       DBPasswordColumn     djpassword
                       DBSchemaClass    MyApp::Schema
                       DBTableClass     Users
                       DBResultSet      mysearch  #optional function that returns a custom resultset
                       DBQuoteChar      `  #optional quoting character
                       DBNameSep        .  #optional separator between tablea nd column names
                       DigestAlgorithm    Any algorithm supported by Digest->new()      #optional
                       DigestEncoding     binary || hex || base64      #optional, defaults
               </Plugin>
       </VHost>

=cut

our $logger = DJabberd::Log->get_logger;

sub log {
    $logger;
}


sub set_config_dbusername {
    $_[0]->{'dbic_dbusername'} = $_[1];
}

sub set_config_dbpassword {
    $_[0]->{'dbic_dbpassword'} = $_[1];
}

sub set_config_dbhost {
    $_[0]->{'dbic_dbhost'} = $_[1];
}

sub set_config_dbtype {
    $_[0]->{'dbic_dbtype'} = $_[1];
}

sub set_config_dbport {
    $_[0]->{'dbic_dbport'} = $_[1];
}

sub set_config_dbname {
    $_[0]->{'dbic_dbname'} = $_[1];
}

sub set_config_dbschemaclass {
    $_[0]->{'dbic_dbschemaclass'} = $_[1];
}

sub set_config_dbtableclass {
    $_[0]->{'dbic_dbtableclass'} = $_[1];
}

sub set_config_dbusernamecolumn {
    $_[0]->{'dbic_dbusernamecolumn'} = $_[1];
}

sub set_config_dbpasswordcolumn {
    $_[0]->{'dbic_dbpasswordcolumn'} = $_[1];
}

sub set_config_dbresultset {
    $_[0]->{'dbic_dbresultset'} = $_[1];
}

sub set_config_dbquotechar {
    $_[0]->{'dbic_dbquotechar'} = $_[1];
}

sub set_config_dbnamesep {
    $_[0]->{'dbic_dbnamesep'} = $_[1];
}

sub set_config_digestalgorithm {
    my ($self, $class) = @_;
    $self->{'dbic_digestobj'} = eval{ Digest->new($class) } if $class;
    croak("$class could not be used as a digest algorithm: $@") 
	unless (ref $self->{'dbic_digestobj'});
}

sub set_config_digestencoding {
    my ($self, $encoding) = @_;
    ($self->{'dbic_digestencoding'}) = ( $encoding =~ /^(binary|hex|base64)$/);
    croak ("$encoding is not a supported encoding scheme") 
	unless($self->{'dbic_digestencoding'});
}

sub finalize {
   my $self = shift;

   croak("Could not load $self->{'dbic_dbschemaclass'}")
       unless eval("require $self->{'dbic_dbschemaclass'}");

   my $dsn = 'dbi:'.$self->{'dbic_dbtype'}.':database='.$self->{'dbic_dbname'};
   $dsn .= ";host=".$self->{'dbic_dbhost'} if(defined $self->{'dbic_dbhost'});
   $dsn .= ";port=".$self->{'dbic_dbport'} if(defined $self->{'dbic_dbport'});
   
   my $sqt_opts = {};
   $sqt_opts->{'quote_char'} = $self->{'dbic_dbquotechar'} 
       if(defined $self->{'dbic_dbquotechar'});
   $sqt_opts->{'name_sep'} = $self->{'dbic_dbnamesep'}
       if(defined $self->{'dbic_dbnamesep'});
   
   $self->{'dbic_schema'} = 
       $self->{'dbic_dbschemaclass'}->connect($dsn,
					      $self->{'dbic_dbusername'},
					      $self->{'dbic_dbpassword'}, 
					      $sqt_opts
					     );

   croak("Could not connect to the database") unless(ref $self->{'dbic_schema'});
}


=head2 can_retrieve_cleartext

  bool can_retrieve_cleartext()

  Will return false if a valid digest type was specified in the config;

=cut

sub can_retrieve_cleartext {
    return defined(shift->{'dbic_digestobj'}) ? 0 : 1;
}

=head2 dbic_rs

ResultSet = dbic_rs()

Will return a L<DBIx::Class::ResultSet> object. 

=cut

sub dbic_rs{
    my $self = shift;

    my $rs = $self->{'dbic_schema'}->resultset($self->{'dbic_dbtableclass'});

    if(defined $self->{'dbic_dbresultset'}){
	my $crs = $self->{'dbic_dbresultset'};
	return $rs->$crs if($rs->can($rs) );
    }

    return $rs;
}

=head2 get_password(username => $username)

Will pass back the stores password to DJabberD for further checking. Will deny connection if username is invalid.

=cut

sub get_password {
    my ($self, $cb, %args) = @_;
    my $username = $args{'username'};
    
    my $user = $self->dbic_rs->find({$self->{'dbic_dbusernamecolumn'} => $username });
    unless(defined $user){
	$cb->decline;
	return;
    }

    $cb->set($user->get_column($self->{'dbic_dbpasswordcolumn'}));
}

=head2 check_cleartext

bool check_cleartext(username => $username, password => $cleartext_password)

Will accept or reject a connection depending on whether the user exists and the password is right or wrong.

=cut

sub check_cleartext {
   my ($self, $cb, %args) = @_;
   my $username = $args{username};
   my $password = $self->_prep_password($args{password});

   unless ($username =~ /^\w+$/) {
       $cb->reject;
       return;
   }

   my $user = $self->dbic_rs->find({$self->{'dbic_dbusernamecolumn'} => $username});
   if(!defined $user){
       $cb->reject();
       $self->log->info("User '$username' denied, does not exist in database");
       return 0;
   } elsif($user->get_column($self->{'dbic_dbpasswordcolumn'}) eq $password){
       $cb->accept;
       $self->log->debug("User '$username' successfully logged in");
       return 1;
   } else{
       $cb->reject();
       $self->log->info("User '$username' denied, password error");
       return 0;   
   }
}

=head2 _prep_password($clear_text_pw)

encoded string = _prep_password(string);

Will return an encoded string if DigestEncoding and DigestAlgorithm are defined, otherwise returns plain text.

=cut

sub _prep_password {
    my ($self, $value) = @_;
    my $digest_str;

    #return plaintext if we dont have a valid digest object
    return $value unless (defined $self->{'dbic_digestobj'});
    
    $self->{'dbic_digestobj'}->add($value);

    if ($self->{dbic_digestencoding} eq 'binary') {
        $digest_str = eval { $self->{'dbic_digestobj'}->digest };    
    } elsif ($self->{dbic_digestencoding} eq 'hex') {
        $digest_str = eval { $self->{'dbic_digestobj'}->hexdigest };
    } else {
        $digest_str = eval { $self->{'dbic_digestobj'}->b64digest } ||
	    eval { $self->{'dbic_digestobj'}->base64digest };
    }

    $self->log->info("could not get a digest string: $@") 
	unless defined($digest_str);

    return $digest_str;
}


=head1 AUTHOR

Guillermo Roditi, (groditi) C<< <groditi at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-djabberd-authen-dbic at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=DJabberd-Authen-DBIC>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc DJabberd::Authen::DBIC

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/DJabberd-Authen-DBIC>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/DJabberd-Authen-DBIC>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=DJabberd-Authen-DBIC>

=item * Search CPAN

L<http://search.cpan.org/dist/DJabberd-Authen-DBIC>

=back

=head1 ACKNOWLEDGEMENTS

Based partly upon L<DBIx::Class::DigestColumns>.

=head1 SEE ALSO

L<Digest>
L<DBIx::Class>
L<DJabberd>
L<DJabberd::Authen>

=head1 COPYRIGHT & LICENSE

Copyright 2006 Guillermo Roditi, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of DJabberd::Authen::DBIC
