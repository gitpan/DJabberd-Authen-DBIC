#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'DJabberd::Authen::DBIC' );
}

diag( "Testing DJabberd::Authen::DBIC $DJabberd::Authen::DBIC::VERSION, Perl $], $^X" );
