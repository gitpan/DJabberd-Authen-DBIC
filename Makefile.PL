use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'DJabberd::Authen::DBIC',
    AUTHOR              => 'Guillermo Roditi <groditi@cpan.org>',
    VERSION_FROM        => 'lib/DJabberd/Authen/DBIC.pm',
    ABSTRACT_FROM       => 'lib/DJabberd/Authen/DBIC.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
	'Digest' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'DJabberd-Authen-DBIC-*' },
);
