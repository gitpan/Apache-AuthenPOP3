# $Id: Makefile.PL,v 1.3 2002/10/29 15:13:11 reggers Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
	NAME          => 'Apache::AuthenPOP3',
	DISTNAME      => 'Apache-AuthenPOP3',
	VERSION_FROM  => 'AuthenPOP3.pm',

	PREREQ_PM	=> {
		Net::POP3	=> 0
	},

	dist		=> {
		COMPRESS	=> "gzip",
		SUFFIX		=> "gz"
	}
);
