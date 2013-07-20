#!/usr/bin/perl -w
#
# test.pl -- verify that test.c has completed without errors
#
# Synopsis:
#   test.pl [<nturns>] [<test-program> [<arguments>]...]
#
# Where testprogram is either "testeld" (the default) or "pretest".
# The difference between them is that the former links with -lefence
# at compile time, while the latter needs it LD_PRELOAD:ed.  <nturns>
# specify how many times to run the test program (once by default).

use strict;

my $nfaults = 0;
my $error = 'etense: chkzone: red zone integrity violated';

# Parse the command line.
my $turns = @ARGV && $ARGV[0] =~ /^\d+/ ? shift : 1;
push(@ARGV, 'testeld') if !@ARGV;
if ($ARGV[0] eq "testeld")
{
	$ENV{'LD_LIBRARY_PATH'} = '.';
} else
{
	$ENV{'LD_PRELOAD'} = './libetense.so';
}
$ARGV[0] = "./$ARGV[0]"
	if index($ARGV[0], '/') < 0;

# Run
for (1..$turns)
{
	my $pid;
	local (*RFH, *WFH);

	pipe(RFH, WFH)
		or die;
	if (!($pid = fork()))
	{
		close(RFH);
		open(STDOUT, '>&', WFH);
		open(STDERR, '>&', WFH);
		exec(@ARGV);
		die;
	}

	$SIG{'__DIE__'} = sub { kill(TERM => $pid); die @_ };

	print "TURN $_\n";
	close(WFH);
	for (;;)
	{
		die if !defined ($_ = <RFH>);
		print if /\bROUND$/;
		last if /\bDONE!$/;
		next unless /\bNEGTEST (?:OVER|UNDER)$/;
		die if !defined ($_ = <RFH>);
		$nfaults++;
		next if /\bSIGSEGV$/;
		next if /\(buffer (?:over|under)run\?\)$/;
		die;
	}
	close(RFH);

	die if !$nfaults;
	print "faulted $nfaults times\n";
}

# End of test.pl
