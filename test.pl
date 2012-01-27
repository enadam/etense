#!/usr/bin/perl -w
#
# XXX This is broken now.
#

use strict;

my ($round, $slot);
my $cancel;
my @faulty;
my $grep;

@ARGV && $ARGV[0] =~ /^\d+$/
	and $grep = shift;
$round = $slot = 0;

my $next;
$_ = <>;
$next = <>;
for (;;)
{
	defined $grep && $grep == $slot
		and print;

	if ($_ eq "DONE!\n")
	{
		defined $grep && $grep != $slot
			and print;
	} elsif ($_ eq "ROUND\n")
	{
		defined $grep && $grep != $slot
			and print;
		$round++;
		$slot = 0;
	} elsif ($_ eq "ALLOC\n")
	{
		die unless $next eq "NEGTEST\n";
	} elsif ($_ eq "REALLOC\n")
	{
		$slot++ unless $next eq "NEGTEST\n";
	} elsif ($_ eq "NEGTEST\n")
	{
		$next eq "FUCKUP\n" || $next =~ /^red zone integrity violated/
			or $slot++;
	} elsif ($_ eq "FUCKUP\n")
	{
		print "round: $round, slot: $slot\n"
			if !defined $grep;
		push(@faulty, $slot);
		$slot++;
	} elsif (/Assertion .* failed\.$/)
	{
		push(@faulty, $slot++);
	} else
	{
		$slot++;
	}

	($_ = $next) ne ''
		or last;
	defined ($next = <>)
		or $next = '';
}

print join("\n", "Faulty slots:", sort({ $a <=> $b } @faulty)), "\n"
	if !defined $grep && @faulty;

# 184
# 1164145456
