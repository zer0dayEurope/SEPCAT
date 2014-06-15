#!/usr/bin/perl

# [SEPCAT] Static Exploitable PHP Code Analysis Tool
# Version: 0.4
#
# https://github.com/vavkamil/SEPCAT

# Functionality based on DevBug (http://devbug.co.uk)
# DevBug is a basic PHP Static Code Analysis tool written mostly in JavaScript.
#
# DevBug was created by Ryan Dewhurst (www.dewhurstsecurity.com)
# as part of his undergraduate university thesis.

use strict;
use warnings;
use Getopt::Long;
use File::Basename;
use File::Find::Rule;

# Command line options
my $help;
my $version;
my $version_num = 'Version 0.4 Alpha';
my $opt_folder;
my $opt_result;
my $opt_file;

my $options = GetOptions(
    "help"    => \$help,
    "version" => \$version,
    "folder"  => \$opt_folder,
    "file"    => \$opt_file,
    "result"  => \$opt_result    # TODO
);

my ( $target, $result ) = @ARGV;

my $InsideCode     = 0;
my $i              = 0;
my $tokenSeperator = "<:::>";    # the token name/value seperator

# Arrays bellow declares all the possible sources, sinks and securing functions.
# All of this data originated from RIPS v0.51 http://sourceforge.net/projects/rips-scanner/
#
# Sources of tainted variables
my @tainted_variables = ( '$_GET', '$_POST', '$_COOKIE', '$_REQUEST', '$_FILES', '$_SERVER', '$_ENV', '$HTTP_GET_VARS', '$HTTP_POST_VARS',
	'$HTTP_COOKIE_VARS', '$HTTP_REQUEST_VARS', '$HTTP_POST_FILES', '$HTTP_SERVER_VARS', '$HTTP_ENV_VARS', 'HTTP_RAW_POST_DATA', 'argc', 'argv' );
my $tainted_variables = "\\" . join "|\\", @tainted_variables;

# Potential Vulnerable Functions
my @XSS = ( "echo", "print", "exit", "die", "printf", "vprintf" );
my $XSS = '(?<!\\w)(' . join( "|", @XSS ) . ')(?!\\w)';

my @fileInclude = ( "include", "include_once", "php_check_syntax", "require", "require_once", "runkit_import", "set_cinlude_path", "virtual" );
my $fileInclude = join "|", @fileInclude;

# Secured Functions
my @securingXSS = ( "esc_attr", "esc_url", "htmlentities", "htmlspecialchars" );
my $securingXSS = '(?:' . ( join "|", @securingXSS ) . ')';

help() if $help;
quit($version_num) if $version;

BEGIN {
    print "\n[SEPCAT] Static Exploitable PHP Code Analysis Tool\n";
}

start_scan();

END {
    print "\n";
}

sub start_scan {
    if ( not defined( $opt_folder or $opt_file ) ) {

        # Usage: perl $0 -folder /var/www/wp_plugins/ -result wp_plugins.txt
        die "Usage: perl $0 -folder /var/www/wp_plugins/\n\n";
    }

    if ( defined( $opt_folder and $target ) ) {
        my @files     = scan_folder($target);                # Scan folder for .php files
        my @tokens    = php_tokenizer(@files);               # Get PHP tokens from source code
        my @tainted   = codeAnalysis(@tokens);               # Check variables for user input sources
        my @unsecured = unsecured( \@tainted, \@tokens );    # Is variable unsecured?
        vulnerable( \@unsecured, \@tokens );                 # See if our tainted vars end up in sensitive sinks
    }
    elsif ( defined( $opt_file and $target ) ) {
        my @files     = scan_file($target);                  # Scan single .php file
        my @tokens    = php_tokenizer(@files);               # Get PHP tokens from source code
        my @tainted   = codeAnalysis(@tokens);               # Check variables for user input sources
        my @unsecured = unsecured( \@tainted, \@tokens );    # Is variable unsecured?
        vulnerable( \@unsecured, \@tokens );                 # See if our tainted vars end up in sensitive sinks
    }
}

sub scan_folder {
    my ($target) = @_;
    quit( "Target " . $target . " is not a folder." ) if ( not -d $target );
    print "[+] Scanning folder: " . $target . "\n\n";

    # my @files = File::Find::Rule->file()->name('*.php')->grep(qr/($tainted_variables)/)->in($target);
    my @files = File::Find::Rule->file()->name('*.php')->in($target);
    return @files;
}

sub scan_file {
    my ($target) = @_;
    quit( "Target " . $target . " is not a file." ) if ( not -f $target );
    print "[+] Scanning file: " . $target . "\n";
    ( $target, my $filepath ) = fileparse($target);
    if ( $filepath eq "./" ) { $filepath = "." }
    my @files = File::Find::Rule->file()->name($target)->in($filepath);
    return @files;
}

sub php_tokenizer {
    my (@files) = @_;
    my @tokens;
    my ( $file, $filepath );
    foreach (@files) {
        ( $file, $filepath ) = fileparse($_);
        if ( $filepath eq "./" ) { $filepath = "." }
        open( my $fh, "<", $_ ) or die "Failed to open file: $!\n";

        while (<$fh>) {

            #s/(\?>)/$1\x0a/g;
            #s/(<\?php)/\x0a$1/g;

            my @Data = split( "\n", $_ );

            #  OK, go through the remaining line fragments.
            $i++;
            foreach (@Data) {
                $_ =~ s/^\s*//;    # Remove any white space characters
                next if (/^\s*$/);       # Skip blank lines
                next if (/^\/\/.*$/);    #Skip // comments

                #  If we're inside an opening block, watch for the
                #  closing block.

                if ( $InsideCode == 1 ) {
                    if (/^(.*)\?>/) {

                        #print "T_CLOSE_TAG<:::>?><:::>" . $i . "\n";
                        push( @tokens, "T_CLOSE_TAG<:::>$_<:::>$i\n" );
                        $InsideCode = 0;
                    }
                    else {

                        my $regex_T_VARIABLE                 = '\$\w+';
                        my $regex_T_NOTOKEN                  = '=|;|\[|\]|\(|\)';
                        my $regex_T_CONSTANT_ENCAPSED_STRING = '\'[^\']*\'';
                        my $regex_T_ECHO                     = 'echo';
                        my $regex_T_INCLUDE                  = 'include';
                        my $regex_all_tokens                 = $regex_T_VARIABLE . "|" . $regex_T_NOTOKEN . "|" . $regex_T_CONSTANT_ENCAPSED_STRING . "|" . $regex_T_ECHO . "|" . $regex_T_INCLUDE;
                        my @raw_php                          = split( "\n", $_ );
                        my @matches;

                        foreach my $raw_line (@raw_php) {

                            my @matches;
                            my $token;
                            if ( @matches = $raw_line =~ /($regex_all_tokens|$securingXSS)/g ) {
                                foreach my $match (@matches) {
                                    if ( ($token) = $match =~ /(\$\w+)/g ) {

                                        #print "T_VARIABLE<:::>" . $token . "<:::>".$i."\n";
                                        push( @tokens, "T_VARIABLE<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /(=|;|\[|\]|\(|\))/g ) {

                                        #print "T_NOTOKEN<:::>" . $token . "<:::>".$i."\n";
                                        push( @tokens, "T_NOTOKEN<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /(echo)/g ) {

                                        #print "T_ECHO<:::>" . $token . "<:::>".$i."\n";
                                        push( @tokens, "T_ECHO<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /(include)/g ) {

                                        #print "T_INCLUDE<:::>" . $token . "<:::>".$i."\n";
                                        push( @tokens, "T_INCLUDE<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /('[^']*')/g ) {

                                        #print "T_CONSTANT_ENCAPSED_STRING<:::>" . $token . "<:::>".$i."\n";
                                        push( @tokens, "T_CONSTANT_ENCAPSED_STRING<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /$securingXSS/g ) {

                                        #print "T_STRING<:::>" . $token . "<:::>".$i."\n";
                                        push( @tokens, "T_STRING<:::>$token<:::>$i" );
                                    }
                                }
                            }
                        }
                    }
                }
                else {

                    #  Otherwise watch for the opening block.

                    if (/<\?php(.*)\?>/) {

                        # print "$1";
                    }
                    elsif (/<\?php(.*)$/) {

                        #print "T_OPEN_TAG<:::><?php<:::>" . $i . "\n";
                        push( @tokens, "T_OPEN_TAG<:::>$_<:::>$i" );
                        $InsideCode = 1;
                    }
                    else {
                        #print "T_INLINE_HTML<:::>" . $_ . "<:::>" . $i . "\n";
                        push( @tokens, "T_INLINE_HTML<:::>$_<:::>$i" );
                    }
                }
            }
        }
        close $fh;
    }
    return @tokens;
}

sub codeAnalysis {
    my ( @tokens, $files ) = @_;
    my @tainted;    # the array that will keep track of tainted variables
    foreach my $tokenCount ( 0 .. $#tokens - 1 ) {
        my @splitToken = split( $tokenSeperator, $tokens[$tokenCount] );
        my $TokenName  = $splitToken[0];
        my $TokenValue = $splitToken[1];
        my $TokenLine  = $splitToken[2];

        my @splitNextToken = split( $tokenSeperator, $tokens[ $tokenCount + 1 ] );
        my $nextTokenName  = $splitNextToken[0];
        my $nextTokenValue = $splitNextToken[1];
        my $nextTokenLine  = $splitNextToken[2];

        # Sources: User Input.

        if ( ( $TokenName eq "T_VARIABLE" ) and ( $nextTokenName eq "T_NOTOKEN" ) and ( $nextTokenValue eq "=" ) ) {    # if variable assignment

            my @splitVarToken = split( $tokenSeperator, $tokens[ $tokenCount + 2 ] );
            my $varTokenName  = $splitVarToken[0];
            my $varTokenValue = $splitVarToken[1];
            if ( ( $varTokenName eq "T_VARIABLE" ) and ( $varTokenValue =~ /$tainted_variables/ ) ) {

                # print $TokenValue." - ".$varTokenValue."\n";
                push( @tainted, $TokenValue );

            }
        }
    }
    return @tainted;
}

sub unsecured {
    my ( $tainted, $tokens ) = @_;
    my @secured;
    my @unsecured;
    my $secured;
    foreach my $tainted_var (@$tainted) {

        #print $tainted_var;
        foreach my $token ( 0 .. $#$tokens - 1 ) {
            my @splitToken = split( $tokenSeperator, @$tokens[$token] );
            my $TokenName  = $splitToken[0];
            my $TokenValue = $splitToken[1];
            my $TokenLine  = $splitToken[2];

            #print $TokenName." - ".$TokenValue."\n";

            my @splitNextToken = split( $tokenSeperator, @$tokens[ $token + 1 ] );
            my $nextTokenName  = $splitNextToken[0];
            my $nextTokenValue = $splitNextToken[1];
            my $nextTokenLine  = $splitNextToken[2];

            if ( ( $TokenValue eq $tainted_var ) and ( $nextTokenValue eq "=" ) ) {
                my @splitVarToken = split( $tokenSeperator, @$tokens[ $token + 2 ] );
                my $varTokenName  = $splitVarToken[0];
                my $varTokenValue = $splitVarToken[1];
                my $varTokenLine  = $splitVarToken[1];
                if ( $varTokenValue =~ /$securingXSS/ ) {

                    #print $TokenValue." - ".$varTokenValue." is secured.\n";
                    push( @secured, $TokenValue );
                }
            }
        }
    }
    if ( @secured == 0 ) {
        $secured = "(test)";
    }
    else {
        $secured = "(\\" . ( join "|\\", @secured ) . ")";
    }
    foreach my $tainted_var (@$tainted) {
        if ( $tainted_var !~ /$secured/ ) {
            push( @unsecured, $tainted_var );
        }
    }
    return @unsecured;
}

sub vulnerable {
    my ( $unsecured, $tokens ) = @_;
    my $XSS_sink;
    my $XSS_line = "0";
    my $fileInclude_sink;
    my $fileInclude_line = "0";
    foreach my $variable (@$unsecured) {

        # print $variable."\n";
        foreach my $token ( 0 .. $#$tokens - 1 ) {
            my @splitToken = split( $tokenSeperator, @$tokens[$token] );
            my $TokenName  = $splitToken[0];
            my $TokenValue = $splitToken[1];
            my $TokenLine  = $splitToken[2];

            # print $TokenName." - ".$TokenValue."\n";
            if ( $TokenValue =~ /$XSS/ ) {
                $XSS_sink = $TokenValue;
                $XSS_line = $TokenLine;
            }
            if ( ( $TokenValue eq $variable ) and ( $TokenLine eq $XSS_line ) ) {
                print "Line " . $TokenLine . ": Cross-Site Scripting (XSS) in '" . $XSS_sink . "' via '" . $TokenValue . "'\n";
            }
            if ( $TokenValue =~ /$fileInclude/ ) {
                $fileInclude_sink = $TokenValue;
                $fileInclude_line = $TokenLine;
            }
            if ( ( $TokenValue eq $variable ) and ( $TokenLine eq $fileInclude_line ) ) {
                print "Line " . $TokenLine . ": PHP File Inclusion in '" . $fileInclude_sink . "' via '" . $TokenValue . "'\n";
            }
        }
    }
}

sub quit {
    my ($text) = @_;
    print "$text\n\n";
    exit;
}

sub help {
    print <<EOHELP;

sepcat.pl at https://github.com/vavkamil/SEPCAT
Usage: perl sepcat.pl -folder /var/www/wp_plugins/

Overview:
    SEPCAT is a simple PHP Static Code Analysis (SCA) tool written in Perl.
    It could be used to quickly test a PHP project that you think
    may have some potential vulnerabilities.

Options:
    -file       Scan a single PHP file.
    -folder     Recursive deep scan for a specific directory.
    -result     Save result to a given output file.
    -version    Print current version.
    -help       This help message.

EOHELP
    exit;
}