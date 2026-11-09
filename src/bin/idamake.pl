#!/usr/bin/perl

#       Makefile wrapper for Unix
#       Can be used with the following switches at the start:
#         -v    ignore IDAMAKE_SIMPLIFY, display full command lines
#         -a    append raw output to idasrc/current/idamake.log
#         -z    filter stdin to stdout (for debugging)
#         --make=path: specify path to make
#       Other options are passed to the underlying make.
#
#       The IDAMAKE_SIMPLIFY envvar turns on filtering of compiler command line
#       The IDAMAKE_PARALLEL envvar turns on parallel compilation
#

use strict;
use warnings;

use Getopt::Long qw(:config no_ignore_case pass_through);
my %opt;
my @ea32 = ('int', 'unsigned int', 'uint32', 'int32');
my @ea64 = ('long long int', 'long long unsigned int', 'unsigned long long', 'uint64', 'int64');

#--------------------------------------------------------------------------
# can the type be used for %a?
sub is_ea_type
{
  my $type = shift;
  my $is64 = shift;

  $type =~ s/ \{aka (.*)}//;
  return 1 if $type eq 'ea_t'
           || $type eq 'adiff_t'
           || $type eq 'asize_t'
           || $type eq 'nodeidx_t'
           || $type eq 'sel_t'
           || $type eq 'tid_t'
           || $type eq 'enum_t'
           || $type eq 'const_t'
           || $type eq 'bmask_t'
           || $type eq 'sval_t'
           || $type eq 'uval_t'
           || $type eq 'inode_t'
           || $type eq 'diridx_t';
  foreach ((!defined($is64) || $is64) ? @ea64 : @ea32)
  {
    return 1 if $type eq $_;
  }
  return 0;
}

#--------------------------------------------------------------------------
sub is_8bytes_if_x64
{
  my $type = shift;

  $type =~ s/ \{aka (.*)}//;
  return $type =~ /long( unsigned)? int/
      || $type =~ /^(__)?u?int64_t$/;
}

#--------------------------------------------------------------------------
sub simplify_command_line
{
  my $cmd = shift;

  return 0 if !$ENV{IDAMAKE_SIMPLIFY};

  if ( $cmd =~ /^ar /
    || $cmd =~ /^([\.\/]*third_party\/linaro\/(linux|win32)\/(arm\-linux\-gnueabi|aarch64\-linux\-gnu)\/bin\/(arm\-linux\-gnueabi|aarch64\-linux\-gnu)-ar(\.exe)?) /
    || $cmd =~ /^([\.\/]*third_party\/android-ndk\/(linux|win32)\/bin\/(armv7a|aarch64|x86_64|i686)-linux-android(eabi)?(\d+)?-ar(\.exe)?) / )
  {
    my $lib = (split ' ', $cmd)[2];
    print "lib $lib\n";
    return 1;
  }
  if ( $cmd =~ /^strip /
    || $cmd =~ /^([\.\/]*third_party\/linaro\/(linux|win32)\/(arm\-linux\-gnueabi|aarch64\-linux\-gnu)\/bin\/(arm\-linux\-gnueabi|aarch64\-linux\-gnu)-strip(\.exe)?) /
    || $cmd =~ /^([\.\/]*third_party\/android-ndk\/(linux|win32)\/bin\/(armv7a|aarch64|x86_64|i686)-linux-android(eabi)?(\d+)??-strip(\.exe)?) / )
  {
    my $strip = (split ' ', $cmd)[1];
    print "strip $strip\n";
    return 1;
  }
  if ( $cmd =~ /install_name_tool .* (\S+)$/ )
  {
    print "name $1\n";
    return 1;
  }

  my $out = 'compile';
  my $argv0 = $cmd;
  my $cmd2 = $cmd;
  $cmd2 =~ s/^ccache //;
  $argv0 = $1 if ( $cmd2 =~ /(.*?)\s/ );
  my $compiling = $argv0 =~ m#^/opt/osxcross/bin/(i386|x86_64)-apple-darwin17-[c\+]{2}#
               || $argv0 =~ m#^(\.\./)*third_party/linaro/(linux|win32)/(arm\-linux\-gnueabi|aarch64\-linux\-gnu)/bin/(arm\-linux\-gnueabi|aarch64\-linux\-gnu)-g?[c\+]{2}(\.exe)?#
               || $argv0 =~ m#^(\.\./)*third_party\/android-ndk\/(linux|win32)\/bin\/(armv7a|aarch64|x86_64|i686)-linux-android(eabi)?(\d+)??-g?[c\+]{2}(\.exe)?#
               || $argv0 =~ m#(/bin/)?g?[c\+]{2}#
               || $argv0 =~ m#/bin/clang#
               || $argv0 eq "c++";
  if ( $compiling )
  {
    $compiling = $cmd =~ / -c /; # really compiling
  }
  else
  {
    if ( $cmd =~ /\/bin\/qmake / )
    {
      my @words = split(/ +/, $cmd);
      print 'qmake ' . $words[-1];
      return 1;
    }
    if ( $cmd =~ m#objcopy --add-section '\.gdb_index# )
    {
      print "Adding .gdb-index section\n";
      return 1;
    }
    return 0 if $cmd !~ m#bin/(moc|uic|rcc) #;
    $out = $1;
    $compiling = 1;
  }
  if ( $compiling )                 # compilation
  {
    my @words = split(/ +/, $cmd2);
    my $skipnext;
    my $i = 0;
    foreach (@words)
    {
      next if $i++ == 0;
      if ( $skipnext )
      {
        $skipnext = 0;
        next;
      }
      if ( /^-o$/ || /^-arch/ || /^-isysroot/ )
      {
        $skipnext = 1;
        next;
      }
      next if /^-/ && $_ !~ /^-D__(EA32|X86)__/ && $_ !~ /^-O/;
      $out .= " $_";
    }
    $out .= "\n" if substr($out,-1,1) ne "\n";
    print $out;
  }
  else                                  # linking
  {
    return 0 unless $cmd2 =~ / -o *(\S+)/;
    print "link $1\n";
  }
  return 1;
}

#--------------------------------------------------------------------------
sub print_filtered_gcc_output
{
  my $FP = shift;
  my $is64 = shift;

  # make stdout unbuffered so we see commands immediately
  select *STDOUT;
  $| = 1;

  my $errfunc;
  my $incs;
  $is64 = 0 if not defined $is64 and $ENV{'__EA32__'};
  my $x86 = $ENV{'__X86__'};
  my $LLL;
  if ( $opt{Z} )
  {
    my $home = $ENV{'HOME'};
    $home = "" unless $home;
    my $f = "$home/idasrc/current/idamake.log";
    open $LLL, '>>', $f or die "$f: $!";
  }
  # OS X's ld interleaves its output, so try to reorder it; it typically
  # outputs lines "ld: warning: could not ..." in 3 printf's: "ld: warning: ",
  # the message and the newline.
  my $ldpending = 0;
  my @ldmsgs = ();

  my $undef_collected = 0;
  while ( <$FP> )
  {
    if ( $undef_collected == 1 )
    {
      undef $errfunc;
      undef $incs;
      $undef_collected = 0;
    }
    print $LLL $_ if ( $opt{Z} );
    chomp;
    s/\r$//;

    # Start workaround (ld's interleaved output)
    my $line = $_;
    if ( $line =~ /^ld: warning: (.*)/ )
    {
      ++$ldpending;
      $line = $1;
    }
    if ( $ldpending > 0 )
    {
      my $msg;
      while ( $line ne "" )
      {
        while ( $line =~ /^(.*?)(ld: warning: )(.*)/ )
        {
          ++$ldpending;
          my $remainder = $3;
          # Check if multiple messages are concatenated (have to know them)
          $msg = $1;
          while ( $msg =~ /^(.+?)(could not .*)$/)
          {
            push @ldmsgs, $1;
            $msg = $2;
          }
          push @ldmsgs, $msg if $msg ne "";
          $line = $remainder;
        }
        $msg = $line;
        while ( $msg =~ /^(.+?)(could not .*)$/)
        {
          push @ldmsgs, $1;
          $msg = $2;
        }
        push @ldmsgs, $msg if $msg ne "";
        $line = "";
      }
      # A newline means an ld message has been issued; be tolerant if, for
      # some reason, we failed to identify all of them.
      $_ = "ld: warning: " . (@ldmsgs?shift @ldmsgs:"");
      --$ldpending;
    }
    # End workaround

    $is64 = 0 if not defined $is64 and /-D__EA32__/;
    $x86  = 1 if not defined $x86  and /-D__X86__/;

    # remove color codes if we're being redirected
    s/\e\[\d+(;\d+)*m//g if not -t STDOUT;

    # clean file/function info when we start a new command
    if ( /^(\e\[\d+(;\d+)*m)*(compile|compiling|link|linking|asm|lib|qmake)(\e\[\d+(;\d+)*m)* /
      || /^(\e\[\d+(;\d+)*m)*(deploy|gendoxycfg|genhooks|genidaapi|genswigheader|gen_idc_bc695|inject_plfm|inject_pydoc|inject_base_hooks_flags|patch_codegen|patch_h_codegen|patch_python_codegen|swig|update_sdk|check_injections|gen_examples_index|split_hexrays_templates)(\e\[\d+(;\d+)*m)* /
      || /^(\e\[\d+(;\d+)*m)*(chkapi)(\e\[\d+(;\d+)*m)*/
      || /^(g(\+\+|cc)(-\d+)?|cp|[\.\/]*third_party\/lsb\/lsb-build-[0-9\.\-]*\/bin\/lsb(c\+\+|cc)|rm|qcp\.sh|g?make\d*\[\d\]:|ar|moc|uic|rcc|name|strip|mkdeb|perl|ccache|#) /
      || /^([\.\/]*third_party\/linaro\/(linux|win32)\/(arm\-linux\-gnueabi|aarch64\-linux\-gnu)\/bin\/(arm\-linux\-gnueabi|aarch64\-linux\-gnu)-(ar|g(\+\+|cc))(\.exe)?) /
      || /^([\.\/]*third_party\/android-ndk\/(linux|win32)\/bin\/(armv7a|aarch64|x86_64|i686)-linux-android(eabi)?(\d+)??-(ar|g(\+\+|cc))(\.exe)?) /
      || m#/bin/clang #
      || /^(Parsing|Generating|Done|IDA API|Symbol Table Maker) /
      || /bin\/(qar\.sh|moc|uic|rcc|g\+\+) /
      || m#^../../third_party/afl/afl-g#
      || m#^/usr/bin/python[0-9\.]* #
      || /^Thank you for using IDA\. Have a nice day!/
      || /g?make\d* -f makefile\.unx deploy$/
      || /\/(g?make\d*|nasm|stm|ihc|install_name_tool|makerev|rasm|prepfpc|lmxdev|qmake|mkapi\.sh|bin2h)(x?64)? /
      || /^nasm / )
    {
      undef $incs;
      undef $errfunc;
    }

    next if simplify_command_line($_);

    # cache file/function information until we really decide to print a bug
    if ( /^In file included/ )
    {
      $incs .= "$_\n";
      next;
    }
    if ( /^ +from/ )
    {
      $incs .= "$_\n";
      next;
    }
    if ( /In( static)?( member)? (function|constructor|destructor)/ )
    {
      $errfunc .= "$_\n";
      next;
    }
    if ( /(In instantiation of)|(At global scope)|(In lambda function:)/ )
    {
      $errfunc .= "\n$_\n";
      next;
    }
    if ( /instantiated from/ )
    {
      $errfunc .= "$_\n";
      next;
    }
    if ( /required from / )
    {
      $errfunc .= "$_\n";
      next;
    }


    s/(\xE2\x80\x98)|(\xE2\x80\x99)|\x91|\x92|`/'/g;   # convert (utf-8) tick/backtick to apostrophe

    # suppress uninteresting warnings
    $undef_collected = 1;
    if ( /format ('\%.*a' )?(expects|specifies) (argument of )?type 'double'(,)? but (the )?argument (\d+ )?has type '(.*?)'/ )
    {
      next if is_ea_type($7, $is64);
    }
    if ( /format ('\%.*a' )?(expects|specifies) (argument of )?type 'float( )?\*'(,)? but (the )?argument (\d+ )?has type '([^ |*]*)( )?\*/ )
    {
      next if is_ea_type($8, $is64);
    }

    if ( /format '%.*ll[duxX]' expects (argument of )?type 'long long( unsigned)? int', but argument \d+ has type '(.*?)'/ )
    {
      next if not $x86 && is_8bytes_if_x64($3);
    }

    next if /is already a friend of/ && $ENV{__MAC__};
    next if /qglobal.h.*This version of Mac OS X is unsupported/;
    next if /format ('\%.*l[duxX]' )?(expects|specifies) (argument of )?type '(long|unsigned|long unsigned) int'(,)? but (the )?argument (\d+ )?has type 's?size_t('| )/;
    next if /format ('\%.*l[duxX]' )?(expects|specifies) (argument of )?type '(long|unsigned|long unsigned) int( )?\*'(,)? but (the )?argument (\d+ )?has type 's?size_t( )?\*/;
    next if /(double|float) format, different type arg/;
    next if /zero-length (gnu_)?printf format string/;
    next if /suggest parentheses around '&&' within '\|\|'/;
    next if /forced in submake: disabling jobserver mode/;
    next if /enumeral and non-enumeral type in conditional expression/;
    next if /warning: -ffunction-sections may affect debugging on some targets/;
    next if /has virtual functions but non-virtual destructor/;
    next if /warning: converting negative value '-0x00000000000000001' to 'uint64'/;
    next if /warning: passing negative value '-0x00000000000000001' for argument 1 to 'bool .*::is_equal_to/;
    next if /warning: ignoring #pragma GCC diagnostic/;
    next if /warning: deleting object of polymorphic class type '(ida)place_t' which has non-virtual destructor/;
    next if /<command-line>:0:0: warning: "_FORTIFY_SOURCE" redefined \[enabled by default\]/;
    next if /note: this is the location of the previous definition/;
    next if /note: expanded from macro/;
    next if /[0-9]+ warning(s)? generated/;
    next if /treating 'c' input as 'c\+\+' when in C\+\+ mode/;
    # mac bug: https://discussions.apple.com/thread/4143805?tstart=0
    next if /DYLD_ environment variables being ignored because main executable.*is setuid or setgid/;
    next if /implicit conversion from 'unsigned long long' to 'ea_t'/;
    next if /warning: format specifies type 'unsigned short' but the argument has type 'int'/;
    next if /warning: -z  defs ignored/;
    next if /: note:/ and not /CASSERT/;
    next if /\/usr\/bin\/ld: skipping incompatible .*\/libgcc.a when searching for -lgcc/;
    next if /clang: warning: libstdc\+\+ is deprecated; move to libc\+\+ with a minimum deployment target of OS X 10\.9/;
    next if /ld: warning: could not create compact unwind for .* stack subl instruction is too different from dwarf stack size/;
    next if /warning: 'template<class> class std::auto_ptr' is deprecated/;
    next if /std::map doesn't provide at\(\)/;
    $undef_collected = 0;

    next if /^$/;

    # ok, it seems to be a real bug/warning
    print "REASON: [$_]\n" if $opt{z} and not /(\*\*\* build)|(Entering)|(Leaving)|(Nothing to be done)/;
    if ( $incs )
    {
      print $incs;
      undef $incs;
    }
    if ( $errfunc )
    {
      print $errfunc;
      undef $errfunc;
    }
    print "$_\n";
  }
  close $LLL if ( $opt{Z} );
  return 1;
}

#--------------------------------------------------------------------------
sub main
{
  my $make = exists($opt{make}) ? $opt{make} : "make";
  my $is64;
  for (@ARGV)
  {
    if ( $_ eq "__EA32__=1" )
    {
      $is64 = 0;
      last;
    }
  }
  open my $FP, "$make @ARGV 2>&1|" or die "Failed to launch make: $!";
  print_filtered_gcc_output($FP, $is64);
  close $FP;
  exit($? != 0);
}

#--------------------------------------------------------------------------
GetOptions(\%opt, "v+", "a+", "z+", "make=s") or die;
if ( $opt{z} )
{
  exit(not print_filtered_gcc_output(*STDIN));
}
else
{
  undef $ENV{IDAMAKE_SIMPLIFY} if exists($opt{v});
  main();
}
