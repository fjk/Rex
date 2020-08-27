#
# (c) Jan Gehring <jan.gehring@gmail.com>
#
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Rex::Interface::Connection;

use strict;
use warnings;

# VERSION

sub create {
  my ( $class, $type ) = @_;

  unless ($type) {
    $type = Rex::Config->get_connection_type();
  }

  my $class_name = "Rex::Interface::Connection::$type";
  eval "use $class_name;";
  if ($@) { die("Error loading connection interface $type.\n$@"); }

  $DB::single=1;
  #Net::SSH2;
  #use Net::SFTP::Foreign;
  #my $sftp = Net::SFTP::Foreign->new(ssh2 => $self->{ssh}, backend =>'Net_SSH2');
  #$sftp->error and die "Unable to stablish SFTP connection: ". $sftp->error;

  #if ( !defined $sftp ) {
  #        Rex::Logger::info(
  #            "FK: connection SSH but no SFTP Object",
  #            "warn"
  #            );
  #} else {
  #    Rex::Logger::info(
  #        "FK: SFTP Object DONE!",
  #        "warn"
  #        );
  #}

  #  $self->{sftp} = $sftp;
  #  $self->{sftp} = $self->{ssh}->sftp;
  print "1 Interface::Connection\n";
  print "1    Type: $type\n";

  return $class_name->new;
}

1;
