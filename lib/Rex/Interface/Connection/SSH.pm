#
# (c) Jan Gehring <jan.gehring@gmail.com>
#
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Rex::Interface::Connection::SSH;

use strict;
use warnings;

# VERSION

BEGIN {
  use Rex::Require;
  Net::SSH2->require;
}

use Carp;
use Rex::Helper::IP;
use Rex::Interface::Connection::Base;
use Data::Dumper;
use base qw(Rex::Interface::Connection::Base);

sub new {
  my $that  = shift;
  my $proto = ref($that) || $that;
  my $self  = $that->SUPER::new(@_);

  bless( $self, $proto );

print "3 Rex::Interface::Connection::SSH\n";
print "3    new: $that Proto: $proto\n";

  return $self;
}

sub connect {
  my ( $self, %option ) = @_;#
  
  my ( $package, $filename, $line ) = caller;
  print "Caller: package: '" . $package . "' File: '" . $filename . "' Line: '" . $line . "'\n";

  my (
    $user, $pass,    $private_key, $public_key, $server,
    $port, $timeout, $auth_type,   $is_sudo
  );

 #  foreach (keys %option) {
 #      print "SSH: option: key: '$_'->'\n";
 #      print "SSH: option: val: $option{$_}\n";
 #  }

  $user        = $option{user};
  $pass        = $option{password};
  $server      = $option{server};
  $port        = $option{port};
  $timeout     = $option{timeout};
  $public_key  = $option{public_key};
  $private_key = $option{private_key};
  $auth_type   = $option{auth_type};
  $is_sudo     = $option{sudo};

 #   my $sftpclass    = $option{sftpclass};
 #Rex::Logger::info( "SFTP Check: " . $sftpclass);
    
  $self->{server}        = $server;
  $self->{is_sudo}       = $is_sudo;
  
  $self->{__auth_info__} = \%option;

  #my $typ = "Net::SSH2";
  #Rex::Logger::debug("Using $typ for connection");
  Rex::Logger::debug( "Using user: " . $user );
  Rex::Logger::debug( Rex::Logger::masq( "Using password: %s", $pass ) )
    if defined $pass;

  #Rex::Logger::info( "$typ :Using server: " . $server );
  #Rex::Logger::info( "$typ :Using port: " . $port);
  #Rex::Logger::info( "$typ :Using timeout: " . $timeout);
  #Rex::Logger::info( "$typ :Using public key: " . $public_key);
  #Rex::Logger::info( "$typ :Using private key: " . $private_key);
  #Rex::Logger::info( "$typ :Using auth type: " . $auth_type);
  #Rex::Logger::info( "$typ :Using is sudo: " . $is_sudo);

  $self->{ssh} = Net::SSH2->new;

  my $fail_connect = 0;

CON_SSH:
  $port    ||= Rex::Config->get_port( server => $server )    || 22;
  #Rex::Logger::info( "$typ :Using port: " . $port);
  
  $timeout ||= Rex::Config->get_timeout( server => $server ) || 3;
  #Rex::Logger::info( "$typ :Using server: " . $server );
  
  $self->{ssh}->timeout( $timeout * 1000 );

  $server =
  Rex::Config->get_ssh_config_hostname( server => $server ) || $server;
  #Rex::Logger::info( "$typ :Using server: " . $server );

  ( $server, $port ) = Rex::Helper::IP::get_server_and_port( $server, $port );
  #Rex::Logger::info( "$typ :Using ip/port: " . $server . ':' . $port );

  Rex::Logger::debug( "Connecting to $server:$port (" . $user . ")" );
  unless ( $self->{ssh}->connect( $server, $port ) ) {
    ++$fail_connect;
    sleep 1;
    goto CON_SSH
      if (
      $fail_connect < Rex::Config->get_max_connect_fails( server => $server ) )
      ; # try connecting 3 times

    Rex::Logger::info( "Can't connect to $server", "warn" );

    $self->{connected} = 0;

    return;
  }

  Rex::Logger::debug( "Current Error-Code: " . $self->{ssh}->error() );
  Rex::Logger::debug( "Connected to $server, trying to authenticate.");

  $self->{connected} = 1;

  if ( $auth_type && $auth_type eq "pass" ) {
    Rex::Logger::debug("Using password authentication.");
    $self->{auth_ret} = $self->{ssh}->auth_password( $user, $pass );
    if ( !$self->{auth_ret} ) {

      # try guessing
      $self->{auth_ret} = $self->{ssh}->auth(
        'username' => $user,
        'password' => $pass
      );

    }
  }
  elsif ( $auth_type && $auth_type eq "key" ) {
    Rex::Logger::debug("Using key authentication.");

    croak "No public_key file defined."  if !$public_key;
    croak "No private_key file defined." if !$private_key;

    $self->{auth_ret} =
      $self->{ssh}->auth_publickey( $user, $public_key, $private_key, $pass );
  }
  else {
    Rex::Logger::debug("Trying to guess the authentication method.");
    $self->{auth_ret} = $self->{ssh}->auth(
      'username'   => $user,
      'password'   => $pass,
      'publickey'  => $public_key  || "",
      'privatekey' => $private_key || ""
    );
  }

  #if ( defined($sftpclass) and str($sftpclass) ) {
  #  Rex::Logger::info( "$typ : SFTP Check: " . $sftpclass);
  #}
  
  my $class_name = "Net::SFTP::Foreign";
  eval "use $class_name;";
  if ($@) { die("Error loading connection interface $class_name .\n$@"); }
  $self->{sftp} = Net::SFTP::Foreign->new(ssh2 => $self->{ssh}, backend =>'Net_SSH2');
  $self->{sftp}->error and die "Unable to stablish SFTP Foreign connection: ". $self->{sftp}->error;

  print "    3 Class Connection ref self ssh? ", ref $self->{ssh}, "\n";
  print "    3 Class Connection ref self sftp? ", ref $self->{sftp}, "\n";

#  $self->{sftp} = $self->{ssh}->sftp;
}

sub reconnect {
  my ($self) = @_;
  Rex::Logger::debug("Reconnecting SSH");

  $self->connect( %{ $self->{__auth_info__} } );
}

sub disconnect {
  my ($self) = @_;
  $self->get_connection_object->disconnect;
}

sub error {
  my ($self) = @_;
  return $self->get_connection_object->error;
}

sub get_connection_object {
  my ($self) = @_;
  return $self->{ssh};
}

sub get_fs_connection_object {
  my ($self) = @_;
  if ( !defined $self->{sftp} ) {
    Rex::Logger::info(
      "It seems that you haven't installed or configured sftp on your server.",
      "warn"
    );
    Rex::Logger::info(
      "Rex needs sftp for file operations, so please install one.", "warn" );
    die("No SFTP server found on remote host.");
  }

  print "    4 get_fs_connection_object ref sftp? ", ref $self->{sftp}, "\n";
  return $self->{sftp};
}

sub is_connected {
  my ($self) = @_;
  return $self->{connected};
}

sub is_authenticated {
  my ($self) = @_;
  return $self->{auth_ret};
}

sub get_connection_type {
  my ($self) = @_;

  my $type = "SSH";

  if ( $self->{is_sudo} && $self->{is_sudo} == 1 ) {
    return "Sudo";
  }

  if ( Rex::is_ssh() && !Rex::is_sudo() ) {
    $type = "SSH";
  }
  elsif ( Rex::is_sudo() ) {
    $type = "Sudo";
  }

  return $type;
}

1;
