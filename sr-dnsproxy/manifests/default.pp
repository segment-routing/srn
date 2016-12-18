
# PATH
Exec { path => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' }

# Execute 'apt-get update'
exec { 'apt-update':
  command => '/usr/bin/apt-get update',
}

# Install python requirements
package { 'python-setuptools':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'python-pip':
  require => [ Exec['apt-update'], Package['python-setuptools'] ],
  ensure => installed,
}

# Install mininet package
package { 'mininet':
  require => [ Exec['apt-update'], Package['bridge-utils'] ],
  ensure => installed,
}

exec { 'quagga-download':
  require => Exec['apt-update'],
  creates => '/quagga-1.0.20160315',
  command => 'wget -O - http://download.savannah.gnu.org/releases/quagga/quagga-1.0.20160315.tar.gz > /quagga-1.0.20160315.tar.gz;\
              tar -xvzf /quagga-1.0.20160315.tar.gz -C /;'
}

# Install version 1.0.2 of quagga
exec { 'quagga':
  require => [ Exec['apt-update'], Package['gawk'], Package['libreadline6-dev'], Exec['quagga-download'] ],
  cwd => '/quagga-1.0.20160315',
  creates => '/quagga',
  command => './configure --prefix=/quagga;\
              adduser quagga;\
              chown quagga:quagga /quagga; chmod 775 /quagga;\
              make;\
              make install;\
              rm /quagga-1.0.20160315.tar.gz;\
              echo "# Quagga binaries" >> /etc/profile;\
              echo "PATH=\"/quagga/sbin:\$PATH\"" >> /etc/profile;\
              echo "alias sudo=\'sudo env \"PATH=\$PATH\"\'" >> /etc/profile;\
              echo "# Quagga binaries" >> /root/.bashrc;\
              echo "PATH=\"/quagga/sbin:\$PATH\"" >> /root/.profile;\
              PATH=/quagga/sbin:$PATH;',
}

# Some other needed python packages
package { 'py2-ipaddress':
  require => Package['python-pip'],
  ensure => installed,
  provider => 'pip',
}
package { 'mako':
  require => Package['python-pip'],
  ensure => installed,
  provider => 'pip',
}

# Download and install ipmininet
exec { 'download-ipmininet':
  require => Package['git'],
  command => 'git clone https://github.com/jadinm/ipmininet.git /home/vagrant/ipmininet',
  creates => '/home/vagrant/ipmininet',
}
exec { 'ipmininet':
  require => [ Exec['apt-update'], Exec['download-ipmininet'], Package['python-setuptools'], Package['python-pip'], Package['mininet'], Package['mako'], Exec['quagga'] ],
  command => 'pip install -e /home/vagrant/ipmininet',
}

# c-ares lib
exec { 'c-ares-build-config':
  require => [ Exec['apt-update'], Package['libtool'] ],
  cwd => '/home/vagrant/lib/c-ares',
  path => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/vagrant/lib/c-ares',
  command => 'buildconf',
  creates => '/home/vagrant/lib/c-ares/configure',
}
exec { 'c-ares-config':
  require => [ Exec['c-ares-build-config'] ],
  cwd => '/home/vagrant/lib/c-ares',
  path => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/vagrant/lib/c-ares',
  command => 'configure --enable-warnings --enable-werror --prefix=/home/vagrant/cares;\
              make;\
              make install;',
  creates => '/home/vagrant/c-ares',
}

# Miscellaneous
package { 'wireshark':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'traceroute':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'tcpdump':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'bridge-utils':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'xterm':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'man':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'libreadline6':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'libreadline6-dev':
  require => [ Exec['apt-update'], Package['libreadline6'] ],
  ensure => installed,
}
package { 'gawk':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'git':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'm4':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'automake':
  require => Exec['apt-update'],
  ensure => installed,
}
package { 'libtool':
  require => [ Exec['apt-update'], Package['m4'], Package['automake'] ],
  ensure => installed,
}
package { 'valgrind':
  require => Exec['apt-update'],
  ensure => installed,
}

# Locale settings
exec { 'locales':
  require => Exec['apt-update'],
  command => "locale-gen fr_BE.UTF-8; update-locale",
}
