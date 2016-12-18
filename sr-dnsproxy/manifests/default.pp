$kernel_package = "/vagrant/linux-????.deb"

$cares_source_path = "/home/vagrant/lib/c-ares"
$cares_path = "/home/vagrant/cares"

$quagga_version = "1.0.20160315"
$quagga_release_url = "http://download.savannah.gnu.org/releases/quagga/quagga-${quagga_version}.tar.gz"
$quagga_source_path = "/quagga-${quagga_version}"
$quagga_download_path = "${quagga_source_path}.tar.gz"
$quagga_path = "/quagga"

$ipmininet_git_repo = "https://github.com/jadinm/ipmininet.git"
$ipmininet_path = "/home/vagrant/ipmininet"

# PATH
$path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Exec { path => $path }

# Execute 'apt-get update'
exec { 'apt-update':
  command => 'apt-get update',
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

# Install specific version of quagga
exec { 'quagga-download':
  require => Exec['apt-update'],
  creates => $quagga_source_path,
  command => "wget -O - ${quagga_release_url} > ${quagga_download_path};\
              tar -xvzf ${quagga_download_path};"
}
exec { 'quagga':
  require => [ Exec['apt-update'], Package['gawk'], Package['libreadline6-dev'], Exec['quagga-download'] ],
  cwd => $quagga_source_path,
  creates => $quagga_path,
  path => "${path}:${quagga_source_path}",
  command => "configure --prefix=${quagga_path};\
              adduser quagga;\
              chown quagga:quagga ${quagga_path}; chmod 775 ${quagga_path};\
              make;\
              make install;\
              rm ${quagga_download_path};\
              echo \"# Quagga binaries\" >> /etc/profile;\
              echo \"PATH=\"${quagga_path}/sbin:\$PATH\"\" >> /etc/profile;\
              echo \"alias sudo=\'sudo env \"PATH=\$PATH\"\'\" >> /etc/profile;\
              echo \"# Quagga binaries\" >> /root/.bashrc;\
              echo \"PATH=\"${quagga_path}/sbin:\$PATH\"\" >> /root/.profile;\
              PATH=${quagga_path}/sbin:$PATH;",
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
  command => "git clone ${ipmininet_git_repo} ${ipmininet_path}",
  creates => $ipmininet_path,
}
exec { 'ipmininet':
  require => [ Exec['apt-update'], Exec['download-ipmininet'], Package['python-setuptools'], Package['python-pip'], Package['mininet'], Package['mako'], Exec['quagga'] ],
  command => "pip install -e ${ipmininet_path}",
}

# c-ares lib
exec { 'c-ares-build-config':
  require => [ Exec['apt-update'], Package['libtool'] ],
  cwd => $cares_source_path,
  path => "${path}:${cares_source_path}",
  command => 'buildconf',
  creates => "${cares_source_path}/configure",
}
exec { 'c-ares-config':
  require => [ Exec['c-ares-build-config'] ],
  cwd => $cares_source_path,
  path => "${path}:${cares_source_path}",
  command => "configure --enable-warnings --enable-werror --prefix=${cares_path};\
              make;\
              make install;",
  creates => $cares_path,
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
