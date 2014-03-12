# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "precise64"
  config.vm.provision :shell, :path => 'vagrant_setup.sh'
  config.vm.network :forwarded_port, guest: 11371, host: 11371, host_ip: '0.0.0.0'
  config.vm.network :forwarded_port, guest: 7474, host: 7474, host_ip: '0.0.0.0'
end
