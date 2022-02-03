# Declarative Openstack

This repository aims to contain scripts to install and manage your Openstack 
installation.

You can manage your whole installation from within a few yaml files, and redeploy 
them anytime, to change current configuration, deploy new nodes and remove old
ones.

You can do all of that in a declarative manner, in simple yaml config files that
you can commit and add to version control (be carefull to **not** store any 
password in your yaml files if you commit them).
