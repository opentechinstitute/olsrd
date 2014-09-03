[![alt tag](http://img.shields.io/badge/maintainer-dismantl-green.svg)](https://github.com/dismantl)
olsrd
=====
The [olsr.org](http://olsr.org) OLSR daemon is an implementation of the [Optimized Link State Routing protocol](http://ietf.org/rfc/rfc3626.txt). As such it allows mesh routing for any network equipment.
It runs on any wifi card that supports ad-hoc mode and of course on any ethernet device.

This repository is a fork of olsrd that contains two plugins specific to the [Commotion Wireless](https://commotionwireless.net) software.

Plugins
=======

DNSSD
-----
The DNSSD plugin is a fork of the P2PD plugin, and is used to forward multicast DNS (mDNS) traffic used to announce local services on the mesh network. It queries [Avahi](http://avahi.org/) service files that conform to the Commotion local service specification and limits the propagation of mDNS service announcements according to the service's TTL (or hop count). This plugin uses the third party [ldns library](https://www.nlnetlabs.nl/projects/ldns/).

MDP
---
The MDP (short for Mesh Datagram Protocol) plugin is a replacement for the secure plugin, and uses the cryptographic functions of the [libserval](https://github.com/servalproject/serval-dna) library to sign and verify signatures on olsrd packets.
