
Debian
====================
This directory contains files used to package snodecoind/snodecoin-qt
for Debian-based Linux systems. If you compile snodecoind/snodecoin-qt yourself, there are some useful files here.

## snodecoin: URI support ##


snodecoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install snodecoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your snodecoinqt binary to `/usr/bin`
and the `../../share/pixmaps/snodecoin128.png` to `/usr/share/pixmaps`

snodecoin-qt.protocol (KDE)

