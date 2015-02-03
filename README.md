# 2hash
2hash, a program to create md5 and sha1 hashes in parallel

2hash v0.1.1 for Win32

SUMMARY

This is a very slightly modified version of the original 2hash v0.1, released
by Thomas Akin in 2004. 

Only changes are a few command line switches (-h and -v, which do what you'd 
expect) and, uh, it's compiled for Windows. 

Source is included. It was compiled with Visual C++ 2008 Express Edition. I 
couldn't figure out the manifest stuff so just compiled it statically (which 
for various reasons is described as not a great idea). 

The compiled .exe was shrunk with UPX: 
  http://upx.sourceforge.net

I've tested it on Windows XP, Windows 2000 Server and Windows 2003 server. 

-- 
David Harrison
@trawg


Original copyright and license:

/*
*  2hash v0.1 - Program to create md5 and sha1 hashes in parallel
*  http://www.crossrealm.com/2hash
*  2004-05-13
*
*  Copyright Thomas Akin (2004)
*  This work is based off of Christophe Devine's md5 and sha1 code
*  found at http://cr0.net:8040
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
