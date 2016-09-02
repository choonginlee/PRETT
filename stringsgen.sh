#!/bin/bash
echo "Start creating strings"
strings -to /bin/ping > ping.txt
strings -to /bin/ping6 > ping6.txt
strings -to /usr/bin/arping > arping.txt
strings -to /usr/bin/avahi-browse > avahi-browse.txt
strings -to /usr/bin/avahi-publish > avahi-publish.txt
strings -to /usr/bin/avahi-resolve > avahi-resolve.txt
strings -to /usr/bin/avahi-set-host-name > avahi-set-host-name.txt
strings -to /usr/bin/bluemoon > bluemoon.txt
strings -to /usr/bin/bluetoothctl > bluetoothctl.txt
strings -to /usr/bin/bluetooth-sendto > bluetooth-sendto.txt
strings -to /usr/bin/btmgmt > btmgmt.txt
strings -to /usr/bin/curl > curl.txt
strings -to /usr/bin/dig > dig.txt
strings -to /usr/bin/dirmngr > dirmngr.txt
strings -to /usr/bin/dirmngr-client > dirmngr-client.txt
strings -to /usr/bin/ftp > ftp.txt
strings -to /usr/bin/fwupdate > fwupdate.txt
strings -to /usr/bin/fwupdmgr > fwupdmgr.txt
strings -to /usr/bin/git > git.txt
strings -to /usr/bin/l2ping > l2ping.txt
strings -to /usr/bin/l2test > l2test.txt


