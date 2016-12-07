#!/bin/bash
timestamp() {
	date +"%T.%N"
}

echo "Start creating strings"
timestamp

strings -to /bin/ping > ./binstring/ping.txt
strings -to /bin/ping6 > ./binstring/ping6.txt
strings -to /usr/bin/arping > ./binstring/arping.txt
strings -to /usr/bin/avahi-browse > ./binstring/avahi-browse.txt
strings -to /usr/bin/avahi-publish > ./binstring/avahi-publish.txt
strings -to /usr/bin/avahi-resolve > ./binstring/avahi-resolve.txt
strings -to /usr/bin/avahi-set-host-name > ./binstring/avahi-set-host-name.txt
strings -to /usr/bin/bluemoon > ./binstring/bluemoon.txt
strings -to /usr/bin/bluetoothctl > ./binstring/bluetoothctl.txt
strings -to /usr/bin/bluetooth-sendto > ./binstring/bluetooth-sendto.txt
strings -to /usr/bin/btmgmt > ./binstring/btmgmt.txt
strings -to /usr/bin/curl > ./binstring/curl.txt
strings -to /usr/bin/dig > ./binstring/dig.txt
strings -to /usr/bin/dirmngr > ./binstring/dirmngr.txt
strings -to /usr/bin/dirmngr-client > ./binstring/dirmngr-client.txt
# strings -to /usr/bin/ftp > ./binstring/ftp.txt
strings -to /usr/bin/fwupdate > ./binstring/fwupdate.txt
strings -to /usr/bin/fwupdmgr > ./binstring/fwupdmgr.txt
strings -to /usr/bin/git > ./binstring/git.txt
strings -to /usr/bin/l2ping > ./binstring/l2ping.txt
strings -to /usr/bin/l2test > ./binstring/l2test.txt
strings -to /usr/bin/mtr > ./binstring/mtr.txt
# strings -to /usr/bin/netkit-ftp > ./binstring/netkit-ftp.txt
strings -to /usr/bin/nm-applet > ./binstring/nm-applet.txt
strings -to /usr/bin/nmtui > ./binstring/nmtui.txt
strings -to /usr/bin/nslookup > ./binstring/nslookup.txt
strings -to /usr/bin/obexctl > ./binstring/obexctl.txt
strings -to /usr/bin/openssl > ./binstring/openssl.txt
# strings -to /usr/bin/pftp > ./binstring/pftp.txt
strings -to /usr/bin/rctest > ./binstring/rctest.txt
strings -to /usr/bin/rfcomm > ./binstring/rfcomm.txt
strings -to /usr/bin/scp > ./binstring/scp.txt
strings -to /usr/bin/sdptool > ./binstring/sdptool.txt
# strings -to /usr/bin/sftp > ./binstring/sftp.txt
strings -to /usr/bin/ssh > ./binstring/ssh.txt
strings -to /usr/bin/telnet > ./binstring/telnet.txt
strings -to /usr/bin/telnet.netkit > ./binstring/telnet.netkit.txt
strings -to /usr/bin/tracepath > ./binstring/tracepath.txt
strings -to /usr/bin/tracepath6 > ./binstring/tracepath6.txt
strings -to /usr/bin/traceroute6 > ./binstring/traceroute6.txt
strings -to /usr/bin/vstp > ./binstring/vstp.txt
strings -to /usr/bin/webbrowser-app > ./binstring/webbrowser-app.txt
strings -to /usr/bin/wget > ./binstring/wget.txt
strings -to /usr/bin/wireshark > ./binstring/wireshark.txt
strings -to /usr/bin/xdg-email > ./binstring/xdg-email.txt
strings -to /usr/bin/xhost > ./binstring/xhost.txt
