# ptmsg #
======

ptmsg is a tool that automatically infering network protocol models from binary tokens.

## Prerequisite (please install in order) ##
- Scapy (pip)
- matplotlib (pip)
- transitions (pip)
- python-tk (apt-get)
- graphviz libgraphviz-dev pkg-config (apt-get)
- pygraphviz (pip)
* Use the following command when installing pygraphviz
pip install pygraphviz --install-option="--include-path=/usr/include/graphviz" --install-option="--library-path=/usr/lib/graphviz/"

## Easy Running Example ##

1. Run stringsgen.sh in the root directory of ptmsg
- It generates tokens from basic binaries of your own linux OS.

2. If strings are generated from binaries, check binstring/ directory.
- There should a lot of txt files which contain strings extracted from target binaries

3. Then run tokenizer.py by specifying binstring/ directory as an arguemnt.
- Ex ) $ python tokenizer.py ./binstring/
- It refines appropriate tokens from the strings

4. If tokens are generated and refined from strings, check tokenfile/ directory.
- There should a lot of txt files which contain tokens refined from strings

5. Then run modeller.py by specifying target FTP server as an arguemnt (permission needed)
- Ex ) $ sudo python modeller.py [Target IP]

6. You will see the requests automatically generated and responses of them.

! For the better performance, disable PAM in vsftpd.
(Ubuntu)
- in /etc/pam.d/vsftpd, add the line SEC_PAM_BYPASS=Y
- in /etc/pam.d/vsftpd, make comments to all the content
- in /etc/vsftpd.conf, make comment in pam_service_name=vsftpd
then reboot!