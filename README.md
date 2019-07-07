# PRETT #
======

PRETT is a tool that automatically infers network protocol models using network traces and binary tokens.

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

1. Make 'binstring' directory and run 'strings_extractor.sh' in the root directory.
- It generates tokens from basic binaries of your own linux OS.

2. If strings are generated from binaries, the 'binstring/' directory should contain a lot of txt files which contain strings extracted from target binaries.

3. Make 'tokenfile' directory and run 'token_refiner.py' to refine appropriate tokens from the strings extracted in step 1.

> $ python token_refiner.py ./binstring/

4. If tokens are generated and refined, the 'tokenfile/' directory should containt a lot of txt files which contain tokens refined from strings.

5. Then run modeller_{ftp,smtp,http}.py specifying target FTP, SMTP, HTTP server IP as its arguemnt (permission needed)

> $ sudo pythonmodeller_{ftp,smtp,http}.py [Target IP]

6. You will see the requests automatically generated and responses of them. We expect a clear state machine is drawn in a file in the root directory, but it may run so long time in case the implemnetaion of the server binary is too complex. We encourage users to quit the process as the job achieved desirable result with heuristics.

! For the better performance, disable PAM in vsftpd.
(Ubuntu)
- in /etc/pam.d/vsftpd, add the line SEC_PAM_BYPASS=Y
- in /etc/pam.d/vsftpd, make comments to all the content
- in /etc/vsftpd.conf, make comment in pam_service_name=vsftpd
then reboot!
