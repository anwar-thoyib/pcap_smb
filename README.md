## Descriptions

The script will extract the PCAP TCP/IP stream binary data to get Samba (Microsoft File Sharing) protocol profiles:
MAC-Address source and targat
IP-Address source and target
Port source and target
Filename, Filesize, and Content.

## Usage

command:
$ ./pcap_smb.py <file_input.pcap> [debug]
$ python3 pcap_smb.py <file_input.pcap> [debug]

example:
$ ./pcap_smb.py smb.pcap
$ ./pcap_smb.py smb.pcap debug

OR

$ python3 pcap_smb.py smb.pcap
$ python3 smb.py smb.pcap debug

output:
filename: result.json

debug: stdout



