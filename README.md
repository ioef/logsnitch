# logsnitch
Python Tool to extract useful info about intrusions from your /var/log Server files.
Currently shows the user and host for authentication failures in known ssh users, failed ssh login attempts from invalid users and ips of malevolent users trying to bruteforce webpages over the running Nginx.

# Instructions
 * Issue chmod +x logsnitch.py
 * Execute the logsnitch.py sudo env GMAIL_USER='xxxxxx@gmail.com' GMAIL_PWD='xxxxxxx' DATA_RECIPIENT='xxxxxx@gmail.com' ./logsnitch.py 

Optionally create a cron job
```
00,30 * * * * env GMAIL_USER='xxxxxx@gmail.com' GMAIL_PWD='xxxxxxx' DATA_RECIPIENT='xxxxxx@gmail.com' /home/user/logsnitch.py  > /dev/null 2>&1
```
