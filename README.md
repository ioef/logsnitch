# logsnitch
Python Tool to extract useful info about intrusions from your /var/log Server files.
Currently shows the user and host for authentication failures in known ssh users, failed ssh login attempts from invalid users and ips of malevolent users trying to bruteforce webpages over the running Nginx.

# Instructions
 * Issue chmod +x logsnitch.py
 * Execute the logsnitch.py file as sudo. sudo ./logsnitch.py

 
# TO DO
Will be enhanced with the smtplib in order to support automated mail sending with this info after it's execution through a cron job.

