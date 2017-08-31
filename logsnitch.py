#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
.__                             .__  __         .__     
|  |   ____   ____  ______ ____ |__|/  |_  ____ |  |__  
|  |  /  _ \ / ___\/  ___//    \|  \   __\/ ___\|  |  \ 
|  |_(  <_> ) /_/  >___ \|   |  \  ||  | \  \___|   Y  \
|____/\____/\___  /____  >___|  /__||__|  \___  >___|  /
           /_____/     \/     \/              \/     \/ 
"""

import os
import sys
import re
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
import time 

#general variables
logpath='/var/log'

#regex patterns
authPattern1 = re.compile(r'(user)=([a-zA-Z[0-9]+$)')
authPattern2 = re.compile(r'(rhost)=([0-9A-Za-z.]*)')
authPattern3 = re.compile(r'(Failed password).*')


# gmail username
USER = os.environ.get('GMAIL_USER')
# gmail password
PWD = os.environ.get('GMAIL_PWD')
# sender address
FROM = 'logsnitch@gmail.com'
# comma separated list of recipients
TO = os.environ.get('DATA_RECIPIENT')


def sendmail(data):
    body = data

    body = 'Hi Admin!\n' + body
    message = MIMEMultipart()
    message['From'] = FROM
    message['To'] = TO
    message['Subject'] = "Server logs Report: " + time.strftime('%d/%m/%Y-%H:%m')
    message.attach(MIMEText(body, 'plain'))
    
    server = smtplib.SMTP('smtp.gmail.com:587')
    server.starttls()
    server.login(USER, PWD)
    server.sendmail(FROM, TO, message.as_string())
    server.quit()

if not os.geteuid() == 0:
    sys.exit('Become root and try again!\nExiting...')


authfailure = []
failedLogins = []

with open(logpath+ '/auth.log', 'r') as logfile1:
    authfile = logfile1.read().splitlines()

    for line in authfile:

        if "authentication failure" in line:
             if "sshd" in line:

                userMo = authPattern1.search(line)
                user   =""
                if userMo:
                    user   = userMo.group(2)
            
                hostMo = authPattern2.search(line)
                host   =""
                if hostMo: 
                    host   = hostMo.group(2)

                if user and host:
                    linesplit = line.split()
                    #extract the date from the line
                    date=[]
                    for i in range(2,-1,-1):
                        date.append(linesplit[i])

                    date = ' '.join(date)
                    authfailure.append({'date':date, 'user':user, 'host':host})
           

             if "pam_unix" in line:
                 pass

        if "Failed password for invalid" in line:
            res = line.split()
            date = ' '.join(res[2::-1])
            failedLogins.append({'date':date,'user':res[10], 'ip':res[12]})
            

ipList = []
nginxdir = logpath + '/nginx'
if os.path.isdir(nginxdir):
    if os.path.exists(nginxdir):
        with open(nginxdir +'/access.log', 'r') as logfile2:
            nginxaccess = logfile2.read().splitlines()
            
            for line in nginxaccess:
                #The following works if you don't provided this kind of interface towards the NET
                if "admin" or "mysql" or "Admin" or "phpMyAdmin2" in line:
                    #The page is not found but the malevolent persistentrly performs requests
                    # to admin pages
                    if "404" in line:
                        #extract ip 
                        ipList.append(line.split(' ')[0])
                       
#preserve only unique IPs. This is done by converting the list to a set and back to a list
ipList = list(set(ipList))

data =""

#Failed ssh Authentication Attempts in your sshd
data += "\n"
data += "Authentication failure in known ssh users\n"
data += "==============================================================================\n"
for record in authfailure:
    data += "Date:%(date)-15s User:%(user)-12s from Host:%(host)s\n" %record
data += "==============================================================================\n"
data +="\n"
    
#Failed ssh login attempts from invalid users
data += "Failed ssh login attempts from invalid users\n"
data += "==============================================================================\n"
for record in failedLogins:
    data += "Date:%(date)-15s User:%(user)-12s from Host:%(ip)s\n" %record
data += "==============================================================================\n"
data += "\n"

#nginx Hacking Attempts
data += "The following intruders identified bruteforcing your Nginx\n"
data += "==============================================================================\n"
for ip in ipList:
    data += ip +'\n'
data += "==============================================================================\n"

try:
    with open('tmp1.tmp', 'r') as tempfile:
        fileContents = tempfile.read()
        if fileContents == data:
            print 'No changes detected in the Server logs!'
        else:
            #write the new data to the file
            with open('tmp1.tmp', 'w') as tmpfile2:
                tmpfile2.write(data)

                #send email only if a change was detected 
                sendmail(data)

except IOError, err:
    #helful error messages
    #print err
    #print err.errno
    #print err.strerror
    #print err.filename

    # if the tmp1.tmp not found create it
    # this happens if it was deleted or if the program
    # executed for the first time
    if err.errno == 2:
        with open('tmp1.tmp', 'w') as tmpfile:
            tmpfile.write(data)
            sendmail(data)
