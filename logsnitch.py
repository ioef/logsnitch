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

#general variables
logpath='/var/log'

#regex patterns
authPattern1 = re.compile(r'(user)=([a-zA-Z[0-9]+$)')
authPattern2 = re.compile(r'(rhost)=([0-9A-Za-z.]*)')
authPattern3 = re.compile(r'(Failed password).*')


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
                    authfailure.append({'user':user, 'host':host})
           

             if "pam_unix" in line:
                 pass

        if "Failed password for invalid" in line:
            res = line.split(' ')
            failedLogins.append({'user':res[11], 'ip':res[13]})
            

ipList = []
nginxdir = logpath + '/nginx'
if os.path.isdir(nginxdir):
    if os.path.exists(nginxdir):
        with open(nginxdir +'/access.log', 'r') as logfile2:
            nginxaccess = logfile2.read().splitlines()
            
            for line in nginxaccess:
                #The following works if you don't provided this kind of interface towards the NET
                if "admin" or "mysql" or "Admin" or "phpMyAdmin2" in line:
                    ipList.append(line.split(' ')[0])

#preserve only unique IPs. This is done by converting the list to a set and back to a list
ipList = list(set(ipList))
            

#Failed ssh Authentication Attempts in your sshd
print "\n"
print "Authentication failure in known ssh users"
print "===================================================================="
for record in authfailure:
    print "user: %(user)-20s from host: %(host)s" %record
print "===================================================================="
print "\n"

#Failed ssh login attempts from invalid users
print "Failed ssh login attempts from invalid users"
print "===================================================================="
for record in failedLogins:
    print "user: %(user)-20s from host: %(ip)s" %record
print "===================================================================="
print "\n"

#nginx Hacking Attempts
print "The following intruders identified bruteforcing your Nginx"
print "===================================================================="
for ip in ipList:
    print ip
print "===================================================================="
