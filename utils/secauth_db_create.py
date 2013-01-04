#!/usr/bin/python
# -*- coding: utf-8 -*-
# A utility script to create an authentication db for 
#    swift encryption middleware
# See the documentation for usage with swift.
#
# Author : Sibi Antony, (c) 2012
# sibi [dot] antony [at] gmail [dot] com 

import MySQLdb as mdb
import sys
from hashlib import md5, sha1
import argparse

DB_USER='openstack'
DB_PASS='openstack'
DB_NAME='swiftauth'
DB_HOST='localhost'

try:
    con = mdb.connect(DB_HOST, DB_USER, DB_PASS, 'mysql');

    with con:
        cur = con.cursor()
        cur.execute("create database if not exists %s" % (DB_NAME))

except mdb.Error, e:
    print "Error creating database %d: %s" % (e.args[0], e.args[1])
    sys.exit(1)

finally:
    if con:
        con.close()

# Create the db schema
try: 
    con = mdb.connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);

    with con:
        cur = con.cursor()
        cur.execute("create table user( account VARCHAR(32) NOT NULL, \
            uname VARCHAR(32) NOT NULL, \
            passwd VARCHAR(64), ugroups VARCHAR(256), \
            userkey VARCHAR(64), acckey VARCHAR(64), \
            primary key (account, uname) )" )
        cur.execute("create table user_to_token( account VARCHAR(32) NOT NULL, \
            uname VARCHAR(32) NOT NULL, \
            enckey VARCHAR(64), \
            primary key (account, uname) )" )

except mdb.Error, e:
    print "Error %d: %s" % (e.args[0], e.args[1])
    sys.exit(1)

finally:
    if con:
        con.close()
