#!/usr/bin/python
# -*- coding: utf-8 -*-

# A utility script to register new users for the
#   swift encryption middleware
# See the documentation for usage with swift.
#
# Author : Sibi Antony, (c) 2012
# sibi [dot] antony [at] gmail [dot] com 

import MySQLdb as mdb
import sys
from hashlib import md5, sha1, sha256
from uuid import uuid4
import argparse
from Crypto.Cipher import AES

# uname, groupname - 32 byte VARCHAR - as per UNIX supported values
# userkey, enckey   - 64 byte VARCHAR
# 
DB_USER='openstack'
DB_PASS='openstack'
DB_NAME='swiftauth'
DB_HOST='localhost'

def secauth_user_add(account, uname, gname, passwd):

    # shadowed password
    h_passwd = md5(passwd).hexdigest()
    passwd_key = sha256(passwd).hexdigest()[:32]

    # The passwd key is used to encrypt a unique user key.
    userkey = uuid4().hex
    aes_enc_userkey = AES.new(passwd_key, AES.MODE_CFB)
    enc_userkey = aes_enc_userkey.encrypt(userkey)

    # The user key is in turn used to encrypt a unique account (tenant) key.
    # - 64 bits for sha256, use a 32 bit key
    acct_key = sha256(account).hexdigest()[:32]
    aes_enc_acctkey = AES.new(userkey, AES.MODE_CFB)
    enc_acctkey = aes_enc_acctkey.encrypt(acct_key)

    try: 
        con = mdb.connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);

        with con:
            cur = con.cursor()
            cur.execute("insert into user values( '%s', '%s', '%s', '%s', '%s', '%s' )" % \
                (account, uname, h_passwd, gname, \
                enc_userkey, enc_acctkey) )
            # The encrypted keys with the token will be filled in by 
            #   the authentication layer
            cur.execute("insert into user_to_token values( '%s', '%s', '%s' )" % \
                (account, uname, h_passwd) )

    except mdb.Error, e:
        print "Error %d: %s" % (e.args[0], e.args[1])
        sys.exit(1)

    finally:
        print "Enc: passwd_key : %s, userkey : %s, acct_key : %s" % (passwd_key, userkey, acct_key)
        passwd_key = sha256(passwd).hexdigest()[:32]

        aes_dec_userkey = AES.new(passwd_key, AES.MODE_CFB)
        userkey = aes_dec_userkey.decrypt(enc_userkey)

        aes_dec_acctkey = AES.new(userkey, AES.MODE_CFB)
        acctkey = aes_dec_acctkey.decrypt(enc_acctkey)

        print "Dec: passwd_key : %s, userkey : %s, acct_key : %s" % (passwd_key, userkey, acct_key)
        if con:
            con.close()

def secauth_group_add(gname):
    # shadowed groupname
    h_gname = md5(gname)
    h_enckey = md5(sha1(gname).hexdigest())

    # Check if this group already exists in db
    try:
        con = mdb.connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);

        with con:
            cur = con.cursor()
            cur.execute("select * from groups where gname = '%s'" % h_gname)
            r = cur.fetchone()
            if not r:
                # no group exist
                cur.execute("insert into groups values ('%s', '%s')" % \
                    (h_gname.hexdigest(), h_enckey.hexdigest()) )


    except mdb.Error, e:
        print "Error %d: %s" % (e.args[0], e.args[1])
        sys.exit(1)

    finally:
        if con:
            con.close()

def secauth_user_del(account, uname):

    try: 
        con = mdb.connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);

        with con:
            cur = con.cursor()
            cur.execute("delete from user where account='%s' and uname='%s'" % \
                (account, uname) )
            cur.execute("delete from user_to_token where account='%s' and uname='%s'" % \
                (account, uname) )

    except mdb.Error, e:
        print "Error %d: %s" % (e.args[0], e.args[1])
        sys.exit(1)

    finally:
        if con:
            con.close()


con = None

parser = argparse.ArgumentParser(description='User management for secure db', \
            formatter_class=argparse.RawTextHelpFormatter)
subparsers = parser.add_subparsers(help='sub-commands', dest='subparser_name')

parser_useradd = subparsers.add_parser('add', help='Add a user')

parser_useradd.add_argument('-a', action='store', dest='account', type=str,
                    help='account name')
parser_useradd.add_argument('-u', action='store', dest='uname', type=str,
                    help='username')
parser_useradd.add_argument('-g', action='store', dest='gname', type=str,
                    help='list of groups, space separated')
parser_useradd.add_argument('-p', action='store', dest='passwd', type=str,
                    help='password')

parser_userdel = subparsers.add_parser('del', help='Delete a user')

parser_userdel.add_argument('-a', action='store', dest='account', type=str,
                    help='account')
parser_userdel.add_argument('-u', action='store', dest='uname', type=str,
                    help='username')

arg = parser.parse_args()

if (arg.subparser_name == 'add'):
    secauth_user_add(arg.account, arg.uname, arg.gname, arg.passwd)
    # secauth_group_add(arg.gname)

elif (arg.subparser_name == 'del'):
    secauth_user_del(arg.account, arg.uname)
