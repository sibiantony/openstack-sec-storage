# An encryption middleware for the secure authentication using 
#    a centralized database.
# See the documentation for usage with swift. 
#
# Author : Sibi Antony, (c) 2012
#            sibi [dot] antony [at] gmail [dot] com 

import errno
import os

from swift.common.swob import Request, Response
from swift.common.utils import split_path, get_logger, TRUE_VALUES

from cStringIO import StringIO
from hashlib import md5, sha1
from Crypto.Cipher import AES
import MySQLdb as mdb


class SecureDBEncMiddleware(object):
    """
    An encryption middleware for the secure authentication using 
    a centralized database.

    Needs to be added to the pipeline and requires a filter
    declaration in the object-server.conf:

    """

    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.devices = conf.get('devices', '/srv/node/')
        swift_dir = conf.get('swift_dir', '/etc/swift')
        self.conf = conf
        self.db_host = conf.get('mdb_host', '127.0.0.1')
        self.db_user = conf.get('mdb_user', 'openstack')
        self.db_pass = conf.get('mdb_pass', 'openstack')
        self.db_name = conf.get('mdb_db', 'swiftauth')

    def __call__(self, env, start_response):
        req = Request(env)
        version, account, container, obj = split_path(req.path, 1, 4, True)
        if obj and container and account and req.method == "POST":
            return self.app(env, start_response)

        elif obj and container and account and req.method == "PUT":
            acc_user = env['REMOTE_USER'].split(',', 2)
            account, user = acc_user[1].split(':', 1)
            h_account = md5(account).hexdigest()
            h_user = md5(user).hexdigest()

            # Get the encryption keys from db
            auth_token = env['HTTP_X_AUTH_TOKEN'].split(':', 1)[0]
            try:
                db_con = mdb.connect(self.db_host, self.db_user, self.db_pass, self.db_name)
                with db_con:
                    dbcur = db_con.cursor()
                    dbcur.execute("select enckey from user_to_token where account = '%s' and uname = '%s' " % \
                    ( h_account, h_user ) )
                dbrow = dbcur.fetchone()
                enc_tokenkey = dbrow[0]
            except mdb.Error, e:
                print "DB Error %d : %s" % (e.args[0], e.args[1])
            finally:
                if db_con:
                    db_con.close()

            #file_enc = AES.new(enc_key, AES.MODE_CFB)
            aes_enc_tokenkey = AES.new(auth_token[-32:], AES.MODE_CFB)
            token_key = aes_enc_tokenkey.decrypt(enc_tokenkey)

            file_enc = AES.new(token_key, AES.MODE_CFB)
            body = file_enc.encrypt(req.body)
            env['wsgi.input'] = StringIO(body)

            return self.app(env, start_response)

        elif obj and container and account and req.method == "GET":
            acc_user = env['REMOTE_USER'].split(',', 2)
            account, user = acc_user[1].split(':', 1)
            h_account = md5(account).hexdigest()
            h_user = md5(user).hexdigest()

            # Get the encryption keys from db
            auth_token = env['HTTP_X_AUTH_TOKEN'].split(':', 1)[0]
            try:
                db_con = mdb.connect(self.db_host, self.db_user, self.db_pass, self.db_name)
                with db_con:
                    dbcur = db_con.cursor()
                    dbcur.execute("select enckey from user_to_token where account = '%s' and uname = '%s' " % \
                    ( h_account, h_user ) )
                dbrow = dbcur.fetchone()
                enc_tokenkey = dbrow[0]
            except mdb.Error, e:
                print "DB Error %d : %s" % (e.args[0], e.args[1])
            finally:
                if db_con:
                    db_con.close()

            aes_enc_tokenkey = AES.new(auth_token[-32:], AES.MODE_CFB)
            token_key = aes_enc_tokenkey.decrypt(enc_tokenkey)

            body = []
            self.status_headers = [None, None]

            app_iter = self.app(env, self._sr_callback(start_response))

            # Modify response 'body'
            try:
                for item in app_iter:
                    # print "Item : ", item
                    body.append(item)
            finally:
                if hasattr(app_iter, 'close'):
                    app_iter.close()

            body = ''.join(body)
            headers = dict(self.status_headers[1])

            # Decrypt the download file. 
            file_dec = AES.new(token_key, AES.MODE_CFB)
            body = file_dec.decrypt(body)

            # We need to fix the header etags before proceeding
            # - Etags are a way of integrity checking within swift and at the client
            # - Calculate the md5, convert header fields into dictionary
            # - Replace etag with the new one.
            headers['etag'] = md5(body).hexdigest()

            # Response headers.. 
            start_response(self.status_headers[0], headers.items(), exc_info=None)

            return body
        else:
            return self.app(env, start_response)

    def _sr_callback(self, start_response):
        """
        A callback for the start_response(). 
        We need to tweak the headers before sending the response 
        back to the user. 

        """
        def callback(status, headers, exc_info=None):
            self.status_headers[:] = [status, headers]
            # Modify response 'headers'

        return callback

def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def secdbenc_filter(app):
        return SecureDBEncMiddleware(app, conf)
    return secdbenc_filter
