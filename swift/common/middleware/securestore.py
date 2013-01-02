# A basic encryption middleware for swift. 
# See the documentation for usage with swift. 
#
# Author : Sibi Antony, (c) 2012
#            sibi [dot] antony [at] gmail [dot] com 

import errno
import os

from swift.common.swob import Request, Response
from swift.common.utils import split_path, hash_path

from cStringIO import StringIO
from hashlib import md5, sha1
from Crypto.Cipher import AES

class SecureStorage(object):
    """
    Swift3 secure storage midleware - Uses a simple basic encryption 
    """
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        # get conf file parameter
        self.caches = conf.get('cache_servers', '127.0.0.1:8088').split(',')

    def __call__(self, env, start_response):
        """Request to the server.py"""
        req = Request(env)

        version, account, container, obj = split_path(req.path, 1, 4, True)

        if obj and container and account and req.method == "POST":
            return self.app(env, start_response)

        elif obj and container and account and req.method == "PUT":
            print "Securestorage dbg: PUT request"
            # Encrypt the incoming file, using AES-256
            # - Encryption key based on acc, container, object
            # - CFB mode, no initialization vector
            enc_key = self.get_enc_key(account, container, obj)
            cipher_enc = AES.new(enc_key, AES.MODE_CFB)
            body = cipher_enc.encrypt(req.body)

            env['wsgi.input'] = StringIO(body)
            return self.app(env, start_response)

        elif obj and container and account and req.method == "GET":
            print "Securestorage dbg: GET request"
            #
            # - Verify this is a file download request
            body = []
            self.status_headers = [None, None]

            app_iter = self.app(env, self._sr_callback(start_response))

            # Modify response 'body'
            try:
                for item in app_iter:
                    body.append(item)
            finally:
                if hasattr(app_iter, 'close'):
                    app_iter.close()

            body = ''.join(body)
            # Decrypt the download file. 
            # - Decryption key based on account, container, object
            # - 
            enc_key = self.get_enc_key(account, container, obj)
            cipher_dec = AES.new(enc_key, AES.MODE_CFB)
            body = cipher_dec.decrypt(body)

            # Fix the header etags
            # - Calculate the md5, convert header fields into dictionary
            # - Replace etag with the new one.
            m = md5()
            m.update(body)
            headers = dict(self.status_headers[1])
            headers['etag'] = m.hexdigest()

            # Response headers.. 
            start_response(self.status_headers[0], headers.items(), exc_info=None)

            return body

        else:
            # print "Securestore dbg: Obj: ", obj, " Container: ", container, " Account: ", account
            return self.app(env, start_response)

    def _sr_callback(self, start_response):
        """
        A callback for the start_response(). 
        We need to tweak the headers before sending the response 
        back to the user. 

        """
        # print "Securestore dbg: sr_callback()"
        def callback(status, headers, exc_info=None):
            self.status_headers[:] = [status, headers]
            # Modify response 'headers'

        return callback

    def get_enc_key(self, account, container, obj):
        """
        Generate a unique, random key for encrypting this file.
        - Maybe based on the user passwords, and/or credentials
        - Need chained keys to support tenants/group access in the above case.
        """
        enc_key = sha1(hash_path(account, container, obj)).hexdigest()
        return enc_key[:16]


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""

    # print "secure storage filter factory"
    conf = global_conf.copy()
    conf.update(local_conf)

    def sec_filter(app):
        return SecureStorage(app, conf)

    return sec_filter
