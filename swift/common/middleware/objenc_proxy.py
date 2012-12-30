# A proxy extension for the Object server encryption middleware
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

class ObjEncProxy(object):
    """
    A proxy extension for the Object server encryption middleware
    This will be responsible for generating the necessary keys 
        required for encryption.

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
            # print "Objenc Proxy: PUT request"

            # Master key for chained encryption.
            env['HTTP_X_OBJECT_META_MASTERKEY'] = self.generate_master_key(account, container, obj)
            # A one-time, unique random key to encrypt this file. 
            env['HTTP_X_OBJECT_META_ENCKEY'] = self.generate_enc_key()

            return self.app(env, start_response)

        elif obj and container and account and req.method == "GET":
            # print "Objenc Proxy: GET request"

            env['HTTP_X_OBJECT_META_MASTERKEY'] = self.generate_master_key(account, container, obj)

            return self.app(env, start_response)

        else:
            # print "Objenc Proxy: Obj: ", obj, " Container: ", container, " Account: ", account
            return self.app(env, start_response)

    def generate_enc_key(self):
        """
        Generate a unique, random key for encrypting this file.
        A new key will be generated each time the file is modified.

        """
        rand_key = md5(os.urandom(32)).hexdigest()
        return rand_key[:16]

    def generate_master_key(self, acc, cont, obj):
        """
        A master key for chained encryption of the individual keys.
            - Master key may be based on the user credentials/password
            - User passwords will break and introduce group access restrictions
            - For simplicity, the key is a sha1 hash of the swift calculated hash_path 
        """
        master_key = sha1(hash_path(acc, cont, obj)).hexdigest()
        return master_key[:16]


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""

    # print "secure storage filter factory"
    conf = global_conf.copy()
    conf.update(local_conf)

    def objproxy_filter(app):
        return ObjEncProxy(app, conf)

    return objproxy_filter
