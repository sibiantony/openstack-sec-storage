# An encryption middleware associated with the object server.
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


class ObjEncMiddleware(object):
    """
    An encryption middleware associated with the object server. 

    Needs to be added to the pipeline and requires a filter
    declaration in the object-server.conf:

    """

    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.devices = conf.get('devices', '/srv/node/')
        swift_dir = conf.get('swift_dir', '/etc/swift')

    def __call__(self, env, start_response):
        req = Request(env)

        if req.method == "PUT":
            # print "objenc dbg : PUT request"
            
            # Get the encryption keys, delete from swift environment
            master_key, env = self.get_master_key(env)
            enc_key, env = self.get_enc_key(env)

            file_enc = AES.new(enc_key, AES.MODE_CFB)
            body = file_enc.encrypt(req.body)
            env['wsgi.input'] = StringIO(body)

            # Add an object metadata item for encryption key
            # The key is encrypted with masterkey before being stored as metadata
            key_enc = AES.new(master_key, AES.MODE_CFB)
            env['HTTP_X_OBJECT_META_ENCKEY'] = key_enc.encrypt(enc_key)

            return self.app(env, start_response)

        elif req.method == "GET":
            # print "objenc dbg : GET request"
            body = []
            self.status_headers = [None, None]

            # Get the master key from the proxy filter, 
            # delete from swift environment
            master_key, env = self.get_master_key(env)

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

            # Decrypt the encryption key from the object metadata
            key_enc = AES.new(master_key, AES.MODE_CFB)
            enc_key = key_enc.decrypt(headers['x-object-meta-enckey'])

            # Decrypt the download file. 
            file_dec = AES.new(enc_key, AES.MODE_CFB)
            body = file_dec.decrypt(body)

            # We need to fix the header etags before proceeding
            # - Etags are a way of integrity checking within swift and at the client
            # - Calculate the md5, convert header fields into dictionary
            # - Replace etag with the new one.
            headers['etag'] = md5(body).hexdigest()

            # The metadata enckey is no more required in a response!
            del headers['x-object-meta-enckey']

            # Response headers.. 
            start_response(self.status_headers[0], headers.items(), exc_info=None)

            return body

        else:
            print "objenc: Return"
            return self.app(env, start_response)

    def get_enc_key(self, environ):
        """
        Get the encryption key passed on by the proxy.
        Delete the meta environ variable

        """
        e_key = environ['HTTP_X_OBJECT_META_ENCKEY']
        del environ['HTTP_X_OBJECT_META_ENCKEY']
 
        return e_key, environ



    def _sr_callback(self, start_response):
        """
        A callback for the start_response(). 
        We need to tweak the headers before sending the response 
        back to the user. 

        """
        # print "objenc debug: sr_callback()"
        def callback(status, headers, exc_info=None):
            self.status_headers[:] = [status, headers]
            # print "objenc dbg, status headers 0", self.status_headers[0]
            # print "objenc dbg, status headers 1", self.status_headers[1]
            # Modify response 'headers'

        return callback

    def get_master_key(self, environ):
       m_key = environ['HTTP_X_OBJECT_META_MASTERKEY']
       del environ['HTTP_X_OBJECT_META_MASTERKEY']

       return m_key, environ


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def objenc_filter(app):
        return ObjEncMiddleware(app, conf)
    return objenc_filter
