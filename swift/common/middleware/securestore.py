from swift.common.swob import Request, Response
from swift.common.utils import split_path
from cStringIO import StringIO
from hashlib import md5, sha1
from Crypto.Cipher import AES

class SecureStorage(object):

    """Swift3 secure storage midleware
	Uses a simple basic encryption """
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
            # 
            # Rely on webob than direct StringIO 
            # body = StringIO(env['wsgi.input'].read(length))
            #

            # print "acl: ",req.acl
            # print "body: ",req.body
            # print "body_file: ",req.body_file
            # print "content_length: ",req.content_length
            # print "query_string: ",req.query_string

            #
            # Encrypt the incoming file, using AES-256
            # - Encryption key static for the moment
            # - CFB mode, no initialization vector
            SECRET_KEY = b'Sixteen byte key'
            cipher_enc = AES.new(SECRET_KEY, AES.MODE_CFB)
            body = cipher_enc.encrypt(req.body)

            env['wsgi.input'] = StringIO(body)

            return self.app(env, start_response)

        elif obj and container and account and req.method == "GET":
            #
            # - Verify this is a file download request
            # - credentials ??
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
            # Decrypt the download file. 
            # - Decryption key static for the moment
            # - 
            SECRET_KEY = b'Sixteen byte key'
            cipher_dec = AES.new(SECRET_KEY, AES.MODE_CFB)
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
            # print "Obj: ", obj, " Container: ", container, " Account: ", account
            return self.app(env, start_response)

    def _sr_callback(self, start_response):
        print "sr_callback()"
        def callback(status, headers, exc_info=None):
            self.status_headers[:] = [status, headers]
            # print "status headers 0", self.status_headers[0]
            # print "status headers 1", self.status_headers[1]
            # Modify response 'headers'
            # start_response(status, headers, exc_info)

        return callback

def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""

    # print "secure storage filter factory"
    conf = global_conf.copy()
    conf.update(local_conf)

    def sec_filter(app):
        return SecureStorage(app, conf)

    return sec_filter
