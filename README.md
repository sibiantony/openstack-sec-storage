openstack-sec-storage
=====================

An attempt to bring in security to the current object storage of OpenStack (swift). Mostly by intercepting requests to the proxy, by creating custom swift filters.
The easiest approach would be to have the user/client encrypt it themselves. However, the time/effort involved in securing the data would want the client to trust a 3rd party (in this case the storage provider itself).

The encryption is performed synchronously, as an asynchronous encryption might break the swift replication process and would leave the system inconsistent.
Moreover, the data will be stored unencrypted for a brief period of time if an asynchronous encryption is attempted. The cost of a synchronous encryption
is high in terms of performance, especially when there is no hardware acceleration for the encryption process. There will be some performance study using the filters.

There are 3 different filters written for swift
* A basic encryption filter
* A filter using a centralized database with shadowed passwords and encrypted keys.
* A distributed encryption filter, wherein the encryption is done by the object servers.

The code/examples in here are written as part of an academic research. Production usage is highly discouraged. Use at your own risk.

Basic encryption filter
=======================
`Files : swift/common/middleware/securestore.py`
A very simple encryption middleware. Generates the key at runtime based on the swift hashpath, and is quite predictable. 
The keys could be based on user password or a per file key. In which case, it is necessary to chain the keys properly so that it respects the ACLs used by swift. 
Most importantly, the tenant->container->object structure. 

Centralized database filter
===========================
`Files : swift/common/middleware/securedb_auth.py, swift/common/middleware/securedb_enc.py`
Uses a database (Mysql in the implementation) to store the user credentials and encrypted keys. There are 2 parts to this : An authentication filter and an encryption filter. The authentication filter is a reimplementation of the default tempauth filter. It generates
a token and keeps a mapping from the token to the encryption key. For simplicity, the mapping is maintained in the same database, and the keys are encrypted using the token.
The second part, the encryption filter, decrypts the keys from the database and uses to encrypt the actual files.

This approach follows a chained encryption, thereby cryptographically securing the ACLs used by swift. The account keys are secured by a user key, which in turn is 
secured by a password key. The password key itself is a secure hash of the user password.  The db creation, user registration can be done using the utility scripts under `utils`.
There are some configurables for the database used, and has to be added to your filter configuration.

`[filter:securedb-enc]`

`use = egg:swift#securedb_enc`

`mdb_host = localhost`

`mdb_user = openstack`

`mdb_pass = openstack`

`mdb_db   = swiftauth`

Some of the problems associated with this approach are that : weaker mapping from tokens to keys, a loaded proxy server and probably scalability issues with a central db.

Distributed encryption filter
=============================
`Files : swift/common/middleware/objenc_proxy.py, swift/common/middleware/objenc.py`
The idea was to free the proxy from becoming a bottleneck by spending time in computation. Also, by default swift performs a lot better if we distribute the storage in multiple containers/objects. i.e each time a new hashpath will
be generated for these and probably will be serviced by a new object server. By distributing the computation (encryption) some performance improvements are expected upon multiple concurrent requests.

This is a filter for the swift object server, so add the filter details to each of the object server configuration. The filter uses a unique key for each file, and a master key to store the per-file-key encrypted.
There is redundant encryption process at each object server, but it frees the proxy from the computation.

Usage
========
The first two approaches above are filters written for the proxy server. In the distributed encryption filter, the objenc_proxy is meant for the proxy-server and objenc is for the object server. Modify the configuration files accordingly.
Detailed below is how the filters are used in general with swift. 

* Add the filter details to setup.py

`'securestore=swift.common.middleware.securestore:filter_factory',`

* Edit /etc/swift/proxy-server.conf (object-server.conf in case the filter is for object servers)

`[pipeline:main]`

`pipeline = healthcheck cache securestore swauth proxy-server`

`[filter:securestore]`

`use = egg:swift#securestore`

`cache_servers = 127.0.0.1:8088`

* Install and reload the proxy server (object servers if a filter for object server)

`python setup.py build; python setup.py install;` restart proxy/object servers
