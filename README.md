openstack-sec-storage
=====================

An attempt to bring in security to the current object storage of OpenStack (swift). Mostly by intercepting requests to the proxy, by creating custom swift filters.

The following middlewares for swift are added:
* Basic encryption filter
* ..

Usage
========

* Add the filter details to setup.py

 <code>'securestore=swift.common.middleware.securestore:filter_factory',</code>
* Edit /etc/swift/proxy-server.conf

 <code>[pipeline:main]
 pipeline = healthcheck cache securestore swauth proxy-server

 [filter:securestore]
 use = egg:swift#securestore
 cache_servers = 127.0.0.1:8088</code>

* Install and reload the proxy server

 <code>python setup.py build; python setup.py install; </code>restart proxy server
