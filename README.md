# Overview

This interface layer handles the communication with Big Data Hub registry service.


# Usage

## Requires

Charms connecting to the Big Data Hub can require this interface.

This interface layer will set the following states, as appropriate:

  * `{relation_name}.connected`   The relation to the Big Data Hub has been
    established, though the service list may not be available yet.  If you
    are providing a service, you can use the following methods to manage your
    service registrations:
      * `register_service(name, data)`
      * `unregister_service(name, uuid=ALL)`

  * `{relation_name}.available`   The list of provided services is available
    from the Hub.  You can use the following methods to get information about
    the provided services:
      * `provided_services()`  The names of all services provided.
      * `providers(name)`  All providers for a given service name.
      * `service(name)`  The earliest registered provider for a given service.

  * `{relation_name}.service.{service_name}`  The given service name has been
    provided.  You can use the areforementioned methods to get information
    about the service.

For example, let's say that a charm wants to use HDFS.  It can connect to the
Big Data Hub and use the following code to wait for HDFS:

```python
@when('flume.installed', 'hub.service.hdfs')
def hdfs_ready(hub):
    hdfs = hub.service('hdfs')
    flume.configure_hdfs(hdfs['ip'], hdfs['port'])
    flume.start()
```

A charm providing a NameNode could then use the following to register it:

```python
@when('hub.connected', 'namenode.ready')
def register_namenode(hub):
    namenode = get_namenode_info()
    hub.register_service('hdfs', {
        'port': namenode['port'],
        'webhdfs_port': namenode['webhdfs_port'],
    })
```

The data provided for a service will vary depending on the service, but is
guaranteed to contain an IP address and a UUID.  If the IP address is not
included in the data used to register the service, the `private-address` for
the local unit will be resolved and used.  If the UUID is not included, one
will be generated.


## Provides

A charm providing this interface is providing the Big Data Hub service.

This interface layer will set the following states, as appropriate:

  * `{relation_name}.client` One or more clients have connected.  The charm
    can tell the client about the registered services using:
      * `provide_services(services)`

  * `{relation_name}.provider` One or more services have been registered as
    being provided.  The charm can get the mapping of provided services with:
      * `registered_services()`

Example:

```python
@when('hub.client', 'hub.provider')
def provide_services(clients, providers):
    clients.provide_services(providers.registered_services())
```


# Contact Information

- <bigdata@lists.ubuntu.com>
