# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import json
import socket
from uuid import uuid4
from ipaddress import ip_address

from charms.reactive import RelationBase
from charms.reactive import hook
from charms.reactive import scopes

from charmhelpers.core import hookenv


ALL = 'any-uuid'


class HubRequires(RelationBase):
    scope = scopes.GLOBAL

    def provided_services(self):
        """
        Returns a list of the names of all the services provided by the Hub.
        """
        conv = self.conversation()
        service_map = json.loads(conv.get_remote('services', '{}'))
        return service_map.keys()

    def providers(self, name):
        """
        Returns a list of all providers for a given service name.

        Each provider will be a collection of data with information
        about the service being provided.  It is guaranteed to contain at
        a minimum a ``uuid`` field and an ``ip`` field with the IP address
        that can be used to connect to that service.

        If no providers are registered for a service, an empty list will
        be returned.
        """
        conv = self.conversation()
        service_map = json.loads(conv.get_remote('services', '{}'))
        return service_map.get(name, [])

    def service(self, name):
        """
        Return one registered service provider information.

        The earliest registered provider of a service will be returned, but
        note that provider could unregister itself and be replaced with a new
        provider at any time.

        The provider will be a collection of data with information about the
        service being provided.  It is guaranteed to contain at a minimum a
        ``uuid`` field and an ``ip`` field with the IP address that can be
        used to connect to that service.

        If no providers are registered for a service, this will return ``None``.
        """
        providers = self.providers(name)
        return providers[0] if providers else None

    @hook('{requires:bigdata-hub}-relation-joined')
    def joined(self):
        conv = self.conversation()
        conv.set_state('{relation_name}.connected')

    @hook('{requires:bigdata-hub}-relation-changed')
    def changed(self):
        """
        Sets a general state "{relation_name}.available" if the list of
        services are available.

        For each service provided by the Hub, a state will be set of the form::

            {relation_name}.service.{service_name}

        The service-specific state will be removed if that service is
        unregistered from the Hub.
        """
        conv = self.conversation()
        conv.toggle_state('{relation_name}.available',
                          active=conv.get_remote('services') is not None)
        previous_services = set(conv.get_local('provided-services', []))
        current_services = set(self.provided_services())
        removed_services = previous_services - current_services
        added_services = current_services - previous_services
        for service in removed_services:
            conv.remove_state('{relation_name}.service.%s' % service)
        for service in added_services:
            conv.add_state('{relation_name}.service.%s' % service)
        conv.set_local('provided-services', current_services)

    @hook('{requires:bigdata-hub}-relation-{departed,broken}')
    def departed(self):
        conv = self.conversation()
        conv.remove_state('{relation_name}.connected')
        conv.remove_state('{relation_name}.available')

    def register_service(self, name, data):
        """
        Register a service.

        If the data does not contain an ``ip`` field, the local unit's
        ``private-address`` value will be resolved to an IP address and used.

        If the data does not contain a UUID, one will be created.  The UUID
        will be returned, either way.
        """
        conv = self.conversation(scopes.GLOBAL)
        services = conv.get_local('registered-services', {})
        data = dict(data)
        if 'uuid' not in data:
            data['uuid'] = uuid4()
        if 'ip' not in data:
            data['ip'] = local_ip()
        services.setdefault(name, []).append(data)
        conv.set_local('registered-services', services)
        conv.set_remote('registered-services', services)
        hookenv.log('Service {} registered with UUID {}'.format(name, data['uuid']))
        return data['uuid']

    def unregister_service(self, name, uuid=ALL):
        """
        Unregister a previously registered service.

        If a UUID is not given, all services provided by this charm for
        that service name will be unregistered.
        """
        conv = self.conversation(scopes.GLOBAL)
        services = conv.get_local('registered-services', {})
        if uuid is ALL:
            services.pop(name, None)
        else:
            for i, service in enumerate(services.get(name, [])):
                if service['uuid'] == uuid:
                    services[name].pop(i)
                    break
            if not services.get(name, []):
                services.pop(name, None)
        conv.set_local('registered-services', services)
        conv.set_remote('registered-services', services)


def local_ip():
    addr = hookenv.unit_get('private-address')
    try:
        ip_address(addr)
        return addr  # already IP
    except ValueError:
        try:
            ip_addr = socket.gethostbyname(addr)
            return ip_addr
        except socket.error as err:
            hookenv.log('Unable to resolve private IP: %s (will attempt to guess)' % addr, hookenv.ERROR)
            hookenv.log('%s' % err, hookenv.ERROR)
            # We have (very, very rarely) encountered unresolvable values for
            # private-addresses that still happen to contain the IP address
            # mixed in using underscores, dashes, or dots.  This is really
            # unreliable and doesn't work for IPv6 at all, but if we can't
            # resolve our own private-address, what else can we do?
            contains_ip_pat = re.compile(r'\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}')
            contained = contains_ip_pat.search(addr)
            if not contained:
                raise ValueError('Unable to resolve or guess IP from private-address: %s' % addr)
            return contained.groups(0).replace('-', '.').replace('_', '.')
