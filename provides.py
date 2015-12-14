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

import json

from charms.reactive import RelationBase
from charms.reactive import hook
from charms.reactive import scopes


class HubProvides(RelationBase):
    scope = scopes.UNIT

    @hook('{provides:bigdata-hub}-relation-joined')
    def joined(self):
        conv = self.conversation()
        conv.set_state('{relation_name}.client')

    @hook('{provides:bigdata-hub}-relation-changed')
    def changed(self):
        conv = self.conversation()
        if conv.get_remote('registered-services'):
            conv.set_state('{relation_name}.provider')

    def registered_services(self):
        """
        Return a mapping of all registered services as a mapping of service
        names to lists of provider data for that service.
        """
        registry = {}
        for conv in self.conversations():
            services = json.loads(conv.get_remote('registered-services', '{}'))
            for name, data in services.items():
                registry.setdefault(name, []).append(data)
        return registry

    def provide_services(self, services):
        """
        Send the given provided services mapping to the connected remote
        services.

        The services mapping should be in the same format as returned by
        `registered_services`.
        """
        for conv in self.conversations():
            conv.set_remote('services', json.dumps(services))

    @hook('{provides:bigdata-hub}-relation-{departed,broken}')
    def departed(self):
        conv = self.conversation()
        conv.remove_state('{relation_name}.client')
        conv.remove_state('{relation_name}.provider')
