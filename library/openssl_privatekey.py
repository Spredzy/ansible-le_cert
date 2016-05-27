#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from ansible.module_utils.basic import *
from OpenSSL import crypto

import os

DOCUMENTATION = '''
---
module: openssl_privatekey
author: "Yanis Guenane (@Spredzy)"
version_added: "2.2"
short_description: Generate SSL private keys
description:
    - "This module allows one to (re)generates SSL private keys. It uses the
       pyOpenSSL python library to interact with openssl. One can generate
       either RSA or DSA private keys."
requirements:
    - "python-pyOpenSSL"
options:
    state:
        required: false
        default: "present"
        choices: [ present, absent ]
        description:
            - Whether the private key should exist or not, , taking action if the state is different from what is stated.
    name:
        required: true
        description:
            - Name of the generated SSL private key
    size:
        required: false
        default: 4096
        description:
            - Size of the SSL key go generate
    type:
        required: false
        default: "RSA"
        choices: [ RSA, DSA ]
        description:
            - The algorithm to use to generate the SSL private key
    force:
        required: false
        default: False
        choices: [ True, False ]
        description:
            - Should the key be forced force by this ansible module
    path:
        required: true
        description:
            - Name of the folder in which the generated SSL private key will be written
'''

EXAMPLES = '''
# Generate an OpenSSL private key with the default values (4096 bits, RSA)
- openssl_privatekey: name=ansible.com.pem path=/etc/ssl/private

# Generate an OpenSSL private key with a different size (2048 bits)
- openssl_privatekey: name=ansible.com.pem path=/etc/ssl/private size=2048

# Force regenerate an OpenSSL private key if it already exists
- openssl_privatekey: name=ansible.com.pem path=/etc/ssl/private force=True

# Generate an OpenSSL private key with a different algorithm (DSA)
- openssl_privatekey: name=ansible.com.pem path=/etc/ssl/private type=DSA
'''

RETURN = '''
size:
    description: Size of the SSL private key
    returned:
        - changed
        - success
    type: integer
    sample: 4096
type:
    description: Algorithm used to generate the SSL private key
    returned:
        - changed
        - success
    type: string
    sample: RSA
privatekey:
    description: Path to the generated SSL private key
    returned:
        - changed
        - success
    type: string
    sample: /etc/ssl/private/ansible.com.pem
'''

class PrivateKeyError(Exception):
    pass

class PrivateKey(object):

    def __init__(self, module):
        self.size = module.params['size']
        self.state = module.params['state']
        self.name = module.params['name']
        self.type = module.params['type']
        self.force = module.params['force']
        self.path = module.params['path']
        self.changed = True

   
    def generate(self):
        """Generate a keypair."""

        if self.force is False and os.path.exists('%s/%s' % (self.path, self.name)):
            self.changed = False
            return

        self.privatekey = crypto.PKey()
        crypto_type = crypto.TYPE_RSA if self.type == 'RSA' else crypto.TYPE_DSA

        try:
            self.privatekey.generate_key(crypto_type, self.size)
            with open('%s/%s' % (self.path, self.name), 'w') as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self.privatekey))
        except TypeError:
            raise PrivateKeyError()
        except ValueError:
            raise PrivateKeyError()


    def remove(self):
        """Remove the private key from the filesystem."""

        try:
            os.remove('%s/%s' % (self.path, self.name))
        except OSError:
            pass


    def dump(self):
        """Serialize the object into a dictionnary."""

        result = {
            'size': self.size,
            'type': self.type,
            'privatekey': '%s/%s' % (self.path, self.name),
            'changed': self.changed,
        }

        return result
        

def main():

    module = AnsibleModule(
        argument_spec = dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            name=dict(required=True, type='str'),
            size=dict(default=4096, type='int'),
            type=dict(default='RSA', choices=['RSA', 'DSA'], type='str'),
            force=dict(default=False, type='bool'),
            path=dict(required=True, type='str'),
        )
    )

    if os.path.isdir(module.params['path']) is False:
        module.fail_json(name=module.params['path'], msg='The directory %s does not exist' % module.params['path'])

    private_key = PrivateKey(module)
    if private_key.state == 'present':
        try:
            private_key.generate()
        except PrivateKeyError as e:
            module.fail_json(name=module.params['path'], msg='An error occured while generation the SSL private key')
    else:
        private_key.remove()

    result = private_key.dump()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
