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


class PrivateKeyError(Exception):
    pass


class PrivateKey(object):

    def __init__(self, module):
        self.size = module.params['size']
        self.state = module.params['state']
        self.name = module.params['name']
        self.type = module.params['type']
        self.replace = module.params['replace']
        self.directory = module.params['directory']

   
    def generate(self):
        """Generate a keypair."""

        if self.replace is False and os.path.exists('%s/%s' % (self.directory, self.name)):
            return

        if os.path.isdir(self.directory) is False:
            raise PrivateKeyError('The specified directory (%s) does not exist' % self.directory)

        self.privatekey = crypto.PKey()
        crypto_type = crypto.TYPE_RSA if self.type == 'RSA' else crypto.TYPE_DSA
        self.privatekey.generate_key(crypto_type, self.size)

        with open('%s/%s' % (self.directory, self.name), 'w') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self.privatekey))


    def remove(self):
        """Remove the private key from the filesystem."""

        try:
            os.remove('%s/%s' % (self.directory, self.name))
        except OSError:
            pass
        

def main():

    module = AnsibleModule(
        argument_spec = dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            name=dict(required=True, type='str'),
            size=dict(default=4096, type='int'),
            type=dict(default='RSA', choices=['RSA', 'DSA'], type='str'),
            replace=dict(default=False, type='bool'),
            directory=dict(default=None, required=True, type='str'),
        )
    )

    private_key = PrivateKey(module)

    if private_key.state == 'present':
        private_key.generate()
    else:
        private_key.remove()

    module.exit_json(changed=True)



if __name__ == '__main__':
    main()
