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
import urllib


class CertError(Exception):
    pass

class Cert(object):
    """ """

    def __init__(self, module):
        self.state = module.params['state']
        self.type = module.params['type']
        self.algo = module.params['algo']
        self.name = module.params['name']
        self.account_key = module.params['account_key']
        self.size = module.params['size']
        self.subjectAltName = module.params['subjectAltName']
        self.directory = module.params['directory']
        self.privatekey = None
        self.request = None
        self.intermediate_pem_url = 'https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem'

        self.subject = {
          'C': module.params['countryName'],
          'ST': module.params['stateOrProvinceName'],
          'L': module.params['localityName'],
          'O': module.params['organizationName'],
          'OU': module.params['organizationalUnitName'],
          'CN': module.params['commonName'],
          'emailAddress': module.params['emailAddress'],
        }

        if self.subject['CN'] is None:
            self.subject['CN'] = self.name


    def get_intermediate_certificate(self):
        """Retrieve the intermediate Let's Encrypt certificate"""

        pem_file = self.intermediate_pem_url.split('/')[-1]
        if os.path.exists('%s/pem/%s' % (self.directory, pem_file)) is False:
            intermediate_pem = urllib.urlopen(self.intermediate_pem_url).read()
            with open('%s/pem/%s' % (self.directory, pem_file), 'w') as f:
                f.write(intermediate_pem)

    def generate_privatekey(self):
        """Generate the private key for this domain name."""

        if os.path.isdir(self.directory) is False:
            raise CertError('The specified directory (%s) does not exist' % self.directory)

        self.privatekey = crypto.PKey()
        crypto_type = crypto.TYPE_RSA if self.type == 'RSA' else crypto.TYPE_DSA
        self.privatekey.generate_key(crypto_type, self.size)

        with open('%s/private/%s.pem' % (self.directory, self.name), 'w') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self.privatekey))


    def generate_csr(self):
        """Generate the certificate signing request."""

        if os.path.isdir(self.directory) is False:
            raise CertError('The specified directory (%s) does not exist' % self.directory)

        req = crypto.X509Req()
        req.set_version(3)
        subject = req.get_subject()
        for (key,value) in self.subject.items():
            if value is not None:
                setattr(subject, key, value)

        # if self.subjectAltName is not None:
        #    req.add_extensions([crypto.X509Extension("subjectAltName", False, self.subjectAltName)])

        req.set_pubkey(self.privatekey)
        req.sign(self.privatekey, self.algo)
        self.request = req
        
        with open('%s/csr/%s.csr' % (self.directory, self.name), 'w') as f:
            f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, self.request))


    def generate_challenge_dir(self):
        """Generate the challenge directory."""

        if os.path.isdir('%s/challenges/%s' % (self.directory, self.name)) is False:
            os.mkdir('%s/challenges/%s' % (self.directory, self.name))


    def sign(self):
        """Retrieve the certificate from the Let's Encrypt servers."""

        # TODO (spredzy): Ugly part should be done directly by interacting
        # with the acme protocol through python-acme
        os.system('acme-tiny --account-key %s/private/%s --csr %s/csr/%s.csr --acme-dir %s/challenges/%s > %s/certs/%s.crt' %
                 (self.directory, self.account_key, self.directory, self.name, self.directory, self.name, self.directory, self.name))

        filenames = [
            '%s/certs/%s.crt' % (self.directory, self.name),
            '%s/pem/%s' % (self.directory, self.intermediate_pem_url.split('/')[-1])
        ]
        with open('%s/pem/%s.pem' % (self.directory, self.name), 'w') as f:
            for fname in filenames:
                with open(fname) as infile:
                    f.write(infile.read())


def main():
    module = AnsibleModule(
        argument_spec = dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            type=dict(default='RSA', choices=['RSA', 'DSA'], type='str'),
            name=dict(required=True, type='str'),
            account_key=dict(required=True, type='str'),
            size=dict(default=4096, type='int'),
            algo=dict(default='sha256', type='str'),
            subjectAltName=dict(default=None, aliases=['subjectAltName'], type='str'),
            directory=dict(default=None, required=True, type='str'),
            countryName=dict(default=None, aliases=['C'], type='str'),
            stateOrProvinceName=dict(default=None, aliases=['ST'], type='str'),
            localityName=dict(default=None, aliases=['L'], type='str'),
            organizationName=dict(default=None, aliases=['O'], type='str'),
            organizationalUnitName=dict(default=None, aliases=['OU'], type='str'),
            commonName=dict(default=None, aliases=['CN'], type='str'),
            emailAddress=dict(default=None, type='str'),
        )
    )

    cert = Cert(module)

    cert.get_intermediate_certificate()
    cert.generate_privatekey()
    cert.generate_csr()
    cert.generate_challenge_dir()
    cert.sign()

    module.exit_json(changed=True)


if __name__ == "__main__":
    main()
