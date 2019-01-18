# -*- coding: utf-8 -*-
#
#   Copyright 2018 Ripple Labs, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

"""Salt runner module to sign certificates with the Vault PKI backend.

Invoked by the vault_pki orchestrator which provides the necessary
keyword arguments to main(). (and follow-up steps after the runner exits)

At a glance this runner takes a minion fully-qualitified domain name
(FQDN), a certificate signing request (CSR), and a destination path on
the minion.

The CSR is verified, by way of checking the FQDN and the desired CN of
the certificate, and the configured validity period is set as configured
in the Salt master config file.

It then makes a request to a configured Vault instance using AppRole
authentication and gets the CSR signed.

The resulting certificate, and a full chain (certificate appended with
the CA's certificate), are written back to the minion at the given
destination path.


Breakdown of the runner's steps:
    - verify CSR is valid, aka CN matches hostname, has
      expiration, etc.
    - apply overrides to CSR for SANs, IPSANs, TTL.
    - open connection to vault and authenticate
    - send CSR to vault to be signed and retrieve cert
    - use version number to write cert and chain into
      proper place on minion

Steps that follow -- but the runner doesn't do:
    - the orchestrator runs vault_pki activate $version_number
    - as part of activation, the vault_pki client will run post-activate
      scripts to inform servers a new certificate is in place
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'Daniel Wilcox (dmw@ripple.com)'

import json
import logging
import os
import six
import socket
import subprocess
import yaml

import hvac

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from salt import client as salt_client
from salt import config as salt_config
from salt import minion as salt_minion
from salt.utils import minions as salt_minion_utils


CERT_FILENAME = 'cert.pem'
FULLCHAIN_FILENAME = 'fullchain.pem'

CERT_VALIDITY_PERIOD = '{:d}h'.format(30 * 24)

SALT_MASTER_CONFIG = '/etc/salt/master'

default_level = logging.INFO
log = logging.getLogger(__file__)
log.setLevel(default_level)
log_formatter = logging.Formatter(('%(asctime)s - %(name)s - %(levelname)s'
                                   ' - %(message)s'))
log_handler = logging.StreamHandler()
log_handler.setFormatter(log_formatter)
log_handler.setLevel(default_level)
log.addHandler(log_handler)


class ConfigError(Exception):
    """Error to raise if config is invalid or incomplete."""
    pass


class SigningError(Exception):
    """Error for issues with the CSR or signing operation."""
    pass


def get_secret_id(source="~/.vault-id"):
    """ Reads a vault user-id (UUID) from a file."""
    source = os.path.abspath(os.path.expanduser(source))
    user_id = None

    # pylint: disable=invalid-name
    if os.path.isfile(source):
        fd = open(source, "r")
        user_id = fd.read().strip()
        fd.close()

    return user_id


def _get_host_overrides(config, hostname):
    """Get host specific parameters from a vault_pki_overrides file.

    Args: config a in-memory representation of /etc/salt/master.
    Returns: A dictionary of Vault compatible keys for PKI signing.
    """
    override_file = config.get('vault_pki_overrides_file')
    if not override_file:
        return {}
    opts = __opts__.copy()
    opts['file_client'] = 'local'
    minion = salt_minion.MasterMinion(opts)
    overrides_filepath = minion.functions['cp.cache_file'](override_file)
    try:
        with open(overrides_filepath, 'r') as f:
            override_data = yaml.safe_load(f.read())
    except (IOError, yaml.YAMLError):
        log.warning(
            'vault_pki_overrides_file is unreadable or not YaML, skipping.'
        )
        return {}
    # Check hostname against minions matching the pattern + return overrides.
    ckminions = salt_minion_utils.CkMinions(__opts__)
    for pattern, values in override_data.items():
        minions =  ckminions.check_minions(pattern, 'compound')
        if 'minions' in minions:
            # In Salt 2018 this is now in a dictionary
            minions = minions['minions']
        if hostname in minions:
            return values
    return {}


def _verify_csr_ok(fqdn, csr_pem_data):
    """Confirms CSR contains only the FQDN of requesting minion.

    Makes assumption that CN will contain hostname despite SAN
    becoming much more common.  That plus the ability to verify
    some outside source for potential extra SANs would be helpful.
    """
    # TODO(dmw) Needs more thorough logging.
    csr_ok = False
    csr = x509.load_pem_x509_csr(str(csr_pem_data), default_backend())
    # TODO(dmw) Check subject alternative name (SAN) is valid as well.
    name_oid = x509.oid.NameOID.COMMON_NAME
    names = csr.subject.get_attributes_for_oid(name_oid)
    log.info('CSR has names {} for minion {}'.format(names, fqdn))
    log.info('CSR ({}): "{}"'.format(fqdn, csr_pem_data))
    if len(names) == 1:
        common_name = names[0].value
        # Backwards compatbile Salt 2018 fix
        fqdn = fqdn if type(fqdn) == unicode else six.u(fqdn)
        if fqdn == common_name:
            csr_ok = True
    return csr_ok


def _get_vault_connection(config):
    """Opens a connection to vault and returns it.

    Uses configuration from the salt master config file for the vault
    URL, role-id and secret-id file.
    """
    try:
        conn = hvac.Client(url=config.get('url'))
        secret_id_file = config.get('vault_secret_id_file')
        if secret_id_file:
            secret_id = get_secret_id(source=secret_id_file)
        else:
            secret_id = get_secret_id()
        result = conn.auth_approle(config.get('role_id'), secret_id)
        # Required until https://github.com/ianunruh/hvac/pull/90
        # is merged, due in hvac 0.3.0
        conn.token = result['auth']['client_token']
    except hvac.exceptions.VaultError as err:
        log.error('Vault error: {}'.format(err))
        return None
    return conn


def _send_certs_to_minion(fqdn, dest_path, cert_data):
    sock_dir = '/var/run/salt/master'
    cert_path = os.path.join(dest_path, CERT_FILENAME)
    fullchain_path = os.path.join(dest_path, FULLCHAIN_FILENAME)
    cert = cert_data['certificate']
    ca_chain = '\n'.join(cert_data['ca_chain'])
    fullchain = '\n'.join([cert, ca_chain])
    cert_info = {"cert": cert, "cert_path": cert_path, "fullchain": fullchain, "fullchain_path": fullchain_path}
    payload = json.dumps({"data": cert_info})
    tag = 'request/certificate'
    send_event = subprocess.check_output("salt '{}' event.fire '{}' '{}'".format(fqdn, payload, tag), shell=True)

    return True


def _write_certs_to_minion(fqdn, dest_path, cert_data):
    """Writes signed cert back to requesting minion at specified path.

    Given a destination path on the minion, write both the signed cert
    and a full chain (cert + CA cert) to it using the standard filenames.
    """
    client = salt_client.LocalClient(SALT_MASTER_CONFIG)
    cert_path = os.path.join(dest_path, CERT_FILENAME)
    fullchain_path = os.path.join(dest_path, FULLCHAIN_FILENAME)
    cert = cert_data['certificate']
    ca_chain = '\n'.join(cert_data['ca_chain'])
    fullchain = '\n'.join([cert, ca_chain])
    write_cert = client.cmd(
        fqdn,
        'file.write',
        [cert_path, cert]
    )
    write_fullchain = client.cmd(
        fqdn,
        'file.write',
        [fullchain_path, fullchain]
    )

    # TODO(dmw) Figure out odd client.cmd rc's and error if needed.
    return True


def main(**kwargs):
    """Ferries CSR to Vault to be signed and writes back returned cert.

    Recieves keyword arguments from invocation by the vault_pki
    orchestrator.  Must include:
        host: string FQDN of the requesting minion
        csr: string PEM encoded certificate signing request (CSR)
        path: string destination path on the minion to write back certs
    """
    fqdn = kwargs.get('host')
    csr = kwargs.get('csr')
    dest_cert_path = kwargs.get('path')

    log.info('Received CSR for {}'.format(fqdn))
    full_config = salt_config.api_config(SALT_MASTER_CONFIG)
    config = full_config.get('vault_pki_runner')
    if _verify_csr_ok(fqdn, csr):
        vault_conn = _get_vault_connection(config)
        #TODO(dmw) Re-factor to slim main() and handle defaults better.
        host_overrides = _get_host_overrides(config, fqdn)
        if host_overrides.get('ttl'):
            validity_period = host_overrides['ttl']
        else:
            validity_period = config.get('validity_period',
                                         CERT_VALIDITY_PERIOD)
        alt_names = set()
        if host_overrides.get('alt_names'):
            for name in host_overrides['alt_names']:
                # Backwards compatbile Salt 2018 fix
                name = name if type(name) == unicode else six.u(name)
                alt_names.add(name)
            log.info('Sending Vault signing with extra SANs: {}'.format(
                ','.join(alt_names)))
        ip_list = []
        if host_overrides.get('ip_sans'):
            try:
                _, _, ip_list = socket.gethostbyname_ex(fqdn)
                log.info('Vault signing with IPSANs: {}'.format(
                    ', '.join(ip_list)))
            except socket.gaierror:
                log.warning('Failed to lookup FQDN "{}" for IPSANs'.format(
                    fqdn))
        # Backwards compatible Salt 2018 fix
        fqdn = fqdn if type(fqdn) == unicode else six.u(fqdn)
        signing_params = {'alt_names': ','.join(alt_names),
                          'ip_sans': ','.join(ip_list),
                          'csr': csr,
                          'common_name': fqdn,
                          'format': 'pem',
                          'ttl': validity_period}
        pki_path = config.get('pki_path')
        if not pki_path:
            raise ConfigError('Missing required parameter "pki_path"')
        try:
            vault_response = vault_conn._post(pki_path, json=signing_params)
        except hvac.exceptions.VaultError as err:
            log.error('Vault error: {}'.format(err))
            raise SigningError('Error signing from vault!')
        cert_data = vault_response.json()['data']
        send_ok = _send_certs_to_minion(fqdn, dest_cert_path, cert_data)
        if not send_ok:
            log.error('Error sending cert to minion!')
        else:
            log.info('Sent new certificate to {}'.format(fqdn))
    else:
        raise SigningError('CSR missing or invalid, check fqdn.')
