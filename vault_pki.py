# -*- coding: utf-8 -*-
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

"""


"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'Daniel Wilcox (dwilcox@ripple.com)'

import logging
import os
import six

import hvac

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from salt import client as salt_client
from salt import config as salt_config


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


def get_user_id(source="~/.vault-id"):
    """ Reads a UUID from file (default: ~/.vault-id)

    TODO: REFACTOR ME OUT
    """
    source = os.path.abspath(os.path.expanduser(source))
    user_id = None

    # pylint: disable=invalid-name
    if os.path.isfile(source):
        fd = open(source, "r")
        user_id = fd.read().strip()
        fd.close()

    return user_id


def _verify_csr_ok(fqdn, csr_pem_data):
    csr_ok = False
    csr = x509.load_pem_x509_csr(csr_pem_data, default_backend())
    name_oid = x509.oid.NameOID.COMMON_NAME
    names = csr.subject.get_attributes_for_oid(name_oid)
    log.info('CSR has names {} for minion {}'.format(names, fqdn))
    if len(names) == 1:
        common_name = names[0].value
        if six.u(fqdn) == common_name:
            csr_ok = True
    return csr_ok


def _get_vault_connection(config):
    try:
        conn = hvac.Client(url=config.get('url'))
        user_id_file = config.get('vault_user_id_file')
        if user_id_file:
            user_id = get_user_id(source=user_id_file)
        else:
            user_id = get_user_id()
        conn.auth_app_id(config.get('app_id'), user_id)
    except hvac.exceptions.VaultError as err:
        log.error('Vault error: {}'.format(err))
        return None
    return conn


def _write_certs_to_minion(fqdn, dest_path, cert_data):
    client = salt_client.LocalClient(SALT_MASTER_CONFIG)
    cert_path = os.path.join(dest_path, CERT_FILENAME)
    fullchain_path = os.path.join(dest_path, FULLCHAIN_FILENAME)
    cert = cert_data['certificate']
    fullchain = '\n'.join([cert, cert_data['issuing_ca']])
    write_cert = client.cmd(
        fqdn,
        'file.write',
        [cert_path, cert]
    )
    write_fullchain= client.cmd(
        fqdn,
        'file.write',
        [fullchain_path, fullchain]
    )
    return True


def main(**kwargs):
    """Ferries CSRs to vault to be signed and returns them.

    necessary steps:
        - verify CSR is valid, aka matches hostname, has
          expiration, etc.
        - open connection to vault and authenticate
        - send CSR to vault to be signed and retrieve cert
        - use version number to write cert and chain into
          proper place on minion
        - issue high state on minion (need to modify states
          that use cert to watch the symlink for changes, or
          pass pillar var that reload is needed)
    """
    fqdn = kwargs.get('host')
    csr = kwargs.get('csr')
    dest_cert_path = kwargs.get('path')

    log.info('Received CSR for {}'.format(fqdn))
    full_config = salt_config.api_config(SALT_MASTER_CONFIG)
    config = full_config.get('vault_pki_runner')
    if _verify_csr_ok(fqdn, csr):
        vault_conn = _get_vault_connection(config)
        validity_period = config.get('validitiy_period',
                                     CERT_VALIDITY_PERIOD)
        signing_params = {'alt_names': six.u(fqdn),
                          'csr': csr,
                          'common_name': six.u(fqdn),
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
        write_ok = _write_certs_to_minion(fqdn, dest_cert_path, cert_data)
        if not write_ok:
            log.error('Error writing cert to minion!')
    else:
        raise SigningError('CSR missing or invalid, check fqdn.')
