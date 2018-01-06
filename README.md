# Salt Runner Vault PKI

Server-side component of the Vault PKI certificate distribution system.

Run by the Salt master to communicate with Hashicorp Vault and issue
certificates for minions.  Enforces security on certificate signing
requests submitted by minions and applies overrides to validity periods,
and alternative names (SANs, IPSANs).

## Overview of Operation

Must be used in tandem with the [Vault PKI Formula](https://github.com/ripple/vault-pki-formula/).

This overview is of the *entire* server side operation of the Vault PKI
system.  The Vault PKI Formula provides crucial parts that must be present
for certificates to be issued.

Events from the servers perspective in order:
1. A Salt event is received from Vault PKI client on a minion requesting a
   certificate (with a CSR, and other data, embedded).
2. Vault PKI Reactor catches the event and starts the orchestrator with the
   data passed as arguments.
3. The orchestrator starts *this* Vault PKI runner to check the CSR, make
   changes, and get it signed by Vault.  This runner also writes the signed
   certificate back to the minion at the path specified in the initial event
   (see client documentation for directory structure).
4. If the runner exited without error the orchestrator runs a small state on
   the minion to activate the new certificate via the Vault PKI client.

# TODO(dmw) Diagrams are golden.

Things this runner *does not do*:
- Accept a CSR with a CN different from the minion ID.  Beware, minion IDs
  and hostnames can vary.
- Accept SANs or IPSANs from a CSR.
- Accept validity periods from a CSR.
- Handle unaccepted minions aka the bootstrapping trust issue.
- Deal in anyway with public certificate authorities.

What Vault PKI *can do*:
- Use Hashicorp Vault to automagically distribute certificates from a private CA.
- Automagically rotate said certificates. (initiated by the client)
- Set sensible (read 'short') default certificate validity periods and
  not worry about it.
- Configure SANs on a per host or hostname pattern basis.
- Enable IPSANs on a per host or hostname pattern basis (caveat: only
  the IP the minion id resolves to in DNS).
- Override validity periods on a per host or hostname pattern basis.
- Create scripts for your services to be kicked, informed, etc.  When a
  new certificate is activated. (client side)

## Requirements

- Salt master (sorry salt-ssh is not really possible)
- Hashicorp Vault
  - PKI backend enabled with your private CA loaded
  - AppRole + Policy for Vault PKI operatio
- Python packages:
  - cryptography [pypi](https://pypi.python.org/pypi/cryptography) [docs](https://cryptography.io/)
  - hvac [pypi](https://pypi.python.org/pypi/hvac/) [github](https://github.com/ianunruh/hvac)
