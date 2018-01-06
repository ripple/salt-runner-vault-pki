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
   changes to the CSR, and get it signed by Vault.  This runner also writes
   the signed certificate back to the minion at a path specified in the
   initial event (see client documentation for directory structure).
4. If the runner exited without error the orchestrator runs a small state on
   the minion to activate the new certificate via the Vault PKI client.

### TODO(dmw) Diagrams are golden.

### Things this runner *does not do*:
- Accept a CSR with a CN different from the minion ID.  Beware, minion IDs
  and hostnames can vary.
- Accept SANs or IPSANs from a CSR.
- Accept validity periods from a CSR.
- Handle unaccepted minions aka the bootstrapping trust issue.
- Deal in anyway with public certificate authorities.

### What Vault PKI *can do*:
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
  - AppRole + Policy for Vault PKI operation
- Python packages:
  - cryptography [pypi](https://pypi.python.org/pypi/cryptography) [docs](https://cryptography.io/)
  - hvac [pypi](https://pypi.python.org/pypi/hvac/) [github](https://github.com/ianunruh/hvac)

## Setup and Example Config

### Setup Hashicorp Vault

Setting up a production, or even persistent, Vault is well beyond the scope of
this document.  Please see Hashicorp's Vault documentation:
[Getting Started](https://www.vaultproject.io/intro/getting-started/install.html).

Especially relevant sections of Vault documentation:
- [PKI Secret Backend](https://www.vaultproject.io/docs/secrets/pki/index.html)
- [Auth Backend: AppRole](https://www.vaultproject.io/docs/auth/approle.html)

#### Development Vault Setup for Vault PKI

What follows is not even a temporary solution for running Vault *all data will
be lost* when the development Vault server stops.  Please consult the Vault
documentation for how to setup a persistent Vault, this setup is for demonstration
and early testing purposes only.  You have been warned.

In a separate terminal run:
```bash
vault server -dev
```

Setup your terminal environment to configure Vault.
```bash
export VAULT_ADDR=http://localhost:8200

export VAULT_TOKEN=$(cat .vault-token)

# or set VAULT_TOKEN to the 'Root Token' output in the dev Vault
# terminal window
```

Enable AppRole authentication + the PKI backend.
```bash
vault auth-enable approle
vault mount -path=pki pki

# tune the PKI backend to a max certificate TTL of 10 years
vault mount-tune -max-lease-ttl=87600h pki
```

Generate a Vault internal CA for testing (normally you may load your
private CA certificate, chain + key here).
```bash
vault write pki/root/generate/internal common_name=my-vault.example.com ttl=87600h
```

Create a PKI role to limit the kinds of CSRs signed/certificates issued.
```bash
vault write pki/roles/my-role allowed_domains=example.com allow_subdomains=true max_ttl=720h
```

Create a permissive policy for use by Vault PKI.
```bash
cat > vault-pki-policy.hcl << EOF
path "pki/*" {
  policy = "write"
}
EOF

vault policy-write vault_pki vault-pki-policy.hcl
```

Create an AppRole for Vault PKI to authenticate to Vault as.
```bash
vault write auth/approle/role/test-pki policies=vault_pki

#'test-pki' is the *name* of the role-id *but is not* the role-id,
# fetch and save the role-id for use in configuring the Salt master.
vault read auth/approle/role/test-pki/role-id
read ROLE_ID
<paste role-id here>

# a secret-id must be pared with the role-id to authenticate to Vault,
# generate one and save it for configuring the Salt master.
vault write -f auth/approle/role/test-pki/secret-id
read SECRET_ID
<paste secret-id here>
```

Now it's time to do a test to make sure everything is working before
adding the extra complexity of the Salt master + Vault PKI.  Make sure
to set your ROLE_ID + SECRET_ID variables as above.

Here we'll be using curl rather than Vault to avoid use of $VAULT_TOKEN.

Plan of attack:
- Authenticate via the new AppRole
- Issue a new certificate
```bash
cat > auth.json << EOF
{"role_id": "$ROLE_ID", "secret_id": "$SECRET_ID"}
EOF

curl -XPOST -d@auth.json $VAULT_ADDR/v1/auth/approle/login
# the field you want is 'client_token'

# or if you have 'jq' installed
curl -XPOST -d@auth.json $VAULT_ADDR/v1/auth/approle/login | jq '.auth.client_token'

# Set MY_TOKEN to the client token received
read MY_TOKEN
<paste client_token here>

# Finally let's issue a certificate -- a shortcut operation where Vault
# creates the CSR + signs it in one go (Vault PKI won't do this though):
curl -XPOST -H"X-Vault-Token: $MY_TOKEN" $VAULT_ADDR/v1/pki/issue/my-role \
    -d '{"common_name": "helloworld.example.com"}'
```
You should have received a JSON blob with a key, certificate and signing
chain.  If not please carefully review the steps above before proceeding.

### Install Vault PKI on the Salt Master

This section assumes you already have a SaltStack installation in place
and a functioning Salt master.  Please see the SaltStack documentation
for tips on setting up a production, or development Salt master.

Especially relevant sections of SaltStack documentation:
- [Installation](https://docs.saltstack.com/en/latest/topics/installation/index.html)
- [Configuring the Salt Master](https://docs.saltstack.com/en/latest/ref/configuration/master.html)
- [Compound Matchers](https://docs.saltstack.com/en/latest/topics/targeting/compound.html)
- [Reactor System](https://docs.saltstack.com/en/latest/topics/reactor/index.html)
- [Orchestrate Runner](https://docs.saltstack.com/en/latest/topics/orchestrate/orchestrate_runner.html#runner)

#### On the Salt Master
```bash
pip install PyYAML hvac

# Note: To install 'cryptography' you will need a full development environment,
# additional likely packages include: libffi-dev libssl-dev python-dev
# Or however those are named in your distribution.

pip install cryptography 

git clone https://github.com/ripple/salt-runner-vault-pki.git /srv/runners/salt-runner-vault-pki
git clone https://github.com/ripple/vault-pki-formula.git /srv/formulas/vault-pki-formula
```

#### Vault PKI Config

While the role-id of the AppRole for Vault PKI is generally accepted as
public -- and can be checked into source control.  The secret-id is not
and Vault PKI expects to find it in a file (hopefully somewhere safe).

For testing we can put it in a file in /etc production is up to your
security policies.
```bash
echo $SECRET_ID > /etc/my-vault-pki-secret-id-file
chmod 600 /etc/my-vault-pki-secret-id-file
```

Certificates on every minion is good.  But being able to vary certificate
validity periods add add SANs is even better.  Here is how to create an
overrides file for those lucky minions.

Quick notes on the syntax:
- Standard YaML syntax
- Top level keys are patterns/hostnames
- Patterns are done using SaltStack compound matching
- Overrides available are 'ttl', 'alt_names' and 'ipsans'
  - 'ttl' must be specified in GoLang Duration syntax (hours are the largest
    unit, so you should only need integer hours e.g. 72h, 24h, 720h, 8760h).
  - 'alt_names' must be a list of fully qualified domains to be used as
    subject alternative names (SANs).
  - 'ipsans' is a boolean, when set to true the minion's id is looked up
    in DNS and the resulting IP address is set in IPSANs.

```bash
cat > /srv/salt/vault_pki_overrides.yml << EOF
'E@www[0-9].example.com':
  alt_names:
    - www.example.com
    - example.com
    - blog.example.com

'my-vault.example.com':
  ttl: 8760h

'something.example.com':
  ipsans: True
EOF
```

The overrides file is loaded fresh during every run. The Salt
master does not need to be restarted to pick up changes.

#### Salt Master Config Editing

These are the bits that specifically need to be in place for Salt master
to work with Vault PKI.  This is *not* a full salt master config and must
be adapted to your particular situation.

```yaml
# some stuff up here about listening ports, workers, logs, etc.

fileserver_backend:
  - roots

pillar_roots:
  base:
    - /srv/pillar

file_roots:
  base:
    - /srv/salt
    - /srv/formulas/vault-pki-formula

runner_dirs:
  - /srv/runners/salt-runner-vault-pki

vault_pki_runner:
    vault_secret_id_file: /etc/my-vault-pki-secret-id-file
    url: http://localhost:8200
    pki_path: /v1/pki/sign/my-role
    role_id: # PASTE $ROLE_ID HERE
    vault_pki_overrides_file: salt://vault_pki_overrides.yml
    validity_period: 720h

reactor:
  - request/sign:
    - salt://reactor/vault_pki_reactor.sls
```

Always restart the Salt master after editing its config file to ensure
changes are picked up.
```bash service salt-master restart```

### Putting It All Together

Setup a minion using the 'cert' state:
```bash
salt 'my-minion.example.com' state.apply cert
```

Then check to see if the certificate arrived (it may take up to 10-15 seconds):
```bash
salt 'my-minion.example.com' cmd.run 'vault_pki list'
# or
salt 'my-minion.example.com' cmd.run 'ls -l /etc/vault_pki/live/$(hostname)/'
```

If the certificate hasn't arrived check the Salt master logs.  The full CSR
PEM block should be logged, overrides mentioned and a runner return block
(or error) should be present as well.
```bash less /var/log/salt/master```

*That's it!*  Your minion will check the certificate daily and request
a new one when it's 50% through the validity period.

See the [Vault PKI formula documentation](https://github.com/ripple/vault-pki-formula/)
for more details about client operation.
