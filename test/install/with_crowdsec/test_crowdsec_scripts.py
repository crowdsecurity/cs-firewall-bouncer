import os
import pexpect
import re
import yaml

import pytest
from pytest_cs.lib import cscli, text

BOUNCER = "crowdsec-firewall-bouncer"
CONFIG = f"/etc/crowdsec/bouncers/{BOUNCER}.yaml"


@pytest.mark.systemd_debug(BOUNCER)
@pytest.mark.dependency()
def test_install_crowdsec(project_repo, bouncer_binary, must_be_root):
    c = pexpect.spawn(
        '/usr/bin/sh', ['scripts/install.sh'],
        encoding='utf-8',
        cwd=project_repo
    )

    c.expect(f"Installing {BOUNCER}")
    c.expect("iptables found")
    c.expect("nftables found")
    c.expect(re.escape("Found nftables (default) and iptables, which firewall "
                       "do you want to use (nftables/iptables)"))
    c.sendline('fntables')
    c.expect("cscli found, generating bouncer api key.")
    c.expect("API Key: (.*)")
    api_key = text.nocolor(c.match.group(1).strip())
    # XXX: what do we expect here ?
    c.wait()
    assert c.terminated
    # XXX: partial configuration, the service won't start
    # assert c.exitstatus == 0

    # installed files
    assert os.path.exists(CONFIG)
    assert os.stat(CONFIG).st_mode & 0o777 == 0o600
    assert os.path.exists(f'/usr/local/bin/{BOUNCER}')
    assert os.stat(f'/usr/local/bin/{BOUNCER}').st_mode & 0o777 == 0o755

    # configuration check
    with open(CONFIG) as f:
        y = yaml.safe_load(f)
        assert y['api_key'] == api_key

    # the bouncer is registered
    with open(f"{CONFIG}.id") as f:
        bouncer_name = f.read().strip()

    assert len(list(cscli.get_bouncers(name=bouncer_name))) == 1

    c = pexpect.spawn(
        '/usr/bin/sh', ['scripts/install.sh'],
        encoding='utf-8',
        cwd=project_repo
    )

    c.expect(f"ERR:.* /usr/local/bin/{BOUNCER} is already installed. Exiting")


@pytest.mark.dependency(depends=['test_install_crowdsec'])
def test_upgrade_crowdsec(project_repo, must_be_root):
    os.remove(f'/usr/local/bin/{BOUNCER}')

    c = pexpect.spawn(
        '/usr/bin/sh', ['scripts/upgrade.sh'],
        encoding='utf-8',
        cwd=project_repo
    )

    c.expect(f"{BOUNCER} upgraded successfully")
    c.wait()
    assert c.terminated
    assert c.exitstatus == 0

    assert os.path.exists(f'/usr/local/bin/{BOUNCER}')
    assert os.stat(f'/usr/local/bin/{BOUNCER}').st_mode & 0o777 == 0o755


@pytest.mark.dependency(depends=['test_upgrade_crowdsec'])
def test_uninstall_crowdsec(project_repo, must_be_root):
    # the bouncer is registered
    with open(f"{CONFIG}.id") as f:
        bouncer_name = f.read().strip()

    c = pexpect.spawn(
        '/usr/bin/sh', ['scripts/uninstall.sh'],
        encoding='utf-8',
        cwd=project_repo
    )

    c.expect(f"{BOUNCER} has been successfully uninstalled")
    c.wait()
    assert c.terminated
    assert c.exitstatus == 0

    # installed files
    assert not os.path.exists(CONFIG)
    assert not os.path.exists(f'/usr/local/bin/{BOUNCER}')

    # the bouncer is unregistered
    assert len(list(cscli.get_bouncers(name=bouncer_name))) == 0
