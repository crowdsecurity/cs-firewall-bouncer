import os
import pexpect
import re
import subprocess

import pytest

@pytest.mark.scripts

def test_install(project_repo, bouncer_binary):
    """
    Run 'sh scripts/install.sh'
    and check that it creates the right files, with the right permissions
    """

    assert os.geteuid() == 0, "This test must be run as root"

    c = pexpect.spawn(
        '/usr/bin/sh', ['scripts/install.sh'],
        cwd=project_repo
    )

    c.expect("Installing crowdsec-firewall-bouncer")
    c.expect("iptables found")
    c.expect("nftables found")
    c.expect(re.escape("Found nftables (default) and iptables, which firewall do you want to use (nftables/iptables)"))
    c.sendline('nftables')
    c.expect("WARN.* cscli not found, you will need to generate an api key.")
    c.expect("WARN.* service not started. You need to get an API key and configure it in /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml")
    c.expect("The crowdsec-firewall-bouncer service has been installed!")
    c.wait()
    assert c.terminated
    assert c.exitstatus == 0

    assert os.path.exists('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml')
    assert os.stat('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml').st_mode & 0o777 == 0o600
    assert os.path.exists('/usr/local/bin/crowdsec-firewall-bouncer')
    assert os.stat('/usr/local/bin/crowdsec-firewall-bouncer').st_mode & 0o777 == 0o755
