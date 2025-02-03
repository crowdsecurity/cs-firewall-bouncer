import os
import subprocess


def test_scripts_nonroot(project_repo, bouncer_binary, must_be_nonroot):
    assert os.geteuid() != 0, "This test must be run as non-root"

    for script in ['install.sh', 'upgrade.sh', 'uninstall.sh']:
        c = subprocess.run(
            ['/usr/bin/sh', f'scripts/{script}'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=project_repo,
            encoding='utf-8',
        )

        assert c.returncode == 1
        assert c.stdout == ''
        assert 'This script must be run as root' in c.stderr
