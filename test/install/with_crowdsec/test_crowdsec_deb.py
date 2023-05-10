import os
import subprocess
import yaml
from pathlib import Path

import pytest
from zxcvbn import zxcvbn

pytestmark = pytest.mark.deb


# TODO: use fixtures to install/purge and register/unregister bouncers


def test_deb_install_purge(deb_package_path, bouncer_under_test, must_be_root):
    # test the full install-purge cycle, doing that in separate tests would
    # be a bit too much

    # TODO: remove and reinstall

    # use the package built as non-root by test_deb_build()
    assert deb_package_path.exists(), f'This test requires {deb_package_path}'

    p = subprocess.check_output(
        ['dpkg-deb', '-f', deb_package_path.as_posix(), 'Package'],
        encoding='utf-8'
    )
    package_name = p.strip()

    subprocess.check_call(['dpkg', '--purge', package_name])

    bouncer_exe = f"/usr/bin/{bouncer_under_test}"
    assert not os.path.exists(bouncer_exe)

    config = f"/etc/crowdsec/bouncers/{bouncer_under_test}.yaml"
    assert not os.path.exists(config)

    # install the package
    p = subprocess.run(
        ['dpkg', '--install', deb_package_path.as_posix()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding='utf-8'
    )
    assert p.returncode == 0, f'Failed to install {deb_package_path}'

    assert os.path.exists(bouncer_exe)
    assert os.stat(bouncer_exe).st_mode & 0o777 == 0o755

    assert os.path.exists(config)
    assert os.stat(config).st_mode & 0o777 == 0o600

    with open(config) as f:
        cfg = yaml.safe_load(f)
        api_key = cfg['api_key']
        # the api key has been set to a random value
        assert api_key == zxcvbn(api_key)['score'] == 4

    with open(config+'.id') as f:
        bouncer_name = f.read().strip()

    p = subprocess.check_output(['cscli', 'bouncers', 'list', '-o', 'json'])
    bouncers = yaml.safe_load(p)
    assert len([b for b in bouncers if b['name'] == bouncer_name]) == 1

    p = subprocess.run(
        ['dpkg', '--purge', package_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding='utf-8'
    )
    assert p.returncode == 0, f'Failed to purge {package_name}'

    assert not os.path.exists(bouncer_exe)
    assert not os.path.exists(config)


def test_deb_install_purge_yaml_local(deb_package_path, bouncer_under_test, must_be_root):
    """
    Check .deb package installation with:

    - a pre-existing .yaml.local file with an api key
    - a pre-registered bouncer

    => the configuration files are not touched (no new api key)
    """

    assert deb_package_path.exists(), f'This test requires {deb_package_path}'

    p = subprocess.check_output(
        ['dpkg-deb', '-f', deb_package_path.as_posix(), 'Package'],
        encoding='utf-8'
    )
    package_name = p.strip()

    subprocess.check_call(['dpkg', '--purge', package_name])
    subprocess.run(['cscli', 'bouncers', 'delete', 'testbouncer'])

    bouncer_exe = f"/usr/bin/{bouncer_under_test}"
    config = Path(f"/etc/crowdsec/bouncers/{bouncer_under_test}.yaml")
    config.parent.mkdir(parents=True, exist_ok=True)

    subprocess.check_call(['cscli', 'bouncers', 'add', 'testbouncer', '-k', '123456'])

    with open(config.with_suffix('.yaml.local'), 'w') as f:
        f.write('api_key: 123456')

    p = subprocess.run(
        ['dpkg', '--install', deb_package_path.as_posix()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding='utf-8'
    )
    assert p.returncode == 0, f'Failed to install {deb_package_path}'

    assert os.path.exists(bouncer_exe)
    assert os.path.exists(config)

    with open(config) as f:
        cfg = yaml.safe_load(f)
        api_key = cfg['api_key']
        # the api key has not been set
        assert api_key == '${API_KEY}'

    p = subprocess.check_output([bouncer_exe, '-c', config, '-T'])
    merged_config = yaml.safe_load(p)
    assert merged_config['api_key'] == '123456'

    p = subprocess.run(
        ['dpkg', '--purge', package_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding='utf-8'
    )
    assert p.returncode == 0, f'Failed to purge {package_name}'

    assert not os.path.exists(bouncer_exe)
    assert not os.path.exists(config)
