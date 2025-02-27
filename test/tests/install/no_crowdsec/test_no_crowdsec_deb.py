import os
import subprocess

import pytest

pytestmark = pytest.mark.deb


def test_deb_install_purge(deb_package_path, bouncer_under_test, must_be_root):
    # test the full install-purge cycle, doing that in separate tests would
    # be a bit too much

    # TODO: remove and reinstall

    # use the package built as non-root by test_deb_build()
    assert deb_package_path.exists(), f"This test requires {deb_package_path}"

    bouncer_exe = f"/usr/bin/{bouncer_under_test}"
    assert not os.path.exists(bouncer_exe)

    config = f"/etc/crowdsec/bouncers/{bouncer_under_test}.yaml"
    assert not os.path.exists(config)

    # install the package
    p = subprocess.run(
        ["dpkg", "--install", deb_package_path.as_posix()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    assert p.returncode == 0, f"Failed to install {deb_package_path}"

    assert os.path.exists(bouncer_exe)
    assert os.stat(bouncer_exe).st_mode & 0o777 == 0o755

    assert os.path.exists(config)
    assert os.stat(config).st_mode & 0o777 == 0o600

    p = subprocess.check_output(["dpkg-deb", "-f", deb_package_path.as_posix(), "Package"], encoding="utf-8")
    package_name = p.strip()

    p = subprocess.run(
        ["dpkg", "--purge", package_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    assert p.returncode == 0, f"Failed to purge {package_name}"

    assert not os.path.exists(bouncer_exe)
    assert not os.path.exists(config)
