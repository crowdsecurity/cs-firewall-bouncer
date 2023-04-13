"""
Full integration test with a real Crowdsec running in Docker
"""

import contextlib
import os
import pytest
import pathlib
import subprocess

SCRIPT_DIR = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent
fw_binary = PROJECT_ROOT.joinpath("crowdsec-firewall-bouncer")
bouncer_binary = fw_binary


def enum_package_names():
    with open(PROJECT_ROOT / 'debian/control') as f:
        for line in f:
            if line.startswith('Package:'):
                yield line.split()[1]


@pytest.fixture(scope='session', params=enum_package_names())
def deb_package_name(request):
    return request.param


@pytest.fixture(scope='session')
def deb_package_version():
    return subprocess.check_output(
            ['dpkg-parsechangelog', '-S', 'version'],
            cwd=PROJECT_ROOT
    ).decode('utf-8').strip()


@pytest.fixture(scope='session')
def deb_package_arch():
    return subprocess.check_output(
            ['dpkg-architecture', '-qDEB_BUILD_ARCH'],
            cwd=PROJECT_ROOT
    ).decode('utf-8').strip()


package_build_done = False


def dpkg_buildpackage():
    subprocess.check_call(['make', 'clean-debian'], cwd=PROJECT_ROOT)
    subprocess.check_call(['dpkg-buildpackage', '-us', '-uc', '-b'], cwd=PROJECT_ROOT)


@pytest.fixture(scope='session')
def deb_package_file(deb_package_name, deb_package_version, deb_package_arch):
    package_filename = f'{deb_package_name}_{deb_package_version}_{deb_package_arch}.deb'
    package_file = PROJECT_ROOT.parent / package_filename

    if not package_build_done:
        if package_file.exists():
            # remove by hand, before running tests
            raise RuntimeError(f'Package {package_filename} already exists. Please remove it first.')
        dpkg_buildpackage()

    yield PROJECT_ROOT.parent / package_file
#    assert (PROJECT_ROOT.parent / package_file).exists(), f'Package {package_file} not found'


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_sessionstart(session):
    if not bouncer_binary.exists() or not os.access(bouncer_binary, os.X_OK):
        raise RuntimeError(f"Bouncer binary not found at {bouncer_binary}. Did you build it?")

    yield


# Create a lapi container, registers a bouncer
# and runs it with the updated config.
# - Returns context manager that yields a tuple of (bouncer, lapi)
@pytest.fixture(scope='session')
def bouncer_with_lapi(bouncer, crowdsec, fw_cfg_factory, api_key_factory, tmp_path_factory):
    @contextlib.contextmanager
    def closure(config_lapi=None, config_bouncer=None, api_key=None):
        if config_bouncer is None:
            config_bouncer = {}
        if config_lapi is None:
            config_lapi = {}
        # can be overridden by config_lapi + config_bouncer
        api_key = api_key_factory()
        env = {
            'BOUNCER_KEY_custom': api_key,
        }
        try:
            env.update(config_lapi)
            with crowdsec(environment=env) as lapi:
                lapi.wait_for_http(8080, '/health')
                port = lapi.probe.get_bound_port('8080')
                cfg = fw_cfg_factory()
                cfg.setdefault('crowdsec_config', {})
                cfg['api_url'] = f'http://localhost:{port}/'
                cfg['api_key'] = api_key
                cfg.update(config_bouncer)
                with bouncer(fw_binary, cfg) as cb:
                    yield cb, lapi
        finally:
            pass

    yield closure


_default_config = {
    'log_mode': 'stdout',
    'log_level': 'info',
}


@pytest.fixture(scope='session')
def fw_cfg_factory():
    def closure(**kw):
        cfg = _default_config.copy()
        cfg |= kw
        return cfg | kw
    yield closure
