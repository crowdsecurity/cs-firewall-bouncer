
from .conftest import fw_binary


def test_partial_config(crowdsec, bouncer, fw_cfg_factory):
    cfg = fw_cfg_factory()

    with bouncer(fw_binary, cfg) as fw:
        fw.wait_for_lines_fnmatch([
            # XXX: improve this message
            "*unable to load configuration: config does not contain mode and log mode*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()

    cfg['mode'] = 'whatever'

    with bouncer(fw_binary, cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*firewall 'whatever' is not supported*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()

    # cfg['mode'] = 'pf'
    cfg['api_key'] = ''

