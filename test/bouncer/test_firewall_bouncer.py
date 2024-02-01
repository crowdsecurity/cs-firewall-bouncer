
import json


def test_backend_mode(bouncer, fw_cfg_factory):
    cfg = fw_cfg_factory()

    del cfg['mode']

    with bouncer(cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*unable to load configuration: config does not contain 'mode'*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()

    cfg['mode'] = 'whatever'

    with bouncer(cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*firewall 'whatever' is not supported*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()

    cfg['mode'] = 'dry-run'

    with bouncer(cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*Starting crowdsec-firewall-bouncer*",
            "*backend type: dry-run*",
            "*backend.Init() called*",
            "*unable to configure bouncer: config does not contain LAPI url*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()


def test_api_url(crowdsec, bouncer, fw_cfg_factory):
    cfg = fw_cfg_factory()

    with bouncer(cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*unable to configure bouncer: config does not contain LAPI url*",
        ])
        fw.proc.wait()
        assert not fw.proc.is_running()

    cfg['api_url'] = ''

    with bouncer(cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*unable to configure bouncer: config does not contain LAPI url*",
        ])
        fw.proc.wait()
        assert not fw.proc.is_running()


def test_api_key(crowdsec, bouncer, fw_cfg_factory, api_key_factory, bouncer_under_test):
    api_key = api_key_factory()
    env = {
        'BOUNCER_KEY_bouncer': api_key
    }

    with crowdsec(environment=env) as lapi:
        lapi.wait_for_http(8080, '/health')
        port = lapi.probe.get_bound_port('8080')

        cfg = fw_cfg_factory()
        cfg['api_url'] = f'http://localhost:{port}'

        with bouncer(cfg) as fw:
            fw.wait_for_lines_fnmatch([
                "*unable to configure bouncer: config does not contain LAPI key or certificate*",
            ])
            fw.proc.wait()
            assert not fw.proc.is_running()

        cfg['api_key'] = 'badkey'

        with bouncer(cfg) as fw:
            fw.wait_for_lines_fnmatch([
                "*Using API key auth*",
                "*API error: access forbidden*",
                "*process terminated with error: bouncer stream halted*",
            ])
            fw.proc.wait()
            assert not fw.proc.is_running()

        cfg['api_key'] = api_key

        with bouncer(cfg) as fw:
            fw.wait_for_lines_fnmatch([
                "*Using API key auth*",
                "*Processing new and deleted decisions*",
            ])
            assert fw.proc.is_running()

            # check that the bouncer is registered
            res = lapi.cont.exec_run('cscli bouncers list -o json')
            assert res.exit_code == 0
            bouncers = json.loads(res.output)
            assert len(bouncers) == 1
            assert bouncers[0]['name'] == 'bouncer'
            assert bouncers[0]['auth_type'] == 'api-key'
            assert bouncers[0]['type'] == bouncer_under_test
