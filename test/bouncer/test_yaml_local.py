
def test_yaml_local(bouncer, fw_cfg_factory):
    cfg = fw_cfg_factory()

    with bouncer(cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*unable to load configuration: config does not contain 'mode'*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()

    config_local = {
        'mode': 'whatever'
    }

    with bouncer(cfg, config_local=config_local) as fw:
        fw.wait_for_lines_fnmatch([
            "*firewall 'whatever' is not supported*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()
