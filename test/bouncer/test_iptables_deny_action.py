
def test_iptables_deny_action(bouncer, fw_cfg_factory):
    cfg = fw_cfg_factory()

    cfg['log_level'] = 'trace'
    cfg['mode'] = 'iptables'

    with bouncer(cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*using 'DROP' as deny_action*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()

    cfg['deny_action'] = 'drop'

    with bouncer(cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*using 'DROP' as deny_action*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()

    cfg['deny_action'] = 'reject'

    with bouncer(cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*using 'REJECT' as deny_action*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()

    cfg['deny_action'] = 'tarpit'

    with bouncer(cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*using 'TARPIT' as deny_action*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()

    cfg['deny_action'] = 'somethingelse'

    with bouncer(cfg) as fw:
        fw.wait_for_lines_fnmatch([
            "*invalid deny_action 'somethingelse', must be one of DROP, REJECT, TARPIT*",
        ])
        fw.proc.wait(timeout=0.2)
        assert not fw.proc.is_running()
