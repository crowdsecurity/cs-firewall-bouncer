import subprocess
from ipaddress import ip_address


def run_cmd(*cmd, ignore_error=False):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if not ignore_error and p.returncode:
        raise SystemExit(f"{cmd} exited with non-zero code with following logs:\n {p.stdout}")

    return p.stdout


def generate_n_decisions(n: int, action="ban", dup_count=0, ipv4=True, duration="4h"):
    if dup_count >= n:
        raise SystemExit(f"generate_n_decisions got dup_count={dup_count} which is >=n")

    unique_decision_count = n - dup_count
    decisions = []
    for i in range(unique_decision_count):
        if ipv4:
            ip = ip_address(i)
        else:
            ip = ip_address(2 ** 32 + i)
        decisions.append(
            {
                "value": ip.__str__(),
                "scope": "ip",
                "type": action,
                "origin": "script",
                "duration": duration,
                "reason": "for testing",
            }
        )
    decisions += decisions[: n % unique_decision_count]
    decisions *= n // unique_decision_count
    return decisions
