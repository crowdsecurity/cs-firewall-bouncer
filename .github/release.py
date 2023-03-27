#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import subprocess
import sys


def _goos():
    yield 'linux'
    yield 'freebsd'


def _goarch(goos):
    yield '386'
    yield 'amd64'
    yield 'arm'
    yield 'arm64'
    if goos == 'linux':
        yield 'ppc64le'
        yield 's390x'
    yield 'riscv64'


def _goarm(goarch):
    if goarch != 'arm':
        yield ''
        return
    yield '6'
    yield '7'


def _static():
    yield True
    yield False


def _build_tarball(os):
    if os == 'linux':
        yield True
    else:
        yield False


def filename_for_entry(prog_name, entry):
    arch = entry['goarch']
    if entry['goarch'] == 'arm':
        arch += 'v' + entry['goarm']
    ret = f'{prog_name}-{entry["goos"]}-{arch}'
    if entry['static']:
        ret += '-static'
    if entry['build_tarball']:
        ret += '.tgz'
    return ret


def matrix(prog_name):
    for goos in _goos():
        for goarch in _goarch(goos):
            for goarm in _goarm(goarch):
                for static in _static():
                    for build_tarball in _build_tarball(goos):
                        yield {
                            'goos': goos,
                            'goarch': goarch,
                            'goarm': goarm,
                            'static': static,
                            'build_tarball': build_tarball,
                        }


def print_matrix(prog_name):
    j = {'include': list(matrix(prog_name))}

    if os.isatty(sys.stdout.fileno()):
        print(json.dumps(j, indent=2))
    else:
        print(json.dumps(j))


default_tarball = {
    'goos': 'linux',
    'goarch': 'amd64',
    'goarm': '',
    'static': False,
    'build_tarball': True,
}

default_binary = {
    'goos': 'linux',
    'goarch': 'amd64',
    'goarm': '',
    'static': False,
    'build_tarball': False,
}


def run_build(prog_name):
    # call the makefile for each matrix entry

    default_tarball_filename = None
    default_binary_filename = None

    for entry in matrix(prog_name):
        env = {'GOOS': entry['goos'], 'GOARCH': entry['goarch']}

        if entry['goarm']:
            env['GOARM'] = entry['goarm']

        if entry['static']:
            env['BUILD_STATIC'] = 'yes'

        if entry['build_tarball']:
            target = 'tarball'
        else:
            target = 'binary'

        print(f"Running make {target} for {env}")

        subprocess.run(['make', target], env=os.environ | env, check=True)

        want_filename = filename_for_entry(prog_name, entry)

        if entry['build_tarball']:
            os.rename(f'{prog_name}.tgz', want_filename)
        else:
            os.rename(f'{prog_name}', want_filename)

        # if this is the default tarball or binary, save the filename
        # we'll use it later to publish a "default" package

        if entry == default_tarball:
            default_tarball_filename = want_filename

        if entry == default_binary:
            default_binary_filename = want_filename

        # Remove the directory to reuse it
        subprocess.run(['make', 'clean-release-dir'], env=os.environ | env, check=True)

    # publish the default tarball and binary
    if default_tarball_filename:
        shutil.copy(default_tarball_filename, f'{prog_name}.tgz')

    if default_binary_filename:
        shutil.copy(default_binary_filename, f'{prog_name}')


def main():
    parser = argparse.ArgumentParser(
        description='Build release binaries and tarballs for all supported platforms')
    parser.add_argument('action', help='Action to perform (ex. run-build, print-matrix)')
    parser.add_argument('prog_name', help='Name of the program (ex. crowdsec-firewall-bouncer)')

    args = parser.parse_args()

    if args.action == 'print-matrix':
        print_matrix(args.prog_name)

    if args.action == 'run-build':
        run_build(args.prog_name)


if __name__ == '__main__':
    main()
