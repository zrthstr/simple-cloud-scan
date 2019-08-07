__version__ = '0.0.1'
__author__ = 'zrth1k@gmail.com'

import logging
import argparse

version_banner = ('\n'
                  ',--.\n'
                  '    )                    SCS - SimpleCloudScan - v{}\n'
                  '  _\'-. _                 Copyright (C) 2018 {}\n'
                  ' (    ) ),--.  \n'
                  '             )-._        This program may be freely redistributed under\n'
                  '_________________)       the terms of the GNU General Public License.'
                  '\n').format(__version__, __author__)


def logger():
    log = logging.getLogger('scs')
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    return log


def parse_cmd_arguments():
    actions = ['scan', 'show_profiles', 'version', 'test', 'usage']
    parser = argparse.ArgumentParser()

    parser.add_argument('--verbose', '-v', default=0, action='count',
                        help='Use -vv for detailed results.')

    parser.add_argument('action', default='usage', choices=actions, help='Action to perform')

    parser.add_argument('--profile', default='default',
                        help='Non-default AWS profile to be used.', type=str)

    parser.add_argument('--region', default='default',
                        help='Non-default AWS region to be used.', type=str)
    return parser


def usage(parser):
    parser.print_help()


def show_version():
    print(version_banner)
