#!/usr/bin/env python3

from config import logger, parse_cmd_arguments, usage, show_version
from aws.scan import aws_scan
from aws.utils import show_profiles, aws_test

def main():
    # Fetch and process commandline arguments
    parser = parse_cmd_arguments()
    args = parser.parse_args()

    # Init logger
    log = logger()
    log.level = 40 - args.verbose * 10

    # Run modules
    if args.action == 'scan':
        aws_scan(args.profile, args.region)
    elif args.action == 'test':
        aws_test()
    elif args.action == 'show_profiles':
        show_profiles()
    elif args.action == 'version':
        show_version()
    else:
        usage(parser)


if __name__ == '__main__':
    main()
