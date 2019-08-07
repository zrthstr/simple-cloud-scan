import logging
import boto3

log = logging.getLogger('scs.meta')


def aws_test():
    client = boto3.client('iam')
    client.list_users()
    print("AWS Login Ok.")


def show_profiles():
    session = boto3.Session()
    profile_count = len(session.available_profiles)
    print('Found {} AWS profiles.'.format(profile_count))

    for counter, profile in enumerate(session.available_profiles):
        print('{:>2}) Profile: \'{}\''.format(counter, profile))
