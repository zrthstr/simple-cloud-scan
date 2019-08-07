import sys
import datetime
import logging
import boto3
import botocore

from aws.iam import IAMscan
from aws.s3 import S3scan
from aws.cloudtrail import Cloudtrailscan

log = logging.getLogger('scs.'+__name__)


def aws_scan(profile, region):
    """ runn aws scanning objects """

    log.info('%s - Scanning AWS in region %s with profile %s', datetime.datetime.now(), region, profile)

    try:
        if region == "default":
            session = boto3.session.Session(profile_name=profile)
        else:
            session = boto3.session.Session(profile_name=profile, region_name=region)

    except botocore.exceptions.ClientError as err:
        log.error(err)
        sys.exit()

    S3scan(session)
    Cloudtrailscan(session)
    IAMscan(session)
