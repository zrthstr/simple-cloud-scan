import logging
from datetime import datetime, timezone, timedelta

log = logging.getLogger('scs.'+__name__)

class Cloudtrailscan():

    def __init__(self, session):
        log.info('Scanning AWS Cloudtrail.')
        self.ct = session.client('cloudtrail')
        self.current_pubkeys, self.old_pubkeys = self.get_all_pubkeys()
        self.print_pubkey_info()
        self.inspect_trails()


    def get_all_pubkeys(self):
        thirty_years = 365 * 30
        now = datetime.now()
        long_time_ago = datetime.today() - timedelta(days=thirty_years)
        pubkeys = self.ct.list_public_keys(StartTime=long_time_ago, EndTime=now)['PublicKeyList']
        current_pubkeys, old_pubkeys = self.sort_keys(pubkeys)
        return current_pubkeys, old_pubkeys


    def print_pubkey_info(self):
        log.info('Current Cloudtrail key fingerprints:')
        for i, key in enumerate(self.current_pubkeys):
            log.info('%d). %s', i, key['Fingerprint'])

        log.debug('Expired Cloudtrail key fingerprints:')
        for i, key in enumerate(self.old_pubkeys):
            log.debug('%d). %s', i, key['Fingerprint'])


    def is_current_pubkey(self, key):
        now = datetime.now(timezone.utc)
        if key['ValidityStartTime'] < now < key['ValidityEndTime']:
            return True
        return False


    def sort_keys(self, pubkeys):
        current_pubkeys = [key for key in pubkeys if self.is_current_pubkey(key)]
        old_pubkeys = [key for key in pubkeys if key not in current_pubkeys]
        return current_pubkeys, old_pubkeys


    def collect_active_trail_data(self, trails):
        log.info('Collecting data on active trails.')
        active_trails = {}

        for trail in trails:
            status = self.ct.get_trail_status(Name=trail['Name'])
            if status['IsLogging']:
                status.update(trail)
                active_trails[trail['Name']] = status

        log.info('Cloudtrail: Found {} active Cloudtrail.'.format(len(active_trails)))
        return active_trails


    def find_global_trails(self, trails):
        return [trails[name] for name, data in trails.items() if data['IncludeGlobalServiceEvents']]


    def inspect_trails(self):
        trails = self.ct.describe_trails(includeShadowTrails=True)['trailList']
        active_trails_data = self.collect_active_trail_data(trails)

        if not trails:
            log.critical('Could not find any trail. This means API calls to AWS are not logged.')
            return
        log.info('Found {} trails.'.format(len(trails)))

        if not active_trails_data:
            log.critical('Could not find any active trail. This means API calls to AWS are not logged.')
            return

        log.info('Found {} active trails.'.format(len(active_trails_data)))
        global_trails = self.find_global_trails(active_trails_data)

        if not global_trails:
            log.critical('Cant find Trail with global_trail_list == True.')
        else:
            log.info('Found trail with global_trail_list == True.')

        for name, data in active_trails_data.items():
            self.validate_trail(name, data)


    def validate_trail(self, name, data):
        inactivity_threshold = 24 * 3600 # 1 day

        log.info('Inspecting Cloudtrail trail {}.'.format(name))
        log.info('Trail has been logging since {}.'.format(data['TimeLoggingStarted']))
        log.info('LatestDeliveryAttemptSucceeded: {}'.format(data['LatestDeliveryAttemptSucceeded']))
        log.info('S3 bucket in use: {}'.format(data['S3BucketName']))

        if not data['LogFileValidationEnabled']:
            log.warning('Trails are not tamper protected. Trail {} LogFileValidationEnabled == False.'.format(name))
        if 'LatestDigestDeliveryError' in data:
            log.warning('Trail {} DigestDeliveryError accured at {}.'.format(name, data['LatestDigestDeliveryError']))
        if 'LatestCloudWatchLogsDeliveryError' in data:
            log.warning('Trail {} CloudWatchLogsDeliveryError accured at {}.'.format(name, data['LatestCloudWatchLogsDeliveryError']))
        if not 'LatestNotificationError' in data == '':
            log.warning('Trail: {} NotificationError accured.'.format(name))
        if 'LatestDeliveryTime' in data:
            delta = datetime.now(timezone.utc) - data['LatestDeliveryTime']
            total_seconds = delta.total_seconds()
            if total_seconds > inactivity_threshold:
                log.error('Inactivity_threshold reached. No new log since {} seconds.'.format(total_seconds))
            else:
                log.info('Last log added {} seconds ago.'.format(total_seconds))
        else:
            log.warning('LatestDeliveryTime not found for trail {}.'.format(name))
