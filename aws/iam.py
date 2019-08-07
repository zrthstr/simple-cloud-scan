from io import StringIO
from time import sleep
from logging import getLogger
from csv import reader as csv_reader

from tabulate import tabulate

log = getLogger('scs.'+__name__)


class IAMscan():
    def __init__(self, session):
        log.info('Inspecting AWS IAM')
        log.info('Requesting AWS IAM credential report generation.')
        self.iam = session.client('iam')

        self.request_credential_report()
        self.inspect_pwssword_policy()
        self.inspect_users()
        #self.inspect_roles()
        self.print_credential_report()


    def request_credential_report(self):
        state = self.iam.generate_credential_report()['State']
        return state


    def print_credential_report(self):
        log.info("Trying to fetch AWS IAM credential report.")
        colums = 8
        max_wait_sec = 6
        for _ in range(max_wait_sec * 2):
            state = self.request_credential_report()
            if state == "COMPLETE":
                report = self.iam.get_credential_report()['Content']
                table = [r[:colums] for r in csv_reader(StringIO(report.decode()))]
                log.info('AWS IAM Credential report: \n{}\n'.format(tabulate(table, headers="firstrow")))
                break
            sleep(0.5)
        else:
            log.warning('Failed to retrieve Credential Report.')


    def inspect_pwssword_policy(self):
        log.info('Inspecting AWS IAM Account Password Policy.')
        defaultMinimumPasswordLength = 12
        pw_policy = self.iam.get_account_password_policy()['PasswordPolicy']

        if pw_policy['MinimumPasswordLength'] < defaultMinimumPasswordLength:
            log.warning('Minimum password length = {}. Shorter than default.'.format(pw_policy['MinimumPasswordLength']))
        else:
            log.info('MinimumPasswordLength {}. ok.'.format(pw_policy['MinimumPasswordLength']))

        pw_requirements = ['RequireSymbols', 'RequireNumbers', 'RequireUppercaseCharacters',
                           'RequireUppercaseCharacters', 'RequireLowercaseCharacters']
        for warning_msg in ['{} = False.'.format(req) for req in pw_requirements if not pw_policy[req]]:
            log.warning(warning_msg)


    def inspect_mfa(self, username):
        users_MFA_devices = self.iam.list_mfa_devices(UserName=username)['MFADevices']
        if users_MFA_devices:
            log.info('Found MFA device for user {}.'.format(username))
        else:
            log.error('No MFA device found for user {}.'.format(username))


    def attached_user_policies(self, username):
        # this list is for sure non compleet..
        high_priv = ['root', 'AdministratorAccess', 'SystemAdministrator', 'AdministratorAccess', 'NetworkAdministrator', ]

        attached_user_policies = self.iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        attached_user_policies_count = len(attached_user_policies)

        log.info('Found {} attached_user_policies for user {}.'.format(attached_user_policies_count, username))

        for policy in attached_user_policies:
            if policy['PolicyName'] in high_priv:
                log.warning('High Privilege Policy {} is attached to user {}.'.format(policy['PolicyName'], username))
            else:
                log.info('Policy {} is attached to User {}.'.format(policy['PolicyName'], username))


    def inspect_users(self):
        log.info('Inspecting AWS IAM users.')
        users = self.iam.list_users()['Users']
        log.info('Found {} users.'.format(len(users)))

        for user in users:
            log.info('Inspecting AWS IAM user %s.', user['UserName'])
            self.inspect_mfa(user['UserName'])
            self.attached_user_policies(user['UserName'])



    def inspect_roles(self):
        ## TBD
        log.info('Inspecting AWS IAM roles.')
        roles = self.iam.list_roles()
        for role in roles['Roles']:
            role_policy = self.iam.list_role_policies(RoleName=role['RoleName'])
            log.info(role_policy)


    def inspect_policies(self):
        ## TBD
        ## aws iam list-policies
        pass
