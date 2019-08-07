import logging

log = logging.getLogger('scs.'+__name__)

class S3scan():
    world = 'http://acs.amazonaws.com/groups/global/AllUsers'
    permission_list = ['FULL_CONTROL', 'READ', 'WRITE']

    def __init__(self, session):
        log.info("Scanning AWS S3")
        self.s3 = session.resource('s3')
        self.s3_cli = session.client('s3')
        self.bucket_list = [bucket.name for bucket in self.s3.buckets.all()] 
        self.chk_permissions()


    def find_grantee(self, grant):
        if 'URI' in grant['Grantee']:
            grantee = grant['Grantee']['URI']
        if 'DisplayName' in grant['Grantee']:
            grantee = grant['Grantee']['DisplayName']
        return grantee 


    def eval_permissions(self, bucket, grant):
        grantee = self.find_grantee(grant)
        for permission in S3scan.permission_list:
            if permission == grant['Permission'] and grantee == S3scan.world:
                if permission == "WRITE":
                    log.critical('Bucket {} permission {} granted to world.'.format(bucket, grant['Permission']))
                else:
                    log.warning('Bucket {} permission {} granted to world.'.format(bucket, grant['Permission']))


    def chk_permissions(self):
        log.info('Found {} AWS S3 buckets'.format(len(self.bucket_list)))

        for bucket in self.bucket_list:
            log.info('Inspecting AWS S3 bucket {}'.format(bucket))
            result = self.s3_cli.get_bucket_acl(Bucket=bucket)
            for grant in result['Grants']:
                self.eval_permissions(bucket, grant)

                        



