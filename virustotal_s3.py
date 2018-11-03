import json
import hashlib
import os
import logging
import codecs
import boto3
import subprocess
from botocore.vendored import requests
from botocore.exceptions import ClientError

# get variable from env
vt_apikey = os.environ['VT_API_KEY']
vt_url = os.environ['VT_URL']
confidence = os.environ['CONFIDENCE']
action_type = os.environ['ACTION']
hook_url = os.environ['HOOK_URL']
slack_channel = os.environ['SLACK_CHANNEL']

# define logger
log_level = os.environ['LOG_LEVEL'].upper()
logger = logging.getLogger()
logger.setLevel(log_level)

# create s3 high level session
s3 = boto3.resource('s3')

# Do the action we pre-define
def action(detect_count,bucket_name,object_name):
    if int(detect_count) > int(confidence) and action_type == 'DETECTION':
        slack_message = {
            'channel': slack_channel,
            'text': "Detect suspicious file \'%s\' on \'%s\' bucket, please check!" % (object_name,bucket_name)
        }
        response = requests.post(hook_url, data=json.dumps(slack_message), headers={'Content-Type': 'application/json'})
        if response.status_code != 200:
            raise ValueError(
                'Error code is: %s and the response is:\n%s'% (response.status_code, response.text)
            )
        logger.info('push to slack')
    elif int(detect_count) > int(confidence) and action_type == 'PREVENTION':
        obj = s3.Object(bucket_name, object_name)
        buf = obj.delete()
        logger.warning('Delete S3 object: ' + object_name)

# calculator SHA-256 hash
def hash_calculator(b_object):
    s = hashlib.sha256()
    s.update(b_object)
    hash = s.hexdigest()
    logger.info('sha256: ' + hash)
    return hash

def lambda_handler(event, context):
    for data in event['Records']:
        bucket_name = data['s3']['bucket']['name']
        object_name = data['s3']['object']['key']
        
        # get object from S3
        obj = s3.Object(bucket_name, object_name)
        buf = obj.get()['Body'].read()
        
        # calculator SHA-256 hash
        h = hash_calculator(buf)
        
        params = {'apikey': vt_apikey, 'resource': h}
        rsp = requests.get(vt_url,params=params)
        rsp_json = rsp.text
        rsp_dict = json.loads(rsp_json)
        detect_count = 0
        for data in rsp_dict['scans']:
            if rsp_dict['scans'][data]['detected'] == True:
                detect_count+=1
        logger.info('Virustotal scanner: ' + str(detect_count) + '/' + str(len(rsp_dict['scans'])))
        
        action(detect_count,bucket_name,object_name)
        

    return {
        "statusCode": 200,
        "body": json.dumps('Virus scan done!')
    }
