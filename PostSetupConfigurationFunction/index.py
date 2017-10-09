import os
import base64
import json
import urlparse
import httplib
import boto3
from botocore.exceptions import ClientError


def decrypt_value(value):
    return_value = {'Status': 'FAILED'}
    value = base64.b64decode(value)

    try:
        kmsclient = boto3.client('kms')
        kms_response = kmsclient.decrypt(CiphertextBlob=value)
        clear = kms_response['Plaintext']
        return_value['Value'] = clear
        return_value['Status'] = 'SUCCESS'
        print('decrypt success')
    except ClientError as e:
        return_value['Reason'] = e.message

    return return_value


def subscribe_lambda(lam, sns):
    return_value = {'Status': 'FAILED'}
    snsc = boto3.client('sns')
    lambdac = boto3.client('lambda')
    try:
        snsrep = snsc.subscribe(
                TopicArn=sns,
                Protocol='lambda',
                Endpoint=lam
            )
        print(snsrep)
    except ClientError as e:
        print(e)
        return_value['Reason'] = e.message
    try:
        print("adding policy")
        function_name = lam.split(':')[-1]  # sick
        print(function_name)
        rep = lambdac.add_permission(
            Action='lambda:InvokeFunction',
            FunctionName=function_name,
            Principal='sns.amazonaws.com',
            SourceArn=sns,
            StatementId=os.urandom(8).encode('hex')
            )
        print(rep)
    except ClientError as e:
        print(e)
        return_value['Reason'] = e.message

    return_value['Status'] = 'SUCCESS'
    return_value['Reason'] = snsrep['SubscriptionArn']
    return return_value


def lambda_handler(event, context):

    # Setup the defaults for our return_value
    return_value = {
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Status': 'FAILED'
    }

    # Every resource needs a unqiue physical id
    if 'PhysicalResourceId' in event:
        return_value['PhysicalResourceId'] = event['PhysicalResourceId']

    else:
        return_value['PhysicalResourceId'] = os.urandom(8).encode('hex')

    # Make sure a request type was provided, and this is a legit
    # cloudformation event
    if 'RequestType' not in event or not event['RequestType']:
        event['RequestType'] = 'wildcard'

    # Create our database tables, indicies and users
    if event['RequestType'] == 'Create':
        response = do_things()
        return_value['Status'] = response['Status']
        return_value['Reason'] = response['Reason']
    elif event['RequestType'] == 'Delete':
        # Do nothing as the table will be deleted along with the database.
        return_value['Status'] = 'SUCCESS'
    elif event['RequestType'] == 'Update':
        # Do nothing as we just want to do a one off bootstrap
        return_value['Reason'] = 'Updates not allowed.'
    else:
        # Someone's invoked this lambda not as a lambda backed resoruce
        response = do_things()
        return_value['Status'] = response['Status']
        return_value['Reason'] = response['Reason']

    # Temporary set to success while we build out the lambda
    # So that the stack doesnt break
    return_value['Status'] = 'SUCCESS'
    return send_response(event, return_value)


def do_things():
    return_value = {}
    response = {}
    return_value['Status'] = 'FAILED'
    return_value['Reason'] = 'idk lol'
    # Pagerduty
    topic_arn = os.environ.get('SNS_TOPIC_ARN', None)
    encrypted_pg_token = os.environ.get('ENCRYPTED_PAGERDUTY_TOKEN', None)
    if None in [topic_arn, encrypted_pg_token]:
        print(topic_arn, encrypted_pg_token)
        pass  # skip this
    else:
        decrypt = decrypt_value(encrypted_pg_token)
        if decrypt['Status'] == 'SUCCESS':
            pg_token = decrypt['Value']
        else:
            pg_token = 'DONTUSE'
            print('DONTUSE pg token')
    encrypted_email = os.environ.get("ENCRYPTED_EMAIL", None)
    if encrypted_email is not None:
        decrypt = decrypt_value(encrypted_email)
        if decrypt['Status'] == 'SUCCESS':
            email = decrypt['Value']
        else:
            email = 'DONTUSE'
            print('DONTUSE email')

    pagerduty_lambda = os.environ.get('PAGERDUTY_LAMBDA', 'DONTUSE')
    email_lambda = os.environ.get('EMAIL_LAMBDA', 'DONTUSE')
    if email_lambda == "DONTUSE":
        email = "DONTUSE"  # bad hack but safer
    if pagerduty_lambda == "DONTUSE":
        pg_token = "DONTUSE"

    if (pg_token == "DONTUSE") & (email == "DONTUSE"):
        return_value['Status'] = 'SUCCESS'
        return_value['Reason'] = 'No alerts to set up tbh'
        print(return_value)
        return return_value

    if pg_token != "DONTUSE":
        print('ok - pg alert setting up')
        response = subscribe_lambda(pagerduty_lambda, topic_arn)
        return_value['Status'] = response.get('Status', 'FAILED')
        return_value['Reason'] = response.get('Reason', 'Who knows?')

    if email != "DONTUSE":
        print('ok - email alert setting up')
        response = subscribe_lambda(email_lambda, topic_arn)
        return_value['Status'] = response.get('Status', 'FAILED')
        return_value['Reason'] = response.get('Reason', 'Who knows?')

    print(return_value)
    return return_value


def send_response(request, return_value):
    print(return_value)
    if 'ResponseURL' in request and request['ResponseURL']:
        url = urlparse.urlparse(request['ResponseURL'])
        body = json.dumps(return_value)
        https = httplib.HTTPSConnection(url.hostname)
        https.request('PUT', url.path + '?' + url.query, body)

    return return_value
