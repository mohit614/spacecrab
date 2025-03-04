import base64
import uuid
import httplib
import urlparse
import json
import boto3


def send_response(request, response, status=None, reason=None):
    """ Send our response to the pre-signed URL supplied by CloudFormation
    If no ResponseURL is found in the request, there is no place to send a
    response. This may be the case if the supplied event was for testing.
    """

    if status is not None:
        response['Status'] = status

    if reason is not None:
        response['Reason'] = reason

    if 'ResponseURL' in request and request['ResponseURL']:
        url = urlparse.urlparse(request['ResponseURL'])
        body = json.dumps(response)
        https = httplib.HTTPSConnection(url.hostname)
        https.request('PUT', url.path+'?'+url.query, body)

    return response


def lambda_handler(event, context):

    response = {
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Status': 'SUCCESS'
    }

    # PhysicalResourceId is meaningless here, but CloudFormation requires it
    if 'PhysicalResourceId' in event:
        response['PhysicalResourceId'] = event['PhysicalResourceId']
    else:
        response['PhysicalResourceId'] = str(uuid.uuid4())

    # There is nothing to do for a delete request
    if event['RequestType'] == 'Delete':
        return send_response(event, response)

    # Encrypt the value using AWS KMS and return the response
    try:

        for key in ['KeyId', 'PlainText']:
            if key not in event['ResourceProperties'] or not event['ResourceProperties'][key]:
                return send_response(
                    event, response, status='FAILED',
                    reason='The properties KeyId and PlainText must not be empty'
                )

        client = boto3.client('kms')
        encrypted = client.encrypt(
            KeyId=event['ResourceProperties']['KeyId'],
            Plaintext=event['ResourceProperties']['PlainText']
        )

        response['Data'] = {
            'CipherText': base64.b64encode(encrypted['CiphertextBlob'])
        }
        response['Reason'] = 'The value was successfully encrypted'

    except Exception as e:
        response['Status'] = 'FAILED'
        response['Reason'] = e.message

    return send_response(event, response)
