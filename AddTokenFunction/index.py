import os
import boto3
from botocore.exceptions import ClientError
import psycopg2
import json
import base64


def lambda_handler(event, context):
    honey_path = os.environ['HONEY_TOKEN_USER_PATH']
    token_group = os.environ['TOKEN_GROUP']
    generate_username_function_arn = os.environ['GENERATE_USERNAME_FUNCTION_ARN']
    lambda_client = boto3.client('lambda')
    client = boto3.client('iam')
    AccessKeyId = None
    SecretAccessKey = None
    Owner = event.get('Owner', None)
    Location = event.get('Location', None)
    ExpiresAt = event.get('ExpiresAt', None)
    Notes = event.get('Notes', None)
    return_value = {}
    return_value['Status'] = 'FAILED'
    encrypted_db_password = os.environ.get('ENCRYPTED_DATABASE_PASSWORD', None)
    encrypted_db_password = base64.b64decode(encrypted_db_password)
    try:
        kmsclient = boto3.client('kms')
        response = kmsclient.decrypt(CiphertextBlob=encrypted_db_password)
        db_password = response['Plaintext']
    except Exception as e:
        print(e.message)

    try:
        con = psycopg2.connect(dbname='TokenDatabase',
                               host=os.environ['TOKEN_DATABASE_ADDRESS'],
                               port=os.environ['TOKEN_DATABASE_PORT'],
                               user=os.environ['FUNCTION_DATABASE_USER'],
                               password=db_password)
        cur = con.cursor()
    except Exception as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    # Try and generate a custom username
    try:
        response = lambda_client.invoke(FunctionName=generate_username_function_arn)
        if(response.get('StatusCode') == 200):
            returned_data = json.loads(response['Payload'].read())
            user = returned_data['UserName']
    except Exception as e:
        print(e.message)
        user = os.urandom(16).encode('hex')

    try:
        response = client.create_user(
            Path=honey_path,
            UserName=user
        )
        response['User']['CreateDate'] = response['User']['CreateDate'].isoformat()
        return_value['User'] = response['User']
        UserArn = response['User']['Arn']
        user = response['User']['UserName']
    except ClientError as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    # check for token counts, if too many, bail:
    try:
        response = client.list_access_keys(UserName=user)
        if len(response['AccessKeyMetadata']) >= 2:
            # too many keys
            return_value['Reason'] = "Unable to create more keys for user %s" % user
            print(json.dumps(return_value))
            return return_value
    except ClientError as e:
        pass

    try:
        response = client.add_user_to_group(
            GroupName=token_group,
            UserName=user
        )
    except ClientError as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    try:
        response = client.create_access_key(
            UserName=user
        )
        AccessKeyId = response['AccessKey']['AccessKeyId']
        SecretAccessKey = response['AccessKey']['SecretAccessKey']
        response['AccessKey']['CreateDate'] = response['AccessKey']['CreateDate'].isoformat()
        return_value['AccessKey'] = response['AccessKey']
    except ClientError as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    # Insert new token entry into the TokenDatabase
    try:
        cur.execute('''
                INSERT INTO token (
                  AccessKeyId,
                  SecretAccessKey,
                  UserName,
                  UserArn,
                  Owner,
                  Location,
                  ExpiresAt,
                  Notes
                ) VALUES (
                  %s, %s, %s, %s, %s, %s , %s, %s
                );
        ''', (
            AccessKeyId,
            SecretAccessKey,
            user,
            UserArn,
            Owner,
            Location,
            ExpiresAt,
            Notes
        ))
        con.commit()
        con.close()
    except Exception as e:
        message = '\n'
        try:
            client.delete_access_key(AccessKeyId=AccessKeyId)
        except ClientError as e:
            message += 'Unable to delete access key %s\n' % AccessKeyId
        try:
            client.delete_user(UserName=user)
        except ClientError as e:
            message += 'Unable to delete user %s\n' % user

        message = e.message + message
        return_value['Reason'] = message
        print(json.dumps(return_value))
        return return_value

    return_value['Status'] = 'SUCCESS'
    print(json.dumps(return_value))
    return return_value
