#AWS Lambda Python Code to rotate RDS Password
# https://prathameshbusa.blogspot.com/2024/07/secure-your-databases-automating-rds.html
import json
import boto3
import pgdb
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager')

    # Make sure the rotation is enabled correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    
    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(service_client, arn, token):
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        get_secret_dict(service_client, arn, "AWSPENDING", token)
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        # Generate a random password
        passwd=get_random_password(service_client)
        current_dict['DB_PASSWORD'] = passwd
        # Put the secret
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))

def set_secret(service_client, arn, token):
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)
    print(pending_dict)
    db_host_secret_name = "datapipes/test-shaktiman1/rds_host"  # Use the actual name of your secret
    db_host = get_secret_dict(service_client, db_host_secret_name, "AWSCURRENT")["DB_HOST"]
    db_name = 'postgres'
    db_user = current_dict["DB_USER"]
    db_password = current_dict["DB_PASSWORD"]
    db_port = '5432'
    
    try:
        conn = pgdb.Connection(
            database=db_name,
            host=db_host,
            user=db_user,
            password=db_password,
            port=db_port
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT quote_ident(%s)", (pending_dict["DB_USER"],))
        escaped_username = cursor.fetchone()[0]
        alter_role = "ALTER USER %s" % escaped_username
        cursor.execute(alter_role + " WITH PASSWORD %s", (pending_dict["DB_PASSWORD"],))
        conn.commit()
        conn.close()
        logger.info("setSecret: Successfully set password for user %s in PostgreSQL DB for secret arn %s." % (db_user, arn))

    except Exception as e:
        logger.error("setSecret: Failed to update password for user %s in PostgreSQL DB for secret arn %s. Error: %s" % (db_user, arn, str(e)))
        raise ValueError("Unable to log into database with current secret of secret arn %s" % arn)


def test_secret(service_client, arn, token):
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)
    db_name = 'postgres'
    db_host_secret_name = "datapipes/test-shaktiman1/rds_host"  # Use the actual name of your secret
    db_host = get_secret_dict(service_client, db_host_secret_name, "AWSCURRENT")["DB_HOST"]
    db_user = 'postgres'
    db_password = pending_dict["DB_PASSWORD"]
    db_port = '5432'
    
    try:
        conn = pgdb.Connection(
            database=db_name,
            host=db_host,
            user=db_user,
            password=db_password,
            port=db_port
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT NOW()")
        conn.commit()
        conn.close()
        logger.info("testSecret: Successfully signed into PostgreSQL DB with AWSPENDING secret in %s" % arn)
    except Exception as e:
        logger.error("testSecret: Failed to connect to PostgreSQL DB with AWSPENDING secret in %s. Error: %s" % (arn, str(e)))
        raise ValueError("Unable to log into database with pending secret of secret ARN %s" % arn)



def finish_secret(service_client, arn, token):
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))


def get_secret_dict(service_client, arn, stage, token=None):
    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)

    # Parse and return the secret JSON string
    return secret_dict

def get_random_password(service_client):
    passwd = service_client.get_random_password(
        ExcludeCharacters=':"\'#@${}%&()*+,./:;<=>?[\\]^_`{|}~',
        PasswordLength=16,
        ExcludeNumbers=False,
        ExcludePunctuation=False,
        ExcludeUppercase=False,
        ExcludeLowercase=False,
        RequireEachIncludedType=True
    )
    return passwd['RandomPassword']
