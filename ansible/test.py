#  (C) Copyright 2024 Hyland (https://www.hyland.com/).
#  This is unpublished proprietary source code of Hyland. All rights reserved.
#  Notice of copyright on this source code does not indicate publication.
#
#  Contributors:
#      siddhgopal soni <mailto:siddhgopal.soni@hyland.com>

import boto3
import pytest
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError
from pytest import fixture , fail



def pytest_addoption(parser):
    parser.addoption(
        "--enable-s3-download-restrict-policy",
        action="store",
        default=False,
        help="Boolean flag, 'true' or 'false'",
    )
    parser.addoption(
        "--authorized-role",
        action="store",
        help="Role that has permission to download",
    )
    parser.addoption("--region", action="store", help="AWS region")
    parser.addoption("--bucket-name", action="store", help="Specify the S3 bucket name")


@fixture
def enable_s3_download_restrict_policy(request):
    return request.config.getoption("--enable-s3-download-restrict-policy")


@fixture
def bucket_name(request):
    return request.config.getoption("--bucket-name")


@fixture
def authorized_role(request):
    return request.config.getoption("--authorized-role")


@fixture
def region(request):
    return request.config.getoption("--region")


# Fixture to initialize the S3 client with direct AWS access
@fixture
def s3_client(region):
    return boto3.client("s3", region_name=region)


# Fixture to assume a specific role and create an S3 client with the assumed role's credentials
@fixture
def s3_client_with_role(region, authorized_role):
    try:
        sts_client = boto3.client("sts")
        assumed_role = sts_client.assume_role(RoleArn=authorized_role, RoleSessionName="TestSession")
        credentials = assumed_role["Credentials"]
        return boto3.client(
            "s3",
            region_name=region,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
    except NoCredentialsError:
        fail("AWS credentials not found for assuming the role.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            fail(f"Role does not have permission to assume: {e}")
        else:
            fail(f"Failed to retrieve bucket policy: {e}")


# Fixture to upload a file to S3 before tests run
@fixture(autouse=True)
def setup_files(s3_client_with_role, bucket_name):
    TEST_FILE = "sample_file.txt"

    Path(TEST_FILE).write_bytes(b"This is a test file for S3 upload.")

    try:
        s3_client_with_role.upload_file(TEST_FILE, bucket_name, TEST_FILE)
        print(f"Uploaded {TEST_FILE} to {bucket_name} successfully.")
    except ClientError as e:
        fail(f"Failed to upload {TEST_FILE} to S3: {e}")

