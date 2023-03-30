#!/usr/bin/env bash

# Arguments:
# 1 - [parameter: FILE_VERSION] - Version of ebs-automation-*.zip
# 2 - [parameter: AWS_REGION] - Region where the code will be uploaded
# 3 - [parameter: CLI_PROFILE] - Profile in ~/.aws/credentials file

FILE_VERSION=$1
AWS_REGION=$2
CLI_PROFILE=$3

if [ "$#" -ne 3 ]; then
  echo -e "error: missing argument(s)

Usage: ./upload-code.sh <file_version> <aws_region> <cli_profile>

Expected Arguments:
1 - [file_version] - Version of ebs-automation-*.zip
2 - [aws_region] - AWS region where the code will be uploaded
3 - [cli_profile] - Profile in ~/.aws/credentials file
"
  exit 1

else
  aws s3api put-object \
    --bucket ebs-automation-artifacts \
    --key ebs-automation-"${FILE_VERSION}".zip \
    --body ebs-automation.zip \
    --server-side-encryption aws:kms \
    --ssekms-key-id XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX \
    --region "$AWS_REGION" \
    --profile "$CLI_PROFILE"

fi