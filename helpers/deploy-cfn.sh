#!/usr/bin/env bash

# Arguments:
# 1 - [parameter: ACTION] - AWS CloudFormation CLI Action. Valid Options: create, update, delete
# 2 - [parameter: STACK_NAME] - CloudFormation Template file name
# 3 - [parameter: AWS_REGION] - Region where the CloudFormation Stack will be created, updated or deleted
# 4 - [parameter: CLI_PROFILE] - Profile in ~/.aws/credentials file

ACTION=$1
STACK_NAME=$2
AWS_REGION=$3
CLI_PROFILE=$4

if [ "$#" -ne 4 ]; then
  echo -e "error: missing argument(s)

Usage: ./deploy-cfn.sh <action> <stack_name> <aws_region> <cli_profile>

Expected Arguments:
1 - [action] - AWS CloudFormation CLI Action. Valid Options: create, update, delete
2 - [stack_name] - CloudFormation Template file name will be used as CloudFormation Stack Name as well
3 - [aws_region] - AWS region where the CloudFormation Stack will be created, updated or deleted
4 - [cli_profile] - Profile in ~/.aws/credentials file
"
  exit 1

elif [ "$ACTION" == "create" ]; then
  aws cloudformation create-stack \
    --stack-name "$STACK_NAME" \
    --template-body file://../aws/"$STACK_NAME".yaml \
    --tags Key=Owner,Value='Cloud Team' Key=Contact,Value='Cloud Engineer - cloud.engineer@company.com' \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --region "$AWS_REGION" \
    --profile "$CLI_PROFILE"

elif [ "$ACTION" == "update" ]; then
  aws cloudformation update-stack \
    --stack-name "$STACK_NAME" \
    --template-body file://../aws/"$STACK_NAME".yaml \
    --tags Key=Owner,Value='Cloud Team' Key=Contact,Value='Cloud Engineer - cloud.engineer@company.com' \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --region "$AWS_REGION" \
    --profile "$CLI_PROFILE"

elif [ "$ACTION" == "delete" ]; then
  aws cloudformation delete-stack \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --profile "$CLI_PROFILE"

else
  echo "error: argument action: Invalid choice, valid choices are:

create
update
delete
"
  exit 1

fi