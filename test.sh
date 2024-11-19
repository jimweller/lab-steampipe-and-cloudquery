#!/bin/bash

# get secrets

set +o monitor

echo "Reading values from AWS"

export RDS_ENDPOINT=$(aws rds describe-db-instances --filters Name=db-instance-id,Values=hcdb-rds | jq -r '.DBInstances.[0].Endpoint.Address')
export RDS_READ_USER=cqread
export RDS_WRITE_USER=cqwrite

export EC2_ID=$(aws ec2 describe-instances --filters aws ec2 describe-instances --filters 'Name=tag:Name,Values=hcdb-svr1' --filters 'Name=instance-state-name,Values=running' | jq -r '.Reservations[0].Instances[0].InstanceId')
export EC2_DNS=$(aws ec2 describe-instances --filters aws ec2 describe-instances --filters 'Name=tag:Name,Values=hcdb-svr1' --filters 'Name=instance-state-name,Values=running' | jq -r '.Reservations[0].Instances[0].PublicDnsName')
export EC2_TOTP=$(aws secretsmanager get-secret-value --secret-id hcdb_secrets| jq -r .SecretString | jq -r '.totp_token')
export EC2_SSH_KEY=$(aws secretsmanager get-secret-value --secret-id hcdb_secrets| jq -r .SecretString | jq  -r '.ssh_key')
export EC2_USER=ec2-user

export STEAMPIPE_PASSWORD=$(aws secretsmanager get-secret-value --secret-id hcdb_secrets| jq -r .SecretString | jq -r '.hcdb_pass')
export STEAMPIPE_USER=steampipe



CLIENT_CERT=$(aws secretsmanager get-secret-value --secret-id hcdb_secrets| jq -r .SecretString | jq -r '.client_certificate')
CLIENT_KEY=$(aws secretsmanager get-secret-value --secret-id hcdb_secrets| jq -r .SecretString | jq -r '.client_key')
CLIENT_ROOT=$(aws secretsmanager get-secret-value --secret-id hcdb_secrets| jq -r .SecretString | jq  -r '.root_certificate')




# put all the keys in place

mkdir -p ~/tmp
echo -e "$CLIENT_CERT\n" > ~/tmp/client.crt
echo -e "$CLIENT_KEY\n" > ~/tmp/client.key
echo -e "$CLIENT_ROOT\n" > ~/tmp/root.crt

echo -e "$EC2_SSH_KEY\n" > ~/.ssh/hcdb

echo -e \$RDS_ENDPOINT=$RDS_ENDPOINT
echo -e \$RDS_READ_USER=$RDS_READ_USER
echo -e \$RDS_WRITE_USER=$RDS_WRITE_USER
echo -e
echo -e \$EC2_ID=$EC2_ID
echo -e \$EC2_DNS=$EC2_DNS
echo -e \$EC2_USER=$EC2_USER
echo -e \$EC2_TOTP=$EC2_TOTP
echo -e "EC2_SSH_KEY is in ~/.ssh/hcdb"
echo -e
echo -e \$STEAMPIPE_PASSWORD=$STEAMPIPE_PASSWORD
echo -e \$STEAMPIPE_USER=$STEAMPIPE_USER
echo -e
echo -e "CLIENT_CERT is in ~/tmp/client.crt"
echo -e "CLIENT_KEY is in ~/tmp/client.key"
echo -e "CLIENT_ROOT is in ~/tmp/root.crt"
echo -e

echo -e "********************************************************************************\nTESTING SSH OVER INTERNET\n(copy and paste the OTP code)\n********************************************************************************"
oathtool --totp --b $EC2_TOTP
ssh -i ~/.ssh/hcdb $EC2_USER@$EC2_DNS 'echo SUCCESS'

echo -e "\n********************************************************************************\nSLEEP 15s for TOTP to cycle\n********************************************************************************"
for ((i=1;i<=15;i++)); do sleep 1; echo -n "$i "; done
echo -e

echo -e "\n********************************************************************************\nTESTING SSH OVER TUNNEL\n(copy and paste the OTP code)\n********************************************************************************"
oathtool --totp --b $EC2_TOTP
# make sure you have your ~/.ssh/config setup to use ec2 instance id with ProxyCommand
ssh -i ~/.ssh/hcdb $EC2_USER@$EC2_ID 'echo SUCCESS'

echo -e "\n********************************************************************************\nTESTING STEAMPIPE OVER INTERNET\n********************************************************************************"
export PGPASSWORD=$STEAMPIPE_PASSWORD
export PGSSLMODE=require
export PGSSLROOTCERT=~/tmp/root.crt
export PGSSLCERT=~/tmp/client.crt
export PGSSLKEY=~/tmp/client.key
echo 'select account_id,count(account_id) from dlv.aws_iam_role group by account_id' 
psql -h $EC2_DNS -U $STEAMPIPE_USER -d steampipe -p 9193 --pset="footer=off" -c 'select account_id,count(account_id) from dlv.aws_iam_role group by account_id' 

echo -e "********************************************************************************\nTESTING STEAMPIPE OVER TUNNEL\n********************************************************************************"
# uses same PG variables as above
aws ssm start-session --target $EC2_ID --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters portNumber="9193",localPortNumber="9193" &
PID=$!
disown %1
sleep 3
psql -h 127.0.0.1 -U $STEAMPIPE_USER -d steampipe -p 9193 --pset="footer=off" -c 'select account_id,count(account_id) from dlv.aws_iam_role group by account_id'
kill $PID
killall session-manager-plugin
unset PGSSLROOTCERT
unset PGSSLCERT
unset PGSSLKEY


echo -e "********************************************************************************\nTESTING CLOUDQUERY OVER INTERNET\n********************************************************************************"
export PGPASSWORD=$(aws rds generate-db-auth-token --hostname $RDS_ENDPOINT --port 5432 --username $RDS_READ_USER)
echo 'select account_id,count(account_id) from aws_iam_roles group by account_id'
psql -h $RDS_ENDPOINT -U $RDS_READ_USER -d cq -p 5432 --pset="footer=off" -c 'select account_id,count(account_id) from aws_iam_roles group by account_id'


echo -e "********************************************************************************\nTESTING CLOUDQUERY OVER TUNNEL\n********************************************************************************"
export PGPASSWORD=$(aws rds generate-db-auth-token --hostname $RDS_ENDPOINT --port 5432 --username $RDS_READ_USER)
aws ssm start-session --target $EC2_ID --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters host="$RDS_ENDPOINT",portNumber="5432",localPortNumber="5432" &
PID=$!
disown %1
sleep 3
psql -h 127.0.0.1 -U $RDS_READ_USER -d cq -p 5432 --pset="footer=off" -c 'select account_id,count(account_id) from aws_iam_roles group by account_id'
kill $PID
killall session-manager-plugin

echo -e "********************************************************************************\nTESTING RDS SECURITY. \"PAM authentication failed\" is SUCCESS. NON-IAM SHOULD FAIL\n********************************************************************************"
export PGPASSWORD=$STEAMPIPE_PASSWORD
(psql -h $RDS_ENDPOINT -U hcdb -d cq -p 5432 -c 'select account_id,count(account_id) from aws_iam_roles group by account_id')