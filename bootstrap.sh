#!/bin/sh


# install software
/bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"
curl -L https://github.com/cloudquery/cloudquery/releases/download/cli-v5.11.0/cloudquery_linux_amd64 -o /usr/local/bin/cloudquery
chmod a+x /usr/local/bin/cloudquery
dnf install postgresql15 google-authenticator -y


# configure software
cd /home/ec2-user   
sudo -E -u ec2-user steampipe plugin install aws

# setup SSH OTP using google-authenticator and grab the TOTP token/seed
sudo -E -u ec2-user google-authenticator -C -t -d -Q NONE -W -f -r 1 -R 15 -q


# update sshd pam config to use google authenticator with OTP
cat <<EOF > /etc/pam.d/sshd
#auth       substack     password-auth
auth       include      postlogin
account    required     pam_sepermit.so
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
# pam_selinux.so close should be the first session rule
session    required     pam_selinux.so close
session    required     pam_loginuid.so
# pam_selinux.so open should only be followed by sessions to be executed in the user context
session    required     pam_selinux.so open env_params
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so
session    include      password-auth
session    include      postlogin
auth       required     pam_google_authenticator.so [authtok_prompt=One Time Passcode: ]
EOF


# Amend sshd config to disallow passwords, but enable keyboard interactive to be able to put in the OTP
# Note: the number must come before the 50-redhat file or redhat will take precedence
cat <<EOF > /etc/ssh/sshd_config.d/25-exampleco.conf
UsePAM yes
ChallengeResponseAuthentication yes
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
EOF

# restart SSH to kickstart MFA OTP
systemctl restart sshd

# start & stop steampipe to initialize the .steampipe directory and database
sudo -E -u ec2-user steampipe service start
sudo -E -u ec2-user steampipe service stop

# setup the ec2-user's home folder
mkdir -p .aws .cloudquery .steampipe

# create cloudquery source, will need PG_CONNECTION_STRING var in script
# not forgiving of special characters, need to urlencode
# echo 'Be-Tn0{!fC1SImm4' | jq -SRr @uri
# postgresql://hcdb:PASSWORD@hcdb-rds.ctg3db2ebws4.us-east-2.rds.amazonaws.com:5432/postgres
cat <<EOF > .cloudquery/postgres.yml
kind: destination
spec:
  name: "postgresql"
  path: "cloudquery/postgresql"
  registry: "github"
  version: "v7.3.5"
  write_mode: "overwrite-delete-stale" # overwrite-delete-stale, overwrite, append
  spec:
    connection_string: \${PG_CONNECTION_STRING}
EOF


# TODO these accounts are hardcoded for now w/ magic strings, need to add to while loop later
# TODO expand scope of cloudquery to read more AWS resources
##,"aws_s3_buckets"]
cat <<EOF > .cloudquery/aws.yml
kind: source
spec:
  name: "aws"
  path: "cloudquery/aws"
  registry: "github"
  version: "v22.19.2"
  tables: ["aws_iam_roles"]
  destinations: ["postgresql"]
  spec:
    accounts:
      - id: "sp087806813403"
        local_profile: "sp087806813403"
      - id: "sp640090909562"
        local_profile: "sp640090909562"
EOF

# setup the cloud query database to have a IAM users, a read user, a write user,
# and change the master user to IAM. Since there are now SQL users and
# everything has to go through SSO, it can be on the internet.

# If you need break glass, you can disable IAM authentication and get in with
# the HCDB user's database password from hcdb_secrets
export RDS_ENDPOINT=$(aws rds describe-db-instances --filters Name=db-instance-id,Values=hcdb-rds | jq -r .DBInstances.[0].Endpoint.Address)
export PGPASSWORD=$(aws secretsmanager get-secret-value --secret-id hcdb_secrets | jq -r .SecretString | jq -r ."hcdb_pass" )

# This is the last time we can ever connect to the db w/ user/pass. after this
# it is only IAM, unless you disable RDS IAM
cat<<EOF > iam.sql
GRANT rds_iam TO hcdb;
EOF

psql -h $RDS_ENDPOINT -U hcdb -d hcdb -f iam.sql
rm -f iam.sql


# connect with the hcdb user and password to set up new IAM roles/users
# now we are connecting with IAM instead of pg password
export PGPASSWORD=$(aws rds generate-db-auth-token --hostname $RDS_ENDPOINT --port 5432 --username hcdb)

cat<<EOF > hcdb.sql
CREATE ROLE cqwrite WITH LOGIN;
GRANT rds_iam TO cqwrite;
GRANT cqwrite TO hcdb;
CREATE ROLE cqread WITH LOGIN;
GRANT rds_iam TO cqread;
CREATE DATABASE cq OWNER=cqwrite;
EOF

psql -h $RDS_ENDPOINT -U hcdb -d hcdb -f hcdb.sql
rm -f hcdb.sql

# now we connect the cq database to grant the privileges to cqread and cqwrite roles
# default privileges is for cqread to have select perms on new tables/seqs created by cqwrite
export PGPASSWORD=$(aws rds generate-db-auth-token --hostname $RDS_ENDPOINT --port 5432 --username cqwrite)

cat<<EOF > cq.sql
GRANT SELECT ON ALL TABLES IN SCHEMA public TO cqread;
ALTER DEFAULT PRIVILEGES FOR ROLE cqwrite IN SCHEMA public GRANT SELECT ON TABLES TO cqread;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO cqread;
ALTER DEFAULT PRIVILEGES FOR ROLE cqwrite IN SCHEMA public GRANT SELECT ON SEQUENCES TO cqread;
EOF

psql -h $RDS_ENDPOINT -U cqwrite -d cq -f cq.sql
rm -f cq.sql


# make a default profile in root's home that is just enough to assume the
# @audit_role in the org account to list accounts in the org, delete when done
# to avoid weird role behavior
mkdir -p ~/.aws
cat <<EOF > ~/.aws/config
[profile default]
role_arn = arn:aws:iam::640090909562:role/@audit_role
credential_source = Ec2InstanceMetadata
role_session_name = steampipe
EOF

# get the list of accounts
aws organizations list-accounts --query "Accounts[?Status!='SUSPENDED'].[Id]" --output text > account-list.txt

rm -rf ~/.aws


# initialize aws config file
echo > .aws/config

# initialize steampipe config file
cat <<EOF > .steampipe/config/aws.spc
# combine all the delivery accounts into an aggregator
connection "dlv" {
  type        = "aggregator"
  plugin      = "aws"
  connections = ["sp087806813403","sp640090909562"]
}
EOF

# aws profile, steampipe connection, and cloduquery spec for each one
exec 9<"account-list.txt"
while read -u9 id
do

cat <<EOF >> .aws/config
[profile sp$id]
role_arn = arn:aws:iam::$id:role/@audit_role
credential_source = Ec2InstanceMetadata
role_session_name = steampipe

EOF

cat <<EOF >> .steampipe/config/aws.spc
connection "sp$id" {
  plugin  = "aws"
  profile = "sp$id"
  regions = ["*"]
}

EOF

done


# Hack steampipe to requires 2FA in the form of a client certificate
# get the postgres version that steampipe installed so we know what folder to monkey with
PGVERSION=$(basename `ls -d .steampipe/db/*/`)
# use steampipe's existing root.crt to make a new server and client cert and key
cd .steampipe/db/$PGVERSION/data
openssl req -new -nodes -text -out server.csr -keyout server.key -subj "/CN=server"
openssl x509 -req -in server.csr -text -days 3650 -CA root.crt -CAkey root.key -CAcreateserial -out server-full.crt
openssl x509 -in server-full.crt -out server.crt

openssl req -new -nodes -text -out client.csr -keyout client.key -subj "/CN=client"
openssl x509 -req -in client.csr -text -days 3650 -CA root.crt -CAkey root.key -CAcreateserial -out client-full.crt
openssl x509 -in client-full.crt -out client.crt
rm -f server-full.crt client-full.crt *.csr

# ec2-user generates an SSH key (no password) to store in secret manager
mkdir -p /home/ec2-user/.ssh && chmod 700 /home/ec2-user/.ssh && chown ec2-user:ec2-user /home/ec2-user/.ssh
sudo -E -u ec2-user ssh-keygen -t ed25519 -C "hcdb@examplecocloud.com" -f /home/ec2-user/.ssh/identity -N ""
mv /home/ec2-user/.ssh/identity.pub /home/ec2-user/.ssh/authorized_keys


# now build a nice big secret package for secrets manager
DBUSER=$(aws secretsmanager get-secret-value --secret-id hcdb_secrets | jq -r .SecretString | jq -r ."hcdb_user")
DBPASS=$(aws secretsmanager get-secret-value --secret-id hcdb_secrets | jq -r .SecretString | jq -r ."hcdb_pass")
ROOTCRT=$(cat root.crt)        # dont' remove this file, postgres needs it for the server cert/key
CLIENTCRT=$(cat client.crt) && rm -f client.crt
CLIENTKEY=$(cat client.key) && rm -f client.key
SSHKEY=$(cat /home/ec2-user/.ssh/identity) && rm -f /home/ec2-user/.ssh/identity
TOTP=$(head -1 /home/ec2-user/.google_authenticator)

jq -n \
--arg rootcrt "$ROOTCRT" \
--arg clientcrt "$CLIENTCRT" \
--arg clientkey "$CLIENTKEY" \
--arg dbuser "$DBUSER" \
--arg dbpass "$DBPASS" \
--arg sshkey "$SSHKEY" \
--arg totp "$TOTP" '{
    "hcdb_user": $dbuser,
    "hcdb_pass": $dbpass,
    "root_certificate": $rootcrt, 
    "client_certificate": $clientcrt, 
    "client_key": $clientkey,
    "totp_token" : $totp,
    "ssh_key" : $sshkey
}' > secrets.json

secretstring=$(cat secrets.json)
rm -f secrets.json

# update the secrets from terraform with all the secrets for clients to connect
aws secretsmanager update-secret --secret-id hcdb_secrets --secret-string "$secretstring"

# build a pg_hba.conf that requires a password and a client certificate to connect from remote
cat <<EOF > pg_hba.conf
# The root user is assumed by steampipe to manage the database configuration.
hostssl all root samehost trust
host    all root samehost trust
# exampleco restrictions
hostssl steampipe steampipe samehost trust
host    steampipe steampipe samehost trust
hostssl steampipe steampipe all scram-sha-256 clientcert=verify-ca
host    steampipe steampipe all reject
EOF

# tell postgres where to find the root.crt file
echo "ssl_ca_file = '/home/ec2-user/.steampipe/db/$PGVERSION/data/root.crt'" > postgresql.conf.d/01-exampleco.conf

# perms of the steampipe postgres customizations
chmod 600 *.crt *.key pg_hba.conf postgresql.conf.d/01-exampleco.conf


cd /home/ec2-user

# clean up ec2-users permissions
chown -R ec2-user:ec2-user .* 
chmod 700 .aws .cloudquery
chmod 600 .steampipe/config/aws.spc .aws/config .cloudquery/aws.yml .cloudquery/postgres.yml
rm -rf account-list.txt



# create cloudinit startup script for steampipe
cat <<EOF>/var/lib/cloud/scripts/per-boot/steampipe-service.sh
#!/bin/sh
export STEAMPIPE_DATABASE_PASSWORD=\$(aws secretsmanager get-secret-value --secret-id hcdb_secrets | jq -r .SecretString | jq -r ."hcdb_pass")
cd /home/ec2-user
sudo -E -u ec2-user steampipe service start
EOF

chmod 755 /var/lib/cloud/scripts/per-boot/steampipe-service.sh

# run it from here on ec2 launch, just this one time, after this it will happen on boot
/var/lib/cloud/scripts/per-boot/steampipe-service.sh

# create a daily cronjob for cloudquery
cat <<EOF>/etc/cron.daily/cloudquery-sync.sh
#!/bin/sh
export RDS_ENDPOINT=\$(aws rds describe-db-instances --filters Name=db-instance-id,Values=hcdb-rds | jq -r .DBInstances.[0].Endpoint.Address)
export PGPASSWORD=\$(aws rds generate-db-auth-token --hostname \$RDS_ENDPOINT --port 5432 --username cqwrite)
export PG_CONNECTION_STRING=postgresql://cqwrite@\$RDS_ENDPOINT:5432/cq

cd /home/ec2-user/.cloudquery
sudo -E -u ec2-user cloudquery sync . --log-console --log-level error
EOF

chmod 755 /etc/cron.daily/cloudquery-sync.sh

# run it from here on ec2 launch, just this one time, after this it will run daily
/etc/cron.daily/cloudquery-sync.sh
