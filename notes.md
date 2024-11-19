# Scratchpad Notes

## Links
- This is useful article for automating the hydration of steampipe. Originally, I thought I could use the FDW in RDS or a postgres server, but the schema has errors. https://briansuk.medium.com/connecting-steampipe-with-google-bigquery-ae37f258090f
- This is useful article for automating the hydration of steampipe. https://dev.to/finnauto/running-steampipe-on-aws-fargate-51ci
- This is a hint on how to setup RDS to use FDW to steampipe, but it throws errors and would be difficult to maintain. https://www.reddit.com/r/aws/comments/uh8w9k/steampipe_and_postgres/
- Useful scripts for provisioning AWS config and steampipe config. Mostly for hints on making our own. https://steampipe.io/docs/guides/aws-orgs#ecs-task
- Postgres FDW syntax docs. https://www.postgresql.org/docs/current/postgres-fdw.html
- Some terraform modules used in the solution
  - RDS https://registry.terraform.io/modules/terraform-aws-modules/rds/aws/latest
  - EC2 https://registry.terraform.io/modules/terraform-aws-modules/ecs/aws/latest
  - VPC https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/latest
- How to set the steam pipe password in a variable such that it is not recorded outside of secrets manager. https://steampipe.io/docs/reference/env-vars/steampipe_database_password
- Cloud init docs on the different folders. We use the per-boot to start our services. https://cloudinit.readthedocs.io/en/latest/reference/modules.html#scripts-per-boot
- Using google authenticator to do MFA over SSH. https://aws.amazon.com/blogs/startups/securing-ssh-to-amazon-ec2-linux-hosts/
- How to do MFA in postgres with client certificates. https://smallstep.com/hello-mtls/doc/combined/postgresql/psql
- Connecting steampipe to grafana (unrelated to this solution, for later). https://turbot.com/pipes/docs/integrations/grafana
- Secret nugget about the redhat ssh config overriding our custom ssh config. Make our number smaller. https://askubuntu.com/questions/1318318/help-cant-seem-to-get-2fa-to-work-for-my-aws-ec2-ssh
- How sshd_config.d overrides work https://forums.fedoraforum.org/showthread.php?324528-sshd_config-d-override-file-not-working-as-expected
- More details on MFA and SSH. https://serverfault.com/questions/1114499/cannot-use-2fa-due-to-disabled-method-keyboard-interactive-even-when-it-is-e
- Documentation setting up the postgres server (steampipe) to require a client certificate and how to configure the client. https://www.postgresql.org/docs/current/ssl-tcp.html#SSL-CLIENT-CERTIFICATES
- How to install steampipe from the command line. For our bootstrap script. https://steampipe.io/docs/steampipe_postgres/install
- Using AWS session manager to establish a tunnel to a non-public RDS instance. https://aws.amazon.com/blogs/database/securely-connect-to-an-amazon-rds-or-amazon-ec2-database-instance-remotely-with-your-preferred-gui/
- AWS session manager plugin. You can just use `brew install session-manager-plugin`. https://docs.aws.amazon.com/systems-manager/latest/userguide/install-plugin-linux.html
- How to use a condition on a policy against a saml identity. This is a secret nugget that is hard to find!!!! https://stackoverflow.com/questions/51326823/targetting-federated-saml-users-in-iam-role-policies
- This was the idea for the saml identity condtions. https://medium.com/@christopher-scholz/how-to-setup-iam-database-authentication-with-iam-identity-center-e8a24cd1a611
- More aws:userid saml condition stuff. https://stackoverflow.com/questions/51326823/targetting-federated-saml-users-in-iam-role-policies
- General IAM+RDS stuff
  - https://blog.devart.com/what-is-aws-iam-and-connection-to-aws-rds-using-iam.html
  - https://www.commandprompt.com/education/how-to-connect-to-my-amazon-rds-for-postgresql-using-iam-authentication/
  - https://aws.amazon.com/blogs/big-data/federate-database-user-authentication-easily-with-iam-and-amazon-redshift/
  - https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/



Random pasting of important command lines and configurations


- `google-authenticator -C -t -d -Q NONE -W -f -r 1 -R 15 -q`


- HCDB_SECRET_NAME=$(aws secretsmanager list-secrets --filter Key="tag-value",Values="hcdb-secret" | jq  -r ".SecretList[0].Name" )
- HCDB_SECRET_USER=$(aws secretsmanager get-secret-value --secret-id $HCDB_SECRET_NAME | jq -r .SecretString | jq -r ."username")
- HCDB_SECRET_PASS=$(aws secretsmanager get-secret-value --secret-id hcdb_secret| jq -r .SecretString | jq -r ."password")
- aws secretsmanager delete-secret --secret-id $arn --force-delete-without-recovery
- aws secretsmanager create-secret --name hcdb_certs --secret-string '{ "key1":"value1","key2":"value2" }'
- SECRET_STRING=$(cat .google_authenticator)
- aws secretsmanager create-secret --name test --secret-string "$SECRET_STRING"

pg_hba.conf
```
hostssl steampipe steampipe samehost trust
host    steampipe steampipe samehost trust
hostssl steampipe steampipe all scram-sha-256 clientcert=verify-ca
host    steampipe steampipe all reject
```


### Adding MFA to ssh
/etc/ssh/sshd_config.d/25-exampleco.conf
```
UsePAM yes
ChallengeResponseAuthentication yes
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

/etc/pam.d/sshd
```
#%PAM-1.0
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
```




- selft signed `openssl req -new -x509 -days 365 -nodes -text -out client.crt -keyout client.key -subj "/CN=client"`

local signed
```
openssl req -new -nodes -text -out server.csr -keyout server.key -subj "/CN=server"
openssl x509 -req -in server.csr -text -days 8000 -CA root.crt -CAkey root.key -CAcreateserial -out server.crt


openssl req -new -nodes -text -out client.csr -keyout client.key -subj "/CN=client"
openssl x509 -req -in client.csr -text -days 8000 -CA root.crt -CAkey root.key -CAcreateserial -out client.crt
```

```
dnf install postgresql15-server postgresql15-server-devel -y
postgresql-setup --initdb
systemctl start postgresql
systemctl enable postgresql
sudo -i -u postgres

/bin/sh -c "$(curl -fsSL https://steampipe.io/install/postgres.sh) aws latest"
https://github.com/turbot/steampipe-plugin-aws/releases/latest/download/steampipe_postgres_aws.pg15.linux_amd64.tar.gz


/home/ec2-user/.steampipe/db/14.2.0/postgres/bin/postgres -p 9193 -c listen_addresses=* -c application_name=steampipe -c cluster_name=steampipe -c log_directory=/home/ec2-user/.steampipe/logs -c ssl=on -c ssl_cert_file=/home/ec2-user/.steampipe/db/14.2.0/data/server.crt -c ssl_key_file=/home/ec2-user/.steampipe/db/14.2.0/data/server.key -c ssl_ca_file=/home/ec2-user/.steampipe/db/14.2.0/data/root.crt -D /home/ec2-user/.steampipe/db/14.2.0/data

/home/ec2-user/.steampipe/db/14.2.0/postgres/bin/postgres -p 9193 -c listen_addresses=* -c application_name=steampipe -c cluster_name=steampipe -c log_directory=/home/ec2-user/.steampipe/logs -c ssl=on -c ssl_cert_file=/home/ec2-user/.steampipe/db/14.2.0/data/server.crt -c ssl_key_file=/home/ec2-user/.steampipe/db/14.2.0/data/server.key -D /home/ec2-user/.steampipe/db/14.2.0/data

```


attached to ssoadmin role
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RdsIamAuth",
      "Action": [
        "rds-db:connect"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:rds-db:*:*:dbuser:*/*"
      ]
    }
  ]
}
```

```
brew install session-manager-plugin
```

sample deny policy for permissions set testing
jim_saml_filter_test
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SamlFilter",
            "Effect": "Deny",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::terraform-remote-state-504400329018-us-east-2",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:userid": "AROAXK4E2HE5N2LBGKPFU:Jim.Weller@exampleco.com"
                }
            }
        }
    ]
}
```


policy to allow iam database connect for the AWSPowerUserAccess role
```
{
  "Version": "2012-10-17",
  "Id": "RdsIamAuth",
  "Statement": [
    {
      "Sid": "RdsIamAuth",
      "Action": [
        "rds-db:connect"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:rds-db:us-east-2:087806813403:dbuser:db-EV46XDFE77NJAWF4JPOF66ASEA/jim.weller"
      ],
      "Condition": {
        "ForAnyValue:StringLike": {
          "aws:userid": "*:Jim.Weller@exampleco.com"
        }
      }
    }
  ]
}
```

```
aws rds describe-db-instances 
```

in hcdb
```
CREATE DATABASE cq OWNER=hcdb;

CREATE ROLE cqwrite WITH LOGIN;
GRANT rds_iam TO cqwrite;

CREATE ROLE cqread WITH LOGIN;
GRANT rds_iam TO cqread;
```

```
DROP DATABASE cq;

REVOKE rds_iam FROM cqwrite;
REVOKE rds_iam FROM cqread;

DROP ROLE cqwrite;
DROP ROLE cqread;
```

in cq db
```
GRANT ALL PRIVILEGES ON DATABASE cq to cqwrite;
GRANT select ON ALL TABLES IN SCHEMA "public" TO cqread;
```

probably don't need this
```
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM cqwrite;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM cqread;
```

```
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity 
WHERE datname = 'cq';

select * from pg_stat_activity;
```

```
journalctl -u cloud-final
```

audit role trust
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::087806813403:role/@hcdb_svr_role"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

```
PGPASSWORD=$(aws rds generate-db-auth-token --hostname \$RDS_ENDPOINT --port 5432 --username cqwrite)
psql -h $RDS_ENDPOINT -U cqwrite -d cq
```