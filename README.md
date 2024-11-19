
# Steampipe and Cloudquery as a Centralized Service

The aim of this solution is to provide a centralized service for doing SQL
queries of AWS infrastructure and services data against the entire fleet of AWS
accounts. This provides useful capabilities to do analysis in SQL which most
technical people are familiar with. It is much faster than writing scripts. It
provides structured data. And it can treat the entire set of ExampleCo AWS accounts
as an aggregate. The architecture is useful for both ad-hoc analysis and data
pipelining. The data can be used to align with architecture pillars like cost
optimization, security, and operational excellence.

The solution leverages [steampipe](https://steampipe.io/) and
[cloudquery](https://www.cloudquery.io/) (community editions) to offer two
different options. Each of those two products provides a SQL interface to the
AWS APIs. And each provide for a different use case.

Steampipe wraps the AWS APIs directly. The data is real time, but queries can take
longer to run. This is useful for ad hoc analysis.

Cloudquery uses ETL to synchronize AWS APIs to a database. The data is a
snapshot, but the queries are fast. This is usefel for point in time analysis
and feeding data pipelines (like data warehouses or data lakes).

The solution is dependent on AWS roles. There needs to be an @audit_role in
every account that has the appropriate ReadOnlyAcces policy and trusts the
@hcdb_svr_role. The diagram below describes the architecture.

![Diagram](architecture-diagram.drawio.svg)

There are three services available, ssh, steampipe, and cloudquery, each with
two **secure** ways of accessing them. They can be accessed directly over the
internet with two factor authentication (different mechanisms per service). Or
they can be accessed over a secure SSM session manager tunnel.

## Prerequisites

- Access to the Delivery Org's audit account with permissions to see secrets, ec2, and rds.
- Client tools, AWS CLI, SSH and Postgres installed on your workstation
- The SSM session-manager-plugin installed on your workstation
- Oathtool for generating an OTP from a TOTP installed on your workstation

## Trying the Solution

> At this time, as a demo, scope is limited to the Delivery org's Org account and Audit
account (087806813403,640090909562). So, you'll need to login to the audit
account (087806813403) to get the details and secrets needed for the examples below. 

### Running the Test Harness, test.sh

The `test.sh` script will get all the necessary values from AWS, setup your SSH
key and your steampipe postgres keys. Then it will run through each service
using each connection method. The only thing you'll need to do is be logged into
the Audit account as an administrator, accept SSH host keys (possibly) and
copy/paste OTP values into the SSH login.

A succesful test will look something like this

```
❯ assume AuditD/AWSAdministratorAccess
[✔] [AuditD/AWSAdministratorAccess](us-east-2) session credentials will expire in 1 hour
❯ ./test.sh
Reading values from AWS
$RDS_ENDPOINT=hcdb-rds.ctg3db2ebws4.us-east-2.rds.amazonaws.com
$RDS_READ_USER=cqread
$RDS_WRITE_USER=cqwrite

$EC2_ID=i-031b368367c8a19ff
$EC2_DNS=ec2-3-147-73-200.us-east-2.compute.amazonaws.com
$EC2_USER=ec2-user
$EC2_TOTP=**********
EC2_SSH_KEY is in ~/.ssh/hcdb

$STEAMPIPE_PASSWORD=**********
$STEAMPIPE_USER=steampipe

CLIENT_CERT is in ~/tmp/client.crt
CLIENT_KEY is in ~/tmp/client.key
CLIENT_ROOT is in ~/tmp/root.crt

********************************************************************************
TESTING SSH OVER INTERNET
(copy and paste the OTP code)
********************************************************************************
595839
(ec2-user@ec2-3-147-73-200.us-east-2.compute.amazonaws.com) One Time Passcode:
SUCCESS

********************************************************************************
SLEEP 15s for TOTP to cycle
********************************************************************************
1 2 3 4 5 6 7 8 9 10 11 12 13 14 15

********************************************************************************
TESTING SSH OVER TUNNEL
(copy and paste the OTP code)
********************************************************************************
647439
(ec2-user@i-031b368367c8a19ff) One Time Passcode:
SUCCESS

********************************************************************************
TESTING STEAMPIPE OVER INTERNET
********************************************************************************
  account_id  | count
--------------+-------
 087806813403 |    26
 640090909562 |    32

********************************************************************************
TESTING STEAMPIPE OVER TUNNEL
********************************************************************************

Starting session with SessionId: Jim.Weller@exampleco.com-0100f2a0d6c647b7d
Port 9193 opened for sessionId Jim.Weller@exampleco.com-0100f2a0d6c647b7d.
Waiting for connections...

Connection accepted for session [Jim.Weller@exampleco.com-0100f2a0d6c647b7d]
  account_id  | count
--------------+-------
 087806813403 |    26
 640090909562 |    32

********************************************************************************
TESTING CLOUDQUERY OVER INTERNET
********************************************************************************
  account_id  | count
--------------+-------
 640090909562 |    32
 087806813403 |    26

********************************************************************************
TESTING CLOUDQUERY OVER TUNNEL
********************************************************************************

Starting session with SessionId: Jim.Weller@exampleco.com-0505b09539484f592
Port 5432 opened for sessionId Jim.Weller@exampleco.com-0505b09539484f592.
Waiting for connections...

Connection accepted for session [Jim.Weller@exampleco.com-0505b09539484f592]
  account_id  | count
--------------+-------
 640090909562 |    32
 087806813403 |    26

********************************************************************************
TESTING RDS SECURITY. "PAM authentication failed" is SUCCESS. NON-IAM SHOULD FAIL
********************************************************************************
psql: error: connection to server at "hcdb-rds.ctg3db2ebws4.us-east-2.rds.amazonaws.com" (18.218.27.244), port 5432 failed: FATAL:  PAM authentication failed for user "hcdb"

```





### Connecting to Steampipe Over Internet with MFA

This method of accessing steampipe over a postgres connection uses a client
key+cert pair as a second form of authentication on top of the password. The
certificates you'll need are in the hcdb_secret in the audit account.

Use a postgres client. I'm using PgAdmin4

- Host: [get the EIP from the hcdb-svr1 EC2 instance]
- Port: 9193
- User: steampipe
- Password: [get the password from the hcdb_secret in secret manager]
- Database: steampipe
- SSL Mode - sslmode=require
- Root certificat - ssl_ca_file=~/tmp/root.crt [get from secret manager]
- Client certificate - ssl_cert_file=~/tmp/client.crt [get from secret manager]
- Client certificate key - ssl_key_file=~/tmp/client.key [get from secret manager]

Open your Postgres client and fill the the fields and parameters to get connected.

> Run the below query to get the count of iam_roles in each connected account. Note how you are accessing more than one account in a single query.

```
select account_id,count(account_id) from dlv.aws_iam_role group by account_id
```

| account_id | count |
| - | - |
| 087806813403 | 26  |
| 640090909562 | 32  |

### Connecting to Steampipe Over Secure Tunnel

This method of accessing steampipe over a postgres connection uses SSM's ability
to create session manager tunnels. So, you'll use the AWS command line to open a
tunnel where a local port on your workstation will be forwarded to a remote
port. MFA in this case is standard ExampleCo Okta logins to AWS.

Use a postgres client. I'm using PgAdmin4

- EC2 Instance ID: [get the instance ID from the hcdb-svr1 EC2 instance]
- Localhost: 127.0.0.1
- Port: 9193
- User: steampipe
- Password: [get the password from the hcdb_secret in secret manager]
- Database: steampipe
- SSL Mode - sslmode=require


First establish the secure tunnel making sure that you are logged in on your terminal with current AWS credentials.
```
aws ssm start-session --target i-0a4fd9646dcc6baa8 --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters portNumber="9193",localPortNumber="9193"
```

Now you can connect your postgres client to 127.0.0.1 port 9193

> Run the below query to get the count of iam_roles in each connected account. Note how you are accessing more than one account in a single query.

```
select account_id,count(account_id) from dlv.aws_iam_role group by account_id
```

| account_id | count |
| - | - |
| 087806813403 | 26  |
| 640090909562 | 32  |

You can break the tunnel by interupting the AWS command line with CTL+C

### Connecting to Cloudquery with IAM Credentials Over Internet

This method uses the aws cli to get an RDS token/password. It is a more
complicated architecture in that it requires a change to the TF policy for
RdsIam. If the policy is not already applied via a PermissionSet from the org
account, that needs to be done first. You'll need to edit the policy in the
Audit account directly since TF can't update it once it is attached to an AWS
reserved role.

- RDS Endpoint: [get the endpoint from the hcdb RDS instance]
- Port: 5432
- DB User: cqread
- Database: cq
- SSL Mode - sslmode=require


First, make sure that you AWS username (@exampleco.com) is added to the policy
HcdbRdsConnectSaml. It is case sensitive. You get get it from the aws cli with
`aws sts get-caller-idenity` get a token. This allows you to get an RDS token
which will be used as your password.


Next generate a DB auth token with the aws cli. This will be your password for the database. Make sure you are using
the AWSReadOnlyAccess role from your aws config since that is where the PermissionSet attaches the RdsIam policy.

RDSHOST=hcdb-rds.ctg3db2ebws4.us-east-2.rds.amazonaws.com
DBUSER=cqread
aws rds generate-db-auth-token --hostname $RDSHOST --port 5432 --username $DBUSER

Finally, open your postgres client and configure it with the RDS endpoint, username,
sslmode, and the password (DB token) you just generated. You have 30 seconds to
use the token.


> Run the below query to get the count of iam_roles in each connected account.

```
select account_id,count(account_id) from aws_iam_roles group by account_id
```

| account_id | count |
| - | - |
| 640090909562 | 32  |
| 087806813403 | 26  |


### Connecting to Cloudquery with Secure Tunnel

Use a postgres client (pgadmin)

- EC2 Instance ID: [get the instance ID from the hcdb-svr1 EC2 instance]
- RDS Endpoint: [get the endpoint from the hcdb RDS instance]
- Localhost: 127.0.0.1
- Port: 5432
- DB User: hcdb
- Password: [get the password from the hcdb_secret in secret manager]
- Database: hcdb
- SSL Mode - sslmode=require

First establish the secure tunnel making sure that you are logged in on your terminal with current AWS credentials.

```
aws ssm start-session --target i-094d28b30413b0805 --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters host="hcdb-rds.ctg3db2ebws4.us-east-2.rds.amazonaws.com",portNumber="5432",localPortNumber="5432"
```

Now you can connect your postgres client to 127.0.0.1 port 5432


> Run the below query to get the count of iam_roles in each connected account.

```
select account_id,count(account_id) from aws_iam_roles group by account_id
```

| account_id | count |
| - | - |
| 640090909562 | 32  |
| 087806813403 | 26  |

You can break the tunnel by interupting the AWS command line with CTL+C

### Connecting to EC2 SSH with internet and MFA

This is a normal vanilla SSH session, except that you will be prompted for an
OTP code which you can generate on the command line.

- EC2 Public DNS: [get the public DNS from the hcdb-svr1 EC2 instance]
- TOTP Token: [get the TOTP from the hcdb_secret]
- SSH private key: [get the private key from the hcdb_secret]

First establish a private key as an alternate identity

```
cat <<EOF> ~/.ssh/hcdb
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNAaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDD3dqDWsw2KumzL2MIUReDrPydJqwYUr+MdzNesQ1yLwAAAJjkb5D05G+Q
9AAAAAtzc2gtZWQyNTUxOQAAACDD3dqDWsw2KumzL2MIUReDrPydJqwYUr+MdzNesQ1yLw
AAAEAMZfhnksENu2TsOUVDmIF3y76phrahGTzONIZTytLxdcPd2oNazDYq6bMvYwhRF4Os
/J0mrBhSv4x3M16xDXIvAAAAFGhjZGJAaHlsYW5kY2xvdWQuY29tAQ==
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 ~/.ssh/hcdb
```

Now in one terminal ssh to the EIP as the ec2-user

```
ssh -i ~/.ssh/hcdb ec2-user@ec2-3-144-29-131.us-east-2.compute.amazonaws.com
```

You'll be prompted for a One Time Passcode

```
(ec2-user@ec2-3-144-29-131.us-east-2.compute.amazonaws.com) One Time Passcode:
```

In another terminal, use the TOTP to generate the OTP

```
oathtool --totp --b AA62BBCX7WBVKWDR3QOBGWO73Z
```

Use the OTP in the original terminal at the One Time Passcode prompt and you'll
be logged into the EC2 server. Run `aws sts get-caller-identity` to see that the
ec2 instance has a role attached as an instance profile.

```
(ec2-user@ec2-3-144-29-131.us-east-2.compute.amazonaws.com) One Time Passcode:
   ,     #_
   ~\_  ####_        Amazon Linux 2023
  ~~  \_#####\
  ~~     \###|
  ~~       \#/ ___   https://aws.amazon.com/linux/amazon-linux-2023
   ~~       V~' '->
    ~~~         /
      ~~._.   _/
         _/ _/
       _/m/'
[ec2-user@ip-10-0-0-171 ~]$ aws sts get-caller-identity
{
    "UserId": "AROARI4NRUTNSJ4XLLGPN:i-094d28b30413b0805",
    "Account": "087806813403",
    "Arn": "arn:aws:sts::087806813403:assumed-role/@hcdb_svr_role/i-094d28b30413b0805"
}
```

### Connecting to EC2 SSH with Secure Tunnel and MFA

This is a special SSH session that uses SSM session manager to tunnel the SSH
connection.

- EC2 Instance ID: [get the instance ID from the hcdb-svr1 EC2 instance]
- TOTP Token: [get the TOTP from the hcdb_secret]
- SSH private key: [get the private key from the hcdb_secret]

First establish a private key as an alternate identity

```
cat <<EOF> ~/.ssh/hcdb
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNAaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDD3dqDWsw2KumzL2MIUReDrPydJqwYUr+MdzNesQ1yLwAAAJjkb5D05G+Q
9AAAAAtzc2gtZWQyNTUxOQAAACDD3dqDWsw2KumzL2MIUReDrPydJqwYUr+MdzNesQ1yLw
AAAEAMZfhnksENu2TsOUVDmIF3y76phrahGTzONIZTytLxdcPd2oNazDYq6bMvYwhRF4Os
/J0mrBhSv4x3M16xDXIvAAAAFGhjZGJAaHlsYW5kY2xvdWQuY29tAQ==
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 ~/.ssh/hcdb
```

Add this line to you ~/.ssh/config file. This tells SSH that any hosts that begin with `i-`
should use a ProxyCommand (aws in this case) to establish the connection.

```
host ssh i-*
   ProxyCommand sh -c "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'"
```

Now in one terminal use ssh to specify ec2-user at the instance id. Notice how
we are using an instance id instead of an IP or DNS.

```
ssh -i ~/.ssh/hcdb ec2-user@i-094d28b30413b0805
```

You'll be prompted for a One Time Passcode

```
(ec2-user@ec2-3-144-29-131.us-east-2.compute.amazonaws.com) One Time Passcode:
```

In another terminal, use the TOTP to generate the OTP

```
oathtool --totp --b AA62BBCX7WBVKWDR3QOBGWO73Z
```

Use the OTP in the original terminal at the One Time Passcode prompt and you'll
be logged into the EC2 server. Run `aws sts get-caller-identity` to see that the
ec2 instance has a role attached as an instance profile.

```
(ec2-user@ec2-3-144-29-131.us-east-2.compute.amazonaws.com) One Time Passcode:
   ,     #_
   ~\_  ####_        Amazon Linux 2023
  ~~  \_#####\
  ~~     \###|
  ~~       \#/ ___   https://aws.amazon.com/linux/amazon-linux-2023
   ~~       V~' '->
    ~~~         /
      ~~._.   _/
         _/ _/
       _/m/'
[ec2-user@ip-10-0-0-171 ~]$ aws sts get-caller-identity
{
    "UserId": "AROARI4NRUTNSJ4XLLGPN:i-094d28b30413b0805",
    "Account": "087806813403",
    "Arn": "arn:aws:sts::087806813403:assumed-role/@hcdb_svr_role/i-094d28b30413b0805"
}
```


## Notes

- All the keys, tokens, and passwords necessary for you, as a client, are stored in a single secret manager secret, hcdb_secret
- The EC2 is immutable you can destroy it. It will rehydrate when recreated. The secrets, ip, and instance id will change. So, you'll have to refresh your local setup.
- The EC2 always needs outbound internet access to download tools during first boot.
- the @audit_role role trust relationship identifies the arn's that can assume the role with a CONDITION instead of the PRINCIPAL because if you delete the arn it replaces it with an ID (that doesn't exist). This is necessary for constantly redeploying the solution. The CONDTION does not get replaced since it is a string. It has the same trust effect. Subtle difference.


## TODO Items
- get the @audit_role in all accounts in all orgs (AFTc or CFTs?)
- extend the aws/steampipe configuration generation to include foundation and heritage orgs
- DNS and/or Static IP addresses?
- Upgrade software and generate configuration on every boot instead of just at launch
- Break the user_data script into mime components a la cloudinit. This will allow some of the config files to be assets in a repo instead of `echo` commands in scripts.
- Steampipe aggregators. It'd be great to pivot them by org (dlv*, fnd*, lxk*) and one giant one (aws*)
- Use real certs for steampipe?
