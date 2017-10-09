# PROJECT SPACECRAB #

~~~
  __                __
 / /_   ___   ___  _\ \
 \  /  (_*_) (_*_) \  /                          PROJECT
  { }    |     |   { }    _____ ____  ___   ______________________  ___    ____
   \\/''''''''''''\//    / ___// __ \/   | / ____/ ____/ ____/ __ \/   |  / __ )
   (  . + *   ˚  .  )    \__ \/ /_/ / /| |/ /   / __/ / /   / /_/ / /| | / __ \
    \  +   +  * ˚  /    ___/ / ____/ ___ / /___/ /___/ /___/ _, _/ ___ |/ /_/ /
     \  ˚   *  ˚  /    /____/_/   /_/  |_\____/_____/\____/_/ |_/_/  |_/_____/
     //'//''''\\'\\
     V  V      V  V
~~~

Bootstraps an AWS account with everything you need to generate, mangage, and distribute and alert on AWS honey tokens. Made with breakfast roti by the Atlassian security team.

No added cyber.

AWS access keys are always a target for attakers and there's no way for them to determine a key is a honey token up front. The attacker attempt to use it on the Internet accessible, fully logged, AWS API. 

It's trivial to create one access key and use it as a honey token but it quickly becames impossible to create hundreds or thousands and automatically expire them, report on them, and alert on them. The goodies in this repo make all of that easy and secure.

Configure your aws cli with root or admin access and run `python manager.py` to get started.

## Authors ##

* @dagrz
* @danbourke

## Overview ##

### Quickstart ###
1. Ensure you have valid AWS credentials in your environment.
2. Run `python manager.py` and answer the questions.

### Slower Start ###
1. Build an empty AWS account, that you will only use for this alerting. You're going to distribute these keys all over the place, and they're relatively safe but keep it away from your prod infrastructure.
2. Generate a https://v2.developer.pagerduty.com/v2/docs/events-api-v2 integration key. Set up the integration to alert to the relevant groups, etc.
3. Configure a domain for AWS's Simple Email Service. There's a lot of documentation about that, start https://aws.amazon.com/ses/ for details. You can also just configure one email address, which might be easier.
4. If you have a tagging policy for your AWS infrastructure, edit tags.json to make sure they meet your requirements.
5. Ensure you have valid AWS credentials for the account you've created.
6. Run `python manager.py` and answer the questions.
7. Wait about half an hour.
8. Check in the AWS console to see if the cloudformation stacks have built.
9. If something has gone wrong just delete "SpaceCrabStack" and start again, tbh.
10. No, we don't know why it doesn't work sometimes. It should work all the time. It is a mystery.


### Parameters ###

The following parameters are passed to the master CloudFormation stack `./CloudFormationTemplates/bootstrap.template`:

* FunctionCodeBucket - The name of the bucket where lambda code lives
* TemplateCodeBucket - The name of the bucket where cloudformation templates live
* MasterDatabaseUser - Token database root user
* MasterDatabasePassword - Token database root password
* FunctionDatabaseUser - Lower privilege database user used by lambda functions
* FunctionDatabasePassword - Lower privilege database password used by lambda functions
* IamTokenUserPath - The path honey tokens are placed under (identifiable by get-caller-identity)
* IamPath - The path of all other IAM resource (not identifiable by get-caller-identity)
* PagerdutyApiToken - A pagerduty events v2 integration key
* AlertEmailAddress - An email address that will can receive alerts
* AlertFromAddress - The email address that will send alerts.

### Resources created ###

* to do

### Requirements ###

* awscli
* boto3

## How to ##

### Create a new honey token ###

~~~~
aws lambda invoke \
  --function-name AddTokenFunction \
  --payload '{ "Location":"Production web server", "Owner":"Jane Smith", "Notes":"Generated manually", "ExpiresAt":"2016-01-01 00:00:00" }' \
  /tmp/out.txt
cat /tmp/out.txt | jq .
~~~~

OR
~~~
python examples/GetHoneyToken.py
~~~

### Update an existing honey token ###

~~~~
aws lambda invoke \
  --function-name UpdateTokenFunction \
  --payload '{ "AccessKeyId":"AKIAJH6CN6HM6PWZXSLQ", "Location":"Test web server", "Owner":"John Smith", "Notes":"Updated by Jane", "ExpiresAt":"2017-01-01 00:00:00" }' \
  /tmp/out.txt
cat /tmp/out.txt | jq .
~~~~

### Delete an existing honey token ###

~~~~
aws lambda invoke \
  --function-name DeleteTokenFunction \
  --payload '{"AccessKeyId":"AKIAJH6CN6HM6PWZXSLQ"}' \
  /tmp/out.txt
cat /tmp/out.txt | jq .
~~~~

### Back up the honey token database immediately ###

~~~~
aws lambda invoke \
  --function-name BackupFunction \
  --payload '{}' \
  /tmp/out.txt
cat /tmp/out.txt | jq .
~~~~

### Change how user names are generated ###

Edit `./GenerateUsernameFunction/index.py`


# Contributors

Pull requests, issues and comments welcome. For pull requests:

* Add tests for new features and bug fixes
* Follow the existing style
* Separate unrelated changes into multiple pull requests

See the existing issues for things to start contributing.

For bigger changes, make sure you start a discussion first by creating an issue and explaining the intended change.

Atlassian requires contributors to sign a Contributor License Agreement, known as a CLA. This serves as a record stating that the contributor is entitled to contribute the code/documentation/translation to the project and is willing to have it used in distributions and derivative works (or is willing to transfer ownership).

Prior to accepting your contributions we ask that you please follow the appropriate link below to digitally sign the CLA. The Corporate CLA is for those who are contributing as a member of an organization and the individual CLA is for those contributing as an individual.

* [CLA for corporate contributors](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=e1c17c66-ca4d-4aab-a953-2c231af4a20b)
* [CLA for individuals](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=3f94fbdc-2fbe-46ac-b14c-5d152700ae5d)

# Copyright

Copyright @ 2017 Atlassian and others.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
