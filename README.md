# DESCRIPTION
AWSATT&CK is a modified version of [Rhino Security Labs's](https://github.com/RhinoSecurityLabs) open-source AWS exploitation framework, [Pacu](https://github.com/RhinoSecurityLabs/pacu) that adds MITRE ATT&CK context to Pacu tactics and additional logging capabilities.

# PHILOSOPHY

Blackbot Labs believes in creating tools where vendor solutions and open source can be provisioned and managed together by all organizations with the intent to deliver actionable attack intelligence organizations can use to define clear objectives and drive strategic security program initiatives.

### *Commitment*

- **INTEGRITY** 
We develop tools and frameworks that produce accurate attack intelligence to help security teams evaluate the integrity of their security solutions.

- **TRANSPARENCY**
We work under the umbrella of full transparency during all phases of tool and framework development. From striking up ideas with our community to enhancing the capabilities of tools used by red teams all over the world; if Blackbot Labs is brewing up a new tool or framework, you'll know about it.


- **AGILITY**
We take pride in enabling lean security teams to remain agile and focused on developing a unique trade-craft that's agnostic to certain tools developed by the red team community. Whether you're keeping tight margins between \(MTTD\) and  \(MTTR\) metrics or evaluating security controls, we'll be here building tools to help you get the job done faster.


- **SCALABILITY**
Scaling operational activities is critical to sustaining efficient security ecosystem workflows in modern environments. If our tools don't help you scale your operational capabilities, let us know and we'll fix it. 


- **FLEXIBILITY**
Blackbot Labs builds and delivers open source tools with the flexibility and intent for security professionals to improve their trade-craft and scale security testing initiatives in IT, OT, cloud-native and hybrid workspaces.


- **RAPID DEPLOYMENT**
Facilitating rapid deployment models is important to us. We'll do our best to deliver practical deployment frameworks that facilitate advanced security eco-systems and data-driven pipelines. 

# CAPABILITIES
AWSATT&CK enhances Pacu's post-exploitation tactics and logging capabilities with MITRE ATT&CK. We inlucded a `b` in a handful of techniques that aren't in the ATT&CK framework. Other light-weight enhancements include console opsec checks for cases wherein target environments require assessing multi-region environments.


| PACU TECHNIQUE | MITRE ATT&CK ID |
| ------ | ------ |
| ttp/api_gateway_create_api_keys.py: | T1543.b.001 |
| ttp/aws_enum_account.py: | T1087.004 |
| ttp/aws_enum_spend.py: | T1526.b.003 |
| ttp/cloudtrail_csv_injection.py: | T1078.004 |
| ttp/cloudtrail_download_event_history.py: | T1530 |
| ttp/cloudwatch_download_logs.py: | T1530 |
| ttp/codebuild_dumps_builds.py: | T1526 |
| ttp/codebuild_dumps_projects.py: | T1526 |
| ttp/codebuild_enum_builds.py: | T1526 |
| ttp/codebuild_enum_projects.py: | T1526 |
| ttp/detection_disruption_alarms.py: | T1526 |
| ttp/detection_disruption_cloudtrail.py: | T1526 |
| ttp/detection_disruption_config_aggregators.py: | T1526 |
| ttp/detection_disruption_config_recorders.py: | T1526 |
| ttp/detection_disruption_config_rules.py: | T1526 |
| ttp/detection_disruption_guardduty.py: | T1526 |
| ttp/detection_disruption_vpc.py: | T1526 |
| ttp/detection_enum_services_cloudtrail.py: | T1526 |
| ttp/detection_enum_services_cloudwatch.py: | T1526 |
| ttp/detection_enum_services_config.py: | T1526 |
| ttp/detection_enum_services_guardduty.py: | T1526 |
| ttp/detection_enum_services_shield.py: | T1526 |
| ttp/detection_enum_services_vpc.py: | T1526 |
| ttp/ebs_enum_snapshots.py: | T1526 |
| ttp/ebs_enum_volumes.py: | T1526 |
| ttp/ebs_explore_snapshots.py: | T1078.004 |
| ttp/ec2_backdoor_apply_rules_sec_groups.py: | T1526 |
| ttp/ec2_backdoor_enum_sec_groups.py: | T1562.007 |
| ttp/ec2_check_termination_protection.py: | T1562.b.008 |
| ttp/ec2_download_userdata_instances.py: | T1526 |
| ttp/ec2_download_userdata_templates.py: | T1526 |
| ttp/ec2_enum_customergateways.py: | T1018 |
| ttp/ec2_enum_dedicatedhosts.py: | T1018 |
| ttp/ec2_enum_elasticips.py: | T1018 |
| ttp/ec2_enum_instances.py: | T1018 |
| ttp/ec2_enum_launchtemplates.py: | T1018 |
| ttp/ec2_enum_natgateways.py: | T1018 |
| ttp/ec2_enum_networkinterfaces.py: | T1018 |
| ttp/ec2_enum_network.py: | T1018 |
| ttp/ec2_enum_routetables.py: | T1018 |
| ttp/ec2_enum_securitygroups.py: | T1018 |
| ttp/ec2_enum_subnets.py: | T1018 |
| ttp/ec2_enum_vpcendpoints.py: | T1018 |
| ttp/ec2_enum_vpcs.py: | T1018 |
| ttp/ec2_startup_shell_script.py: | T1078.004 |
| ttp/ecs_dumps_task_def.py: | T1530 |
| ttp/ecs_enum_clusters.py: | T1526 |
| ttp/ecs_enum_containers.py: | T1526 |
| ttp/ecs_enum_services.py: | T1526 |
| ttp/ecs_enum_taskdef.py: | T1526 |
| ttp/elb_enum_logging.py: | T1082 |
| ttp/enum_secrets_manager.py: | T1552.b.007 |
| ttp/enum_secrets_parameter_store.py: | T1552.b.007 |
| ttp/glue_enum_connections.py: | T1526 |
| ttp/glue_enum_crawlers.py: | T1526 |
| ttp/glue_enum_databases.py: | T1526 |
| ttp/glue_enum_devendpoints.py: | T1526 |
| ttp/glue_enum_jobs.py: | T1526 |
| ttp/iam_backdoor_assume_role.py: | T1484.b.001 |
| ttp/iam_backdoor_users_keys.py: | T1098.b.005 |
| ttp/iam_backdoor_users_password.py: | T1531.b.001 |
| ttp/iam_bruteforce_permissions.py: | T1526.b.002 |
| ttp/iam_build_service_list.py: | T1526.b.002 |
| ttp/iam_detect_honeytokens.py: | T1526 |
| ttp/iam_dumps_credential_report.py: | T1530 |
| ttp/iam_enum_groups.py: | T1087 |
| ttp/iam_enum_guessing_roles.py: | T1078.004 |
| ttp/iam_enum_guessing_users.py: | T1078.004 |
| ttp/iam_enum_policies.py: | T1087 |
| ttp/iam_enum_roles_permissions.py: | T1069.003 |
| ttp/iam_enum_roles.py: | T1087 |
| ttp/iam_enum_users_permissions.py: | T1069.003 |
| ttp/iam_enum_users.py: | T1087 |
| ttp/iam_get_credential_report.py: | T1087.004 |
| ttp/iam_privesc_scan.py: | T1526 |
| ttp/inspector_get_reports.py: | T1537.b.001 |
| ttp/lambda_backdoor_new_roles_cleanup.py: | T1098.b.005 |
| ttp/lambda_backdoor_new_roles.py: | T1098.b.005 |
| ttp/lambda_backdoor_new_sec_groups_cleanup.py: | T1098.b.005 |
| ttp/lambda_backdoor_new_sec_groups.py: | T1098.b.005 |
| ttp/lambda_backdoor_new_users_cleanup.py: | T1098.b.004 |
| ttp/lambda_backdoor_new_users.py: | T1098.b.004 |
| ttp/lambda_check_functions.py: | T1526 |
| ttp/lambda_enum.py: | T1526 |
| ttp/lightsail_download_ssh_keys.py: | T1530 |
| ttp/lightsail_enum_activenames.py: | T1526.b.001 |
| ttp/lightsail_enum_blueprints.py: | T1526.b.001 |
| ttp/lightsail_enum_bundles.py: | T1526.b.001 |
| ttp/lightsail_enum_disk_snapshots.py: | T1526.b.001 |
| ttp/lightsail_enum_disks.py: | T1526.b.001 |
| ttp/lightsail_enum_instances.py: | T1526.b.001 |
| ttp/lightsail_enum_keypairs.py: | T1526.b.001 |
| ttp/lightsail_enum_load_balancers.py: | T1526.b.001 |
| ttp/lightsail_enum_operations.py: | T1526.b.001 |
| ttp/lightsail_enum_staticips.py: | T1526.b.001 |
| ttp/lightsail_generate_ssh_keys.py: | # |
| ttp/lightsail_generate_temp_access.py: | T1098.b.005 |
| ttp/rds_explore_snapshots_cleanup.py: | T1530 |
| ttp/rds_explore_snapshots.py: | T1530 |
| ttp/s3_download_bucket.py: | T1526 |
| ttp/s3_enum_bucket.py: | T1526 |
| ttp/systemsmanager_rce_ec2.py: | T1569.b.001 |
| ttp/vpc_enum_directconnect.py: | T1046 |
| ttp/vpc_enum_peering.py: | T1046 |
| ttp/vpc_enum_vpn.py: | T1046 |
| ttp/waf_enum.py: | T1518.b.002 |


##LOGGING ENHANCEMENTS
JSON logging is enrichmented with MITRE ATT&CK techniques and additional fields that make it easy for operators to identify and mitigate AWS security defenses. 
```
{
  "technique_info": {
    "blackbot_id": "T1078.004",
    "external_id": "",
    "used_by": "",
    "services": "sts",
    "prerequisite_modules": [],
    "arguments_to_autocomplete": [],
    "version": "1",
    "last_updated_by": "@User",
    "intent": "Adversaries may obtain and abuse credentials of a cloud account as initial access",
    "name": "Valid Accounts: Cloud Accounts",
    "evidence_status": "1"
  },
  "ttp_exec": {
    "blackbot_id": "T1078.004",
    "external_id": "",
    "name": "",
    "intent": "",
    "kill_chain_phases": [],
    "url": "",
    "x_mitre_is_subtechnique": "",
    "x_mitre_permissions_required": [],
    "object_marking_refs": [],
    "created_by_ref": "",
    "external_references": [],
    "id": "",
    "type": "",
    "cid": "",
    "version": "1"
  },
  "ttp_mitigation": {
    "external_references": [],
    "name": "",
    "description": "",
    "type": "",
    "id": "",
    "object_marking_refs": [],
    "mid_desc_video": "",
    "x_mitre_defense_bypassed": [],
    "x_mitre_detection": "",
    "x_mitre_data_sources": [],
    "x_mitre_platforms": [],
    "blackbot_id": "T1078.004",
    "external_id": "",
    "spec_version": ""
  },
  "ttp_detection": {
    "blackbot_id": "T1078.004",
    "external_id": "",
    "aws_iam": "",
    "aws_single": "",
    "aws_cognito": "",
    "aws_directory_service": "",
    "aws_access_manager": "",
    "aws_organization": "",
    "aws_security_hub": "",
    "aws_guardduty": "",
    "aws_inspector": "",
    "aws_config": "",
    "aws_cloudtrail": "",
    "aws_iot_defender": "",
    "aws_network_firewall": "",
    "aws_shield": "",
    "aws_waf": "",
    "aws_firewall_manager": "",
    "aws_macie": "",
    "aws_kms": "",
    "aws_cloud_hsm": "",
    "aws_cerficate_manager": "",
    "aws_secrets_manager": "",
    "aws_detective": "",
    "cloudendure": "",
    "aws_artifact": ""
  },
  "evidence_status": "",
  "event_id": "SWcAygC3Iclcr",
  "ac_id": "",
  "evidence": {
    "aws_access_key_id": "2k3i9f6vtdh4g0f982l5qltc52k3ofo8dg5",
    "aws_secret_access_key": "63dkic9spofuighsduf4567hna76slhj2p7v",
    "aws_session_token": null,
    "regions": null
  }
```

## MITRE ATT&CK COVERAGE
- [MITRE ATT&CK Coverage Map](https://attack.blackbot.io)




## USE CASES 
- SOCs, AWS Security engineers, DevSecOps, teams need to evaluate AWS workload protection against targeted AWS attacks and map results to MITRE ATT&CK

GET INVOLVED
[Join the Pacu community on slack](https://join.slack.com/t/pacu-cloudgoat/shared_invite/enQtNDE3OTk0MjA3NTA2LTRmOTVmZjEyYjIzOTYxMGJmZDc4ZDVkOGU3ZmJlOWZhNzdkYWQ2ZmQxNTFjZThjMmJlMDFmMTU4NzUwMDM2NmY)


## DOCUMENTATION:
Checkout the [Pacu wiki](https://github.com/RhinoSecurityLabs/pacu/wiki)  



## CODE OF CONDUCT

Blackbot Labs operates under the umbrella of full transparency while ensuring end-user privacy remains a top priority. For more details on how we operate with our community, visit our community page.

[https://blackbot.io/community](https://blackbot.io/community)

## Disclaimers, and the AWS Acceptable Use Policy

AWSATT&CK enhancements and and Pacu's capabilities are compliant with the AWS Acceptable Use Policy. 
    For opsec safe operations, request authorization from Amazon before actually running AWSATT&CK against your infrastructure.    
    

## CREDITS & ACKNOWLEDGEMENTS 

- [Rhino Security Labs](https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/) - for releasing a solid framework.
- Spenscer Gietzen [@SpenGietz](https://twitter.com/SpenGietz) and all [PACU](https://github.com/RhinoSecurityLabs/pacu) project contributors.
 