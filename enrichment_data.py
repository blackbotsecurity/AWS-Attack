def blackbot_ttp_detection(blackbot_id, external_id, version):
    blackbot_ttp_detection = {
            "blackbot_id": blackbot_id,
            "external_id": external_id,
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
            "aws_artifact": "",
        }
    return blackbot_ttp_detection

def mitre_ttp_mitigation(blackbot_id, external_id, version):
    mitre_ttp_mitigation = {
            "external_references": [],                      # Usually, the first one the mitigation ID , URL, and source: . We dont need the third-party refernces yet.     
            "name": "",                                     # Usually at the begining of each file
            "description": "",                              # Usually at the begining of each file
            "type": "",                                     # Usually at the begining of each file
            "id": "",                                       # Usually at the begining of each file - course-of-action--* 
            "object_marking_refs": [],                      # Get all of them
            "type": "",                                     # Likely course-of-action, but may include other values
            "mid_desc_video": "",                           # Enriched by Rust from Blackbot mitigation-video.json
            "x_mitre_defense_bypassed": [],                 # Enriched by Rust from enterprise-attack.json 
            "x_mitre_detection": "",                        # Enriched by Rust from enterprise-attack.json 
            "x_mitre_data_sources": [],                     # Enriched by Rust from enterprise-attack.json 
            "x_mitre_platforms": [],                        # Enriched by Rust from enterprise-attack.json 
            "object_marking_refs": [],                      # Enriched by Rust from enterprise-attack.json
            "blackbot_id": blackbot_id,          # Enriched by C2
            "external_id": external_id,          # Enriched by C2: Same as external_references
            "type": "",                                     # Typcially, "bundle" 
            "id": "",                                       # usually bundle--.*  
            "spec_version": "",
            }

    return mitre_ttp_mitigation

def mitre_ttp_exec(blackbot_id, external_id, version):
    mitre_ttp_exec = {
            "blackbot_id": blackbot_id,          # Enriched by C2
            "external_id": external_id,          # Enriched by C2 - Same as external_references
            "name": "",                                     # Enriched by Rust from enterprise-attack.json
            "intent": "",                                   # Enriched by C2 - Extract key data from MITRE Description. Eventually, move to Blackbot intent.json
            "kill_chain_phases": [],                        # Enriched by Rust from enterprise-attack.json -> coupled with "kill_chain_name" : "mitre-attack"  only
            "url": "",                                      # Enriched by Rust from enterprise-attack.json -> exernal_references
            "x_mitre_is_subtechnique": "",                  # Enriched by Rust from enterprise-attack.json : Type: Boolean
            "x_mitre_permissions_required": [],             # Enriched by Rust from enterprise-attack.json 
            "object_marking_refs": [],                      # Enriched by Rust from enterprise-attack.json
            "created_by_ref": "",                           # Enriched by Rust from enterprise-attack.json
            "external_references": [],                      # Enriched by Rust from enterprise-attack.json - Get from external_references :  ["url": ""]
            "id": "",                                       # Enriched by Rust from enterprise-attack.json - attack-pattern--*
            "type": "",                                     # Enriched by Rust from enterprise-attack.json                   
            "cid": "",                                      # Enriched by C2 - Customer ID
            "version": version,                  # Enriched by C2
            }

    return mitre_ttp_exec



