#Each name represents the name of the TTP

valid_account_info = {
        'blackbot_id': 'T1078.004',
        'external_id': '',
        'used_by': '',
        'services': [],
        'prerequisite_modules': [],
        'arguments_to_autocomplete': [],
        'version': '1',
        'last_updated_by': '@Blackbot',
        'intent': 'Adversaries may obtain and abuse credentials of a cloud account as initial access',
        'name': 'Valid Accounts: Cloud Accounts',

}

cloud_service_region = {
        'blackbot_id': 'T1526.b.004',
        'external_id': '',
        'used_by': '',
        'services': [],
        'prerequisite_modules': [],
        'arguments_to_autocomplete': [],
        'version': '1',
        'last_updated_by': '@Blackbot',
        'intent': '',
        'name': '',

}

modify_user_agent = {
        'blackbot_id': 'T1070.b.001',
        'external_id': '',
        'used_by': '',
        'services': ['any'],
        'prerequisite_modules': [],
        'arguments_to_autocomplete': [],
        'version': '1',
        'last_updated_by': '@Blackbot',
        'intent': 'Aversaries will attempt to modify the user-agent string of HTTP requests to evade web aplication defenses',
        'name': 'Masquerading: Rename User-Agent String',

}

iam_policy_discovery = {
        'blackbot_id': 'T1069.b.001',
        'external_id': '',
        'used_by': '',
        'services': ['any'],
        'prerequisite_modules': [],
        'arguments_to_autocomplete': [],
        'version': '1',
        'last_updated_by': '@Blackbot',
        'intent': 'Adversaries may attempt to find group and permission settings.',
        'name':'Permission Groups Discovery: IAM Policy Discovery',

}

console_aws = {
        'blackbot_id': '',
        'external_id': '',
        'controller': 'get_aws_console',
        'services': ['any'],
        'prerequisite_modules': [],
        'arguments_to_autocomplete': [],
        'version': '1',
        'last_updated_by': '@Blackbot',
        'intent': '',
        'name':'',

}
