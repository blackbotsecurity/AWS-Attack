#!/usr/bin/env python3
import copy
import importlib
import json
import os
import random
import re
import shlex
import subprocess
import datetime
import sys
import time
import traceback
import argparse
from els import do_api_upload
from default_ttps import valid_account_info, cloud_service_region, iam_policy_discovery, modify_user_agent, console_aws
from enrichment_data import mitre_ttp_exec, mitre_ttp_mitigation, blackbot_ttp_detection
import uuid
import random
import string

try:
    import requests
    import boto3
    import botocore
    import urllib.parse

    import configure_settings
    import settings

    from core.models import AWSKey, awsattackSession
    from setup_database import setup_database_if_not_present
    from utils import get_database_connection, set_sigint_handler
except ModuleNotFoundError as error:
    exception_type, exception_value, tb = sys.exc_info()
    print('⣿ awsattack :≫⣿ awsattack :≫ Traceback (most recent call last):\n{}{}: {}\n'.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value)))
    print('⣿ awsattack :≫ ERROR: "Unable to start", reason: "Required Python package was not found".')
    print('⣿ awsattack :≫ Run `sh install.sh` to check and install awsattack\'s Python requirements.')
    sys.exit(1)


class Main:

    COMMANDS = [
        'aws', 'data', 'exec', 'exit', 'help', 'import_keys', 'list', 'run-attack',
        'ls', 'quit', 'regions', 'run', 'search', 'services', 'set_keys', 'set_regions',
        'swap_keys', 'update_regions', 'whoami', 'change_session', 'sessions', 'delete_session', 'export_keys', 'open_console', 'console', 'check_user_agent'
    ]

    def __init__(self):
        self.database = None
        self.running_technique_names = []

        self.ac_id = ''
        self.event_id = ''
        self.current_technique = ''
        self.chain = False

    # Utility methods

    def log_error(self, text, exception_info=None, session=None, local_data=None, global_data=None):
        """ Write an error to the file at log_file_path, or a default log file
        if no path is supplied. If a session is supplied, its name will be used
        to determine which session directory to add the error file to. """

        timestamp = time.strftime('%F %T', time.gmtime())

        if session:
            session_tag = '({})'.format(session.name)
        else:
            session_tag = '<No Target Session>'

        try:
            if session:
                log_file_path = 'sessions/{}/awsattack_error.log'.format(session.name)
            else:
                log_file_path = 'awsattack_global_error.log'

            print('\n[{}] awsattack encountered an error while running the previous command. Check {} for technical details. [LOG LEVEL: {}]\n\n    {}\n'.format(timestamp, log_file_path, settings.ERROR_LOG_VERBOSITY.upper(), exception_info))

            log_file_directory = os.path.dirname(log_file_path)
            if log_file_directory and not os.path.exists(log_file_directory):
                os.makedirs(log_file_directory)

            formatted_text = '[{}] {}: {}'.format(timestamp, session_tag, text)

            if settings.ERROR_LOG_VERBOSITY.lower() in ('low', 'high', 'extreme'):
                if session:
                    session_data = session.get_all_fields_as_dict()
                    # Empty values are not valid keys, and that info should be
                    # preserved by checking for falsiness here.
                    if session_data.get('secret_access_key'):
                        session_data['secret_access_key'] = '****** (Censored)'

                    formatted_text += 'SESSION DATA:\n    {}\n'.format(
                        json.dumps(
                            session_data,
                            indent=4,
                            default=str
                        )
                    )

            if settings.ERROR_LOG_VERBOSITY.lower() == 'high':
                if local_data is not None and global_data is not None:
                    formatted_text += '\nLAST TWO FRAMES LOCALS DATA:\n    {}\n'.format('\n\n    '.join(local_data[:2]))
                    formatted_text += '\nLAST TWO FRAMES GLOBALS DATA:\n    {}\n'.format('\n\n    '.join(global_data[:2]))

            elif settings.ERROR_LOG_VERBOSITY.lower() == 'extreme':
                if local_data is not None and global_data is not None:
                    formatted_text += '\nALL LOCALS DATA:\n    {}\n'.format('\n\n    '.join(local_data))
                    formatted_text += '\nALL GLOBALS DATA:\n    {}\n'.format('\n\n    '.join(global_data))

            formatted_text += '\n'

            with open(log_file_path, 'a+') as log_file:
                log_file.write(formatted_text)

        except Exception as error:
            print('⣿ awsattack :≫ ERROR: Exception raised: {}'.format(str(error)))
            raise

    # @message: String - message to print and/or write to file
    # @output: String - where to output the message: both, file, or screen
    # @output_type: String - format for message when written to file: plain or xml
    # @is_cmd: boolean - Is the log the initial command that was run (True) or output (False)? Devs won't touch this most likely
    def print(self, message='', output='both', output_type='plain', is_cmd=False, session_name=''):
        session = self.get_active_session()

        if session_name == '':
            session_name = session.name

        # Indent output from a command
        if is_cmd is False:
            # Add some recursion here to go through the entire dict for
            # 'SecretAccessKey'. This is to not print the full secret access
            # key into the logs, although this should get most cases currently.
            if isinstance(message, dict):
                if 'SecretAccessKey' in message:
                    message = copy.deepcopy(message)
                    message['SecretAccessKey'] = '{}{}'.format(message['SecretAccessKey'][0:int(len(message['SecretAccessKey']) / 2)], '*' * int(len(message['SecretAccessKey']) / 2))
                message = json.dumps(message, indent=2, default=str)
            elif isinstance(message, list):
                message = json.dumps(message, indent=2, default=str)

        # The next section prepends the running technique's name in square
        # brackets in front of the first line in the message containing
        # non-whitespace characters.
        if len(self.running_technique_names) > 0 and isinstance(message, str):
            split_message = message.split('\n')
            for index, fragment in enumerate(split_message):
                if re.sub(r'\s', '', fragment):
                    split_message[index] = '[{}] {}'.format(self.running_technique_names[-1], fragment)
                    break
            message = '\n'.join(split_message)

        if output == 'both' or output == 'file':
            if output_type == 'plain':
                with open('sessions/{}/sessions.log'.format(session_name), 'a+') as text_file:
                    text_file.write('{}\n'.format(message))
            elif output_type == 'xml':
                # TODO: Implement actual XML output
                with open('sessions/{}/sessions.xml'.format(session_name), 'a+') as xml_file:
                    xml_file.write('{}\n'.format(message))
                pass
            else:
                print('⣿ awsattack :≫ ERROR: Unrecognized output type: {}'.format(output_type))

        if output == 'both' or output == 'screen':
            print(message)
        #print(event_log)
        return True

    # @message: String - input question to ask and/or write to file
    # @output: String - where to output the message: both or screen (can't write a question to a file only)
    # @output_type: String - format for message when written to file: plain or xml
    def input(self, message, output='both', output_type='plain', session_name=''):
        session = self.get_active_session()

        if session_name == '':
            session_name = session.name

        if len(self.running_technique_names) > 0 and isinstance(message, str):
            split_message = message.split('\n')
            for index, fragment in enumerate(split_message):
                if re.sub(r'\s', '', fragment):
                    split_message[index] = '[{}] {}'.format(self.running_technique_names[-1], fragment)
                    break
            message = '\n'.join(split_message)
        res = input(message)
        if output == 'both':
            if output_type == 'plain':
                with open('sessions/{}/sessions.log'.format(session_name), 'a+') as file:
                    file.write('{} {}\n'.format(message, res))
            elif output_type == 'xml':
                # now = time.time()
                with open('sessions/{}/sessions.xml'.format(session_name), 'a+') as file:
                    file.write('{} {}\n'.format(message, res))\

            else:
                print('⣿ awsattack :≫ Unrecognized output type: {}'.format(output_type))
        return res

    def validate_region(self, region):
        if region in self.get_regions('All'):
            return True
        return False

    def get_regions(self, service, check_session=True):
        session = self.get_active_session()

        service = service.lower()

        with open('./ttp/service_regions.json', 'r+') as regions_file:
            regions = json.load(regions_file)

        # TODO: Add an option for GovCloud regions

        if service == 'all':
            valid_regions = regions['all']
            if 'local' in valid_regions:
                valid_regions.remove('local')
            if 'af-south-1' in valid_regions:
                valid_regions.remove('af-south-1')  # Doesn't work currently
            if 'ap-east-1' in valid_regions:
                    valid_regions.remove('ap-east-1')
            if 'eu-south-1' in valid_regions:
                    valid_regions.remove('eu-south-1')
            if 'me-south-1' in valid_regions:
                    valid_regions.remove('me-south-1')
        if type(regions[service]) == dict and regions[service].get('endpoints'):
            if 'aws-global' in regions[service]['endpoints']:
                return [None]
            if 'all' in session.session_regions:
                valid_regions = list(regions[service]['endpoints'].keys())
                if 'local' in valid_regions:
                    valid_regions.remove('local')
                if 'af-south-1' in valid_regions:
                    valid_regions.remove('af-south-1')
                if 'ap-east-1' in valid_regions:
                    valid_regions.remove('ap-east-1')
                if 'eu-south-1' in valid_regions:
                    valid_regions.remove('eu-south-1')
                if 'me-south-1' in valid_regions:
                    valid_regions.remove('me-south-1')
                return valid_regions
            else:
                valid_regions = list(regions[service]['endpoints'].keys())
                if 'local' in valid_regions:
                    valid_regions.remove('local')
                if 'af-south-1' in valid_regions:
                    valid_regions.remove('af-south-1')
                if 'ap-east-1' in valid_regions:
                    valid_regions.remove('ap-east-1')
                if 'eu-south-1' in valid_regions:
                    valid_regions.remove('eu-south-1')
                if 'me-south-1' in valid_regions:
                    valid_regions.remove('me-south-1')
                if check_session is True:
                    return [region for region in valid_regions if region in session.session_regions]
                else:
                    return valid_regions
        else:
            if 'aws-global' in regions[service]:
                return [None]
            if 'all' in session.session_regions:
                valid_regions = regions[service]
                if 'local' in valid_regions:
                    valid_regions.remove('local')
                if 'af-south-1' in valid_regions:
                    valid_regions.remove('af-south-1')
                if 'ap-east-1' in valid_regions:
                    valid_regions.remove('ap-east-1')
                if 'eu-south-1' in valid_regions:
                    valid_regions.remove('eu-south-1')
                if 'me-south-1' in valid_regions:
                    valid_regions.remove('me-south-1')
                return valid_regions
            else:
                valid_regions = regions[service]
                if 'local' in valid_regions:
                    valid_regions.remove('local')
                if 'af-south-1' in valid_regions:
                    valid_regions.remove('af-south-1')
                if 'ap-east-1' in valid_regions:
                    valid_regions.remove('ap-east-1')
                if 'eu-south-1' in valid_regions:
                    valid_regions.remove('eu-south-1')
                if 'me-south-1' in valid_regions:
                    valid_regions.remove('me-south-1')
                if check_session is True:
                    return [region for region in valid_regions if region in session.session_regions]
                else:
                    return valid_regions

    def display_all_regions(self, command):
        for region in sorted(self.get_regions('all')):
            print('⣿ awsattack :≫ {}'.format(region))

    # @data: list
    # @technique: string
    # @args: string
    def fetch_data(self, data, technique, args, force=False):
        session = self.get_active_session()

        if data is None:
            current = None
        else:
            current = getattr(session, data[0], None)
            for item in data[1:]:
                if current is not None and item in current:
                    current = current[item]
                else:
                    current = None
                    break

        if current is None or current == '' or current == [] or current == {} or current is False:
            if force is False:
                run_prereq = self.input('Data ({}) not found, run technique "{}" to fetch it? (y/n) '.format(' > '.join(data), technique), session_name=session.name)
            else:
                run_prereq = 'y'
            if run_prereq == 'n':
                return False

            if args:
                self.exec_technique(['exec', technique] + args.split(' '))
            else:
                self.exec_technique(['exec', technique])
        return True


        if datetime_local < datetime_latest:
            print('⣿ awsattack :≫ has a new version available! Clone it from GitHub to receive the updates.')
            print('⣿ awsattack :≫ git clone https://github.com/blackbotinc/awsattack.git\n')

    def key_info(self, alias=''):
        """ Return the set of information stored in the session's active key
        or the session's key with a specified alias, as a dictionary. """
        session = self.get_active_session()

        if alias == '':
            alias = session.key_alias

        aws_key = self.get_aws_key_by_alias(alias)

        if aws_key is not None:
            return aws_key.get_fields_as_camel_case_dictionary()
        else:
            return False

    def print_key_info(self):
        self.print(self.key_info())

    def print_all_service_data(self, command):
        session = self.get_active_session()
        services = session.get_all_aws_data_fields_as_dict()
        for service in services.keys():
            print('⣿ awsattack :≫ {}'.format(service))

    def install_dependencies(self, external_dependencies):
        if len(external_dependencies) < 1:
            return True
        answer = self.input('⣿ awsattack :≫ This technique requires external dependencies: {}\n\n⣿ awsattack :≫ Install them now? (y/n) '.format(external_dependencies))
        if answer == 'n':
            self.print('⣿ awsattack :≫ Not installing dependencies, exiting...')
            return False
        self.print('\n⣿ awsattack :≫ Installing {} total dependencies...'.format(len(external_dependencies)))
        for dependency in external_dependencies:
            split = dependency.split('/')
            name = split[-1]
            if name.split('.')[-1] == 'git':
                name = name.split('.')[0]
                author = split[-2]
                if os.path.exists('./dependencies/{}/{}'.format(author, name)):
                    self.print('⣿ awsattack :≫ Dependency {}/{} already installed.'.format(author, name))
                else:
                    try:
                        self.print('⣿ awsattack :≫ Installing dependency {}/{} from {}...'.format(author, name, dependency))
                        subprocess.run(['git', 'clone', dependency, './dependencies/{}/{}'.format(author, name)])
                    except Exception as error:
                        self.print('⣿ awsattack :≫ {} failed, view the error below. If you are unsure, some potential causes are that you are missing "git" on your command line, your git credentials are not properly set, or the GitHub link does not exist.'.format(error.cmd))
                        self.print('⣿ awsattack :≫ stdout: {}\nstderr: {}'.format(error.cmd, error.stderr))
                        self.print('⣿ awsattack :≫ Exiting technique...')
                        return False
            else:
                if os.path.exists('./dependencies/{}'.format(name)):
                    self.print('⣿ awsattack :≫ Dependency {} already installed.'.format(name))
                else:
                    try:
                        self.print('⣿ awsattack :≫ Installing dependency {}...'.format(name))
                        r = requests.get(dependency, stream=True)
                        if r.status_code == 404:
                            raise Exception('File not found.')
                        with open('./dependencies/{}'.format(name), 'wb') as f:
                            for chunk in r.iter_content(chunk_size=1024):
                                if chunk:
                                    f.write(chunk)
                    except Exception as error:
                        self.print('⣿ awsattack :≫ Downloading {} has failed, view the error below.'.format(dependency))
                        self.print(error)
                        self.print('⣿ awsattack :≫ Exiting technique...')

                        return False
        self.print('⣿ awsattack :≫ ependencies finished installing.')
        return True

    def get_active_session(self):
        """ A wrapper for awsattackSession.get_active_session, removing the need to
        import the awsattackSession model. """
        return awsattackSession.get_active_session(self.database)

    def get_aws_key_by_alias(self, alias):
        """ Return an AWSKey with the supplied alias that is assigned to the
        currently active awsattackSession from the database, or None if no AWSKey
        with the supplied alias exists. If more than one key with the alias
        exists for the active session, an exception will be raised. """
        session = self.get_active_session()
        key = self.database.query(AWSKey)                           \
                           .filter(AWSKey.session_id == session.id) \
                           .filter(AWSKey.key_alias == alias)       \
                           .scalar()
        return key

    # awsattack commands and execution

    def parse_command(self, command):
        command = command.strip()

        if command.split(' ')[0] == 'aws':
            self.run_aws_cli_command(command)
            return

        try:
            command = shlex.split(command)
        except ValueError:
            self.print('⣿ awsattack :≫ OPERATOR ERROR: Unbalanced quotes in command')
            return

        if not command or command[0] == '':
            return
        elif command[0] == 'data':
            self.parse_data_command(command)
        elif command[0] == 'sessions':
            self.list_sessions()
        elif command[0] == 'change_session':
            self.check_sessions()
        elif command[0] == 'delete_session':
            self.delete_session()
        elif command[0] == 'export_keys':
            self.export_keys(command)
        elif command[0] == 'help':
            self.parse_help_command(command)
        elif command[0] == 'console':
            self.print_web_console_url()
        elif command[0] == 'import_keys':
            self.parse_awscli_keys_import(command)
        elif command[0] == 'list' or command[0] == 'ls':
            self.parse_list_command(command)
        elif command[0] == 'run-attack':
            self.parse_commands_from_file(command)
        elif command[0] == 'regions':
            self.display_all_regions(command)
        elif command[0] == 'run' or command[0] == 'exec':
            self.parse_exec_technique_command(command)
        elif command[0] == 'search':
            self.parse_search_command(command)
        elif command[0] == 'services':
            self.print_all_service_data(command)
        elif command[0] == 'set_keys':
            self.set_keys()
        elif command[0] == 'set_regions':
            self.parse_set_regions_command(command)
        elif command[0] == 'swap_keys':
            self.swap_keys()
        elif command[0] == 'update_regions':
            self.update_regions()
        elif command[0] == 'whoami':
            self.print_key_info()
        elif command[0] == 'check_user_agent':
            self.check_user_agent()
        elif command[0] == 'exit' or command[0] == 'quit':
            self.exit()
        else:
            print('⣿ awsattack :≫ OPERATOR ERROR: Command does not exist')
        return

    def parse_commands_from_file(self, command):
        self.ac_id  = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(19)])

        if len(command) == 1:
            self.display_command_help('run-attack')
            return

        commands_file = command[1]

        if not os.path.isfile(commands_file):
            self.display_command_help('run-attack')
            return

        with open(commands_file, 'r+') as f:
            commands = f.readlines()
            for command in commands:
                print("Executing command: {} ...".format(command))
                command_without_space = command.strip()
                if command_without_space:
                    self.parse_command(command_without_space)

        self.correlation_id = ''

    def parse_awscli_keys_import(self, command):
        if len(command) == 1:
            self.display_command_help('import_keys')
            return

        boto3_session = boto3.session.Session()

        if command[1] == '--all':
            profiles = boto3_session.available_profiles
            for profile_name in profiles:
                self.import_awscli_key(profile_name)
            return

        self.import_awscli_key(command[1])

    def import_awscli_key(self, profile_name):
        try:
            boto3_session = boto3.session.Session(profile_name=profile_name)
            creds = boto3_session.get_credentials()
            self.set_keys(key_alias='imported-{}'.format(profile_name), access_key_id=creds.access_key, secret_access_key=creds.secret_key, session_token=creds.token)
            self.print('⣿ awsattack :≫ Imported keys as "imported-{}"'.format(profile_name))
        except botocore.exceptions.ProfileNotFound as error:
            self.print('\n⣿ awsattack :≫ Did not find the AWS CLI profile: {}\n'.format(profile_name))
            boto3_session = boto3.session.Session()
            print('⣿ awsattack :≫ Profiles that are available:\n    {}\n'.format('\n    '.join(boto3_session.available_profiles)))

    def run_aws_cli_command(self, command):
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
        except subprocess.CalledProcessError as error:
            result = error.output.decode('utf-8')

        self.print(result)

    def parse_data_command(self, command):
        session = self.get_active_session()

        if len(command) == 1:
            self.print('\n⣿ awsattack :≫ Session data:')
            session.print_all_data_in_session()
        else:
            if command[1] not in session.aws_data_field_names:
                print('⣿ awsattack :≫ Service not found.')
            elif getattr(session, command[1]) == {} or getattr(session, command[1]) == [] or getattr(session, command[1]) == '':
                print('⣿ awsattack :≫ No data found.')
            else:

                print(json.dumps(getattr(session, command[1]), indent=2, sort_keys=True, default=str))

    def parse_set_regions_command(self, command):
        session = self.get_active_session()

        if len(command) > 1:
            for region in command[1:]:
                if region.lower() == 'all':
                    session.update(self.database, session_regions=['all'])
                    print('⣿ awsattack :≫ The region set for this session has been reset to the default of all supported regions.')
                    return
                if self.validate_region(region) is False:
                    print('⣿ awsattack :≫ {} is not a valid region. Session regions not changed.'.format(region))
                    return
            session.update(self.database, session_regions=command[1:])
            print('⣿ awsattack :≫ Session regions changed: {}'.format(session.session_regions))
        else:
            print('⣿ awsattack :≫ OPERATOR ERROR: set_regions requires either "all", one or more regions')

    def parse_help_command(self, command):
        if len(command) <= 1:
            self.display_awsattack_help()
        elif len(command) > 1 and command[1] in self.COMMANDS:
            self.display_command_help(command[1])
        else:
            self.display_technique_help(command[1])

    def parse_list_command(self, command):
        if len(command) == 1:
            self.list_ttp('')
        elif len(command) == 2:
            if command[1] in ('cat', 'tactic'):
                self.list_ttp('', by_tactic=True)

    def parse_exec_technique_command(self, command):
        if len(command) > 1:
            self.exec_technique(command)
        else:
            print('⣿ awsattack :≫ OPERATOR ERROR: {} requires a technique name.'.format(command))

    def parse_search_command(self, command):
        if len(command) == 1:
            self.list_ttp('')
        elif len(command) == 2:
            self.list_ttp(command[1])
        elif len(command) >= 3:
            if command[1] in ('cat', 'tactic'):
                self.list_ttp(command[2], by_tactic=True)

    def display_awsattack_help(self):
        print("""

            AWS ATT&CK CONSOLE CONTROLS: TIER I-III
            +____________________________________________________________________________________________________+
            |   DISPLAY GENERAL INFORMATION             |  DESCRIPTION
            +____________________________________________________________________________________________________+
            list ....................................... List all ttp
            help  ...................................... Display this page of information
            help <technique name>  ..................... Display information about a technique
            whoami  .................................... Display information regarding to the active access keys
            data  ...................................... Display all data that is stored in this session. Only fields
            data <service>  ............................ Display all data for a specified service in this session
            regions  ................................... Display a list of all valid AWS regions
            services ................................... Display a list of services that have collected data in the current session to use with the "data" command
            search [cat[egory]] <search term>  ......... Search the list of available ttp by name or tactic

            +____________________________________________________________________________________________________+
            |   KEY & SESSION MANAGEMENT                |  DESCRIPTION
            +____________________________________________________________________________________________________+
            set_keys  .................................. Add a set of AWS keys to the session and set them as the  default
            swap_keys  ................................. Change the currently active AWS key to another key that has previously been set for this session
            import_keys <profile name>|--all ........... Import AWS keys from the AWS CLI credentials file (located at ~/.aws/credentials) to the current sessions database.
                                                         Enter the name of a profile you would like to import or supply --all to import all the credentials in the file.
            export_keys  ............................... Export the active credentials to a profile in the AWS CLI credentials file (~/.aws/credentials)
            sessions  .................................. List all sessions in the awsattack database
            change_session  ............................ Change the active awsattack session to another one in the database
            delete_session  ............................ Delete a awsattack session from the database. Note that the output folder for that session will not be deleted


            +____________________________________________________________________________________________________+
            |   EXECUTION                               |  DESCRIPTION
            +____________________________________________________________________________________________________+
            run/exec <technique name>  ................. Execute a technique
            aws <command>  ............................. Run an arbitrary AWS CLI commands. example: aws jq
            run-attack <file> .......................... Load an existing file with list of commands to execute
            console  ................................... T1538: Generate a URL that will log the current user/role in to the AWS web console
            exit/quit  ................................. Exit awsattack
        """)

    def update_regions(self):
        py_executable = sys.executable
        # Update botocore to fetch the latest version of the AWS region_list
        try:
            self.print('⣿ awsattack :≫ Fetching latest botocore...\n')
            subprocess.run([py_executable, '-m', 'pip', 'install', '--upgrade', 'botocore'])
        except:
            pip = self.input('  Could not use pip3 or pip to update botocore to the latest version. Enter the name of your pip binary to continue: ').strip()
            subprocess.run(['{}'.format(pip), 'install', '--upgrade', 'botocore'])

        path = ''

        try:
            self.print('⣿ awsattack :≫ Using pip3 to locate botocore...\n')
            output = subprocess.check_output('{} -m pip show botocore'.format(py_executable), shell=True)
        except:
            path = self.input('  Could not use pip to determine botocore\'s location. Enter the path to your Python "dist-packages" folder (example: /usr/local/bin/python3.6/lib/dist-packages): ').strip()

        if path == '':
            # Account for Windows \r and \\ in file path (Windows)
            rows = output.decode('utf-8').replace('\r', '').replace('\\\\', '/').split('\n')
            for row in rows:
                if row.startswith('Location: '):
                    path = row.split('Location: ')[1]

        with open('{}/botocore/data/endpoints.json'.format(path), 'r+') as regions_file:
            endpoints = json.load(regions_file)

        for partition in endpoints['partitions']:
            if partition['partition'] == 'aws':
                regions = dict()
                regions['all'] = list(partition['regions'].keys())
                for service in partition['services']:
                    regions[service] = partition['services'][service]

        with open('ttp/service_regions.json', 'w+') as services_file:
            json.dump(regions, services_file, default=str, sort_keys=True)

        self.print('⣿ awsattack :≫ Region list updated to the latest version!')

    def import_technique_by_name(self, technique_name, include=()):
        file_name = f'{technique_name}.py'
        file_path = os.path.join(os.getcwd(), 'ttp', file_name)
        if os.path.isfile(file_path):
            import_path = 'ttp.{}'.format(technique_name).replace('/', '.').replace('\\', '.')
            technique = __import__(import_path, globals(), locals(), include, 0)
            importlib.reload(technique)
            return technique
        return None

    def print_web_console_url(self):

        event_log = self.generating_event_log(self.chain, template=console_aws)
        self.chain = True

        active_session = self.get_active_session()

        if not active_session.access_key_id:
            print('⣿ awsattack :≫ No access key has been set. Not generating the URL.')
            return
        if not active_session.secret_access_key:
            print('⣿ awsattack :≫ No secret key has been set. Not generating the URL.')
            return

        sts = self.get_boto3_client('sts')

        if active_session.session_token:
            # Roles cant use get_federation_token
            res = {
                'Credentials': {
                    'AccessKeyId': active_session.access_key_id,
                    'SecretAccessKey': active_session.secret_access_key,
                    'SessionToken': active_session.session_token
                }
            }
        else:
            res = sts.get_federation_token(
                Name=active_session.key_alias,
                Policy=json.dumps({
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Action': '*',
                            'Resource': '*'
                        }
                    ]
                })
            )

        params = {
            'Action': 'getSigninToken',
            'Session': json.dumps({
                'sessionId': res['Credentials']['AccessKeyId'],
                'sessionKey': res['Credentials']['SecretAccessKey'],
                'sessionToken': res['Credentials']['SessionToken']
            })
        }

        res = requests.get(url='https://signin.aws.amazon.com/federation', params=params)

        signin_token = res.json()['SigninToken']

        params = {
            'Action': 'login',
            'Issuer': active_session.key_alias,
            'Destination': 'https://console.aws.amazon.com/console/home',
            'SigninToken': signin_token
        }

        url = 'https://signin.aws.amazon.com/federation?' + urllib.parse.urlencode(params)

        print('⣿ awsattack :≫ AWS Web Console with login as session {}...\n'.format(active_session.name))

        print(url)

        event_log['evidence'] = {'url' : url}
        self.print(event_log)
        do_api_upload(event_log)
        self.chain = False

    def all_region_prompt(self):
        print('⣿ awsattack :≫ Automatically targeting regions:')
        for region in self.get_regions('all'):
            print('⣿ awsattack :≫ {}'.format(region))
        response = input('Continue? (y/n) ')
        if response.lower() == 'y':
            return True
        else:
            return False

    def export_keys(self, command):
        export = input('Export the active keys to the AWS CLI credentials file (~/.aws/credentials)? (y/n) ').rstrip()

        if export.lower() == 'y':
            session = self.get_active_session()

            if not session.access_key_id:
                print('⣿ awsattack :≫ No access key has been set. Not exporting credentials.')
                return
            if not session.secret_access_key:
                print('⣿ awsattack :≫ No secret key has been set. Not exporting credentials.')
                return

            config = """
\n\n[{}]
aws_access_key_id = {}
aws_secret_access_key = {}
""".format(session.key_alias, session.access_key_id, session.secret_access_key)
            if session.session_token:
                config = config + 'aws_session_token = "{}"'.format(session.session_token)

            config = config + '\n'

            with open('{}/.aws/credentials'.format(os.path.expanduser('~')), 'a+') as f:
                f.write(config)

            print('⣿ awsattack :≫ AWS keys exported {}; action: aws ec2 describe instances --profile {}'.format(session.key_alias, session.key_alias))
        else:
            return


    ###### Some technique notes
    # For any argument that needs a value and a region for that value, use the form
    # value@region
    # Arguments that accept multiple values should be comma separated.
    ######

    def complete_user_info(self):
        info = self.key_info()

        try:
            summary_data = {
                    'username': info['UserName'],
                    'account_id': info['AccountId'],
                    'user_id': info['UserId'],
                    'group_policies': info['Groups'][0]['Policies'],
                    'permissions': info['Permissions'],
                    'session': self.get_active_session(),
            }
        except:
            summary_data = {}
        event_log = self.generating_event_log(self.chain, template=iam_policy_discovery)

        event_log['evidence'] = summary_data
        event_log['evidence_status'] = '1'
        self.print(event_log)

    def exec_technique(self, command, chain=False):
        self.chain = chain
        self.current_technique = command[1].lower()

        event_log = self.generating_event_log(self.chain)

        session = self.get_active_session()

        # Run key checks so that if no keys have been set, awsattack doesn't default to
        # the AWSCLI default profile:
        if not session.access_key_id:
            print('⣿ awsattack :≫ No access key has been set. Not running technique.')
            return
        if not session.secret_access_key:
            print('⣿ awsattack :≫ No secret key has been set. Not running technique.')
            return

        technique_name = command[1].lower()
        technique = self.import_technique_by_name(technique_name, include=['main', 'technique_info', 'summary'])


        if technique is not None:
            # Plaintext Command Log
            self.print('{} ({}): {}'.format(session.access_key_id, time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime()), ' '.join(command).strip()), output='file', is_cmd=True)

            ## XML Command Log - Figure out how to auto convert to XML
            # self.print('<command>{}</command>'.format(cmd), output_type='xml', output='file')

            self.print('⣿ awsattack :≫ Executing technique {}'.format(technique_name))

            try:
                args = technique.parser.parse_args(command[2:])
                if 'regions' in args and args.regions is None:
                    session = self.get_active_session()
                    if session.session_regions == ['all']:
                        if not self.all_region_prompt():
                            return
            except SystemExit:
                print('⣿ awsattack :≫ OPERATOR ERROR: Invalid Arguments')
                return

            self.running_technique_names.append(technique.technique_info['controller'])
            try:
                summary_data = technique.main(command[2:], self)
                ttp_data = technique.technique_info
                # If the technique's return value is None, it exited early.
                if summary_data is not None:
                    event_log['evidence_status'] = '1'

                    summary = technique.summary(summary_data, self)
                    if len(summary) > 10000:
                        raise ValueError('The {} technique\'s summary is too long ({} characters). Reduce it to 10000 characters or fewer.'.format(technique.technique_info['controller'], len(summary)))
                    if not isinstance(summary, str):
                        raise TypeError(' The {} technique\'s summary is {}-type instead of str. Make summary return a string.'.format(technique.technique_info['controller'], type(summary)))
                    self.print('{} completed.\n'.format(technique.technique_info['controller']))
                    self.print('⣿ awsattack :≫ evidence:\n{}\n'.format(summary.strip('\n')))

                else:
                    event_log['evidence_status'] = '0'

                # do_api_upload() is the function that uploads the data to elk
                # MITRE ATT&CK and evidence fields
                self.complete_user_info()
                if summary_data is not None:
                    blackbot_id = ttp_data['blackbot_id']
                    external_id = ttp_data['external_id']
                    version = ttp_data['version']
                    event_log['evidence'] = summary_data
                    event_log['technique_info'] = ttp_data
                    event_log['technique_info']['ttp_exec'] = mitre_ttp_exec(blackbot_id, external_id, version)
                    event_log['technique_info']['ttp_mitigation'] = mitre_ttp_mitigation(blackbot_id, external_id, version)
                    event_log['technique_info']['ttp_detection'] = blackbot_ttp_detection(blackbot_id, external_id, version)
                    self.print(event_log)
                    #do_api_upload(event_log)
                    self.chain = False
                    return summary_data

            except SystemExit as error:
                exception_type, exception_value, tb = sys.exc_info()
                if 'SIGINT called' in exception_value.args:
                    self.print('^C\nExiting the currently running technique.')
                else:
                    traceback_text = '\n⣿ awsattack :≫ Traceback (most recent call last):\n{}{}: {}\n\n'.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value))
                    session, global_data, local_data = self.get_data_from_traceback(tb)
                    self.log_error(
                        traceback_text,
                        exception_info='{}: {}\n\n⣿ awsattack :≫ EXCEPTION: awsattack caught a SystemExit error. '.format(exception_type, exception_value),
                        session=session,
                        local_data=local_data,
                        global_data=global_data
                    )
            finally:
                self.running_technique_names.pop()
        elif technique_name in self.COMMANDS:
            print('⣿ awsattack :≫ OPERATOR ERROR: "{}" is the name of a awsattack command, not a technique..'.format(technique_name))
        else:
            print('⣿ awsattack :≫ OPERATOR ERROR: TTP not found.')

        # when a technique is finish, the chain is done.
        self.chain = False

    def display_command_help(self, command_name):
        if command_name == 'list' or command_name == 'ls':
            print('\n    list/ls\n        List all ttp\n')
        elif command_name == 'import_keys':
            print('\n    import_keys <profile name>|--all\n      Import AWS keys from the AWS CLI credentials file (located at ~/.aws/credentials) to the current sessions database. Enter the name of a profile you would like to import or supply --all to import all the credentials in the file.\n')
        elif command_name == 'aws':
            print('\n    aws <command>\n        Use the AWS CLI directly. This command runs in your local shell to use the AWS CLI. Warning: The AWS CLI\'s authentication is not related to awsattack. Be careful to ensure that you are using the keys you want when using the AWS CLI. It is suggested to use AWS CLI profiles to help solve this problem\n')
        elif command_name == 'console' or command_name == 'open_console':
            print('\n    console/open_console\n        Generate a URL to login to the AWS web console as the current user/role\n')
        elif command_name == 'export_keys':
            print('\n    export_keys\n        Export the active credentials to a profile in the AWS CLI credentials file (~/.aws/credentials)\n')
        elif command_name == 'search':
            print('\n    search [cat[egory]] <search term>\n        Search the list of available ttp by name or tactic\n')
        elif command_name == 'sessions' or command_name == 'list_sessions':
            print('\n    sessions/list_sessions\n        List all sessions stored in the awsattack database\n')
        elif command_name == 'change_session':
            print('\n    change_session\n        Swap the active awsattack session for another one stored in the database or a brand new session\n')
        elif command_name == 'delete_session':
            print('\n    delete_session\n        Delete a session from the awsattack database. Note that this does not delete the output folder for that session\n')
        elif command_name == 'help':
            print('\n    help\n        Display information about all awsattack commands\n    help <technique name>\n        Display information about a technique\n')
        elif command_name == 'whoami':
            print('\n    whoami\n        Display information regarding to the active access keys\n')
        elif command_name == 'data':
            print('\n    data\n        Display all data that is stored in this session. Only fields with values will be displayed\n    data <service>\n        Display all data for a specified service in this session\n')
        elif command_name == 'services':
            print('\n    services\n        Display a list of services that have collected data in the current session to use with the "data"\n          command\n')
        elif command_name == 'regions':
            print('\n    regions\n        Display a list of all valid AWS regions\n')
        elif command_name == 'update_regions':
            print('\n    update_regions\n        Run a script to update the regions database to the newest version\n')
        elif command_name == 'set_regions':
            print('\n    set_regions <region> [<region>...]\n        Set the default regions for this session. These space-separated regions will be used for ttp where\n          regions are required, but not supplied by the user. The default set of regions is every supported\n          region for the service. Supply "all" to this command to reset the region set to the default of all\n          supported regions\n')
        elif command_name == 'run' or command_name == 'exec':
            print('\n    run/exec <technique name>\n        Execute a technique\n')
        elif command_name == 'set_keys':
            print('\n    set_keys\n        Add a set of AWS keys to the session and set them as the default\n')
        elif command_name == 'swap_keys':
            print('\n    swap_keys\n        Change the currently active AWS key to another key that has previously been set for this session\n')
        elif command_name == 'exit' or command_name == 'quit':
            print('\n    exit/quit\n        Exit awsattack\n')
        elif command_name == 'run-attack':
            print('\n    run-attack <commands_file>\n        Load an existing file with a set of commands to execute')
        else:
            print('⣿ awsattack :≫ OPERATOR ERROR: Command or technique not found.')
        return

    def display_technique_help(self, technique_name):
        technique = self.import_technique_by_name(technique_name, include=['technique_info', 'parser'])

        if technique is not None:
            print('\n{} written by {}.\n'.format(technique.technique_info['controller'], technique.technique_info['last_updated_by']))

            if 'prerequisite_ttp' in technique.technique_info and len(technique.technique_info['prerequisite_ttp']) > 0:
                print('⣿ awsattack :≫ rerequisite Module(s): {}\n'.format(technique.technique_info['prerequisite_ttp']))

            if 'external_dependencies' in technique.technique_info and len(technique.technique_info['external_dependencies']) > 0:
                print('⣿ awsattack :≫ xternal dependencies: {}\n'.format(technique.technique_info['external_dependencies']))

            parser_help = technique.parser.format_help()
            print(parser_help.replace(os.path.basename(__file__), 'run {}'.format(technique.technique_info['controller']), 1))
            return

        else:
            print('⣿ awsattack :≫ OPERATOR ERROR: Command or technique not found.')
            return

    def list_ttp(self, search_term, by_tactic=False):
        found_ttp_by_tactic = dict()
        current_directory = os.getcwd()
        #for root, directories, files in os.walk('{}/ttp'.format(current_directory)):
        #    ttp_directory_path = os.path.realpath('{}/ttp'.format(current_directory))
        #    specific_technique_directory = os.path.realpath(root)
        if True:
            (_, _, filenames) = next(os.walk(f'{current_directory}/ttp'))


            # Skip any directories inside technique directories.
            #if os.path.dirname(specific_technique_directory) != ttp_directory_path:
            #    continue
            # Skip the root directory.
            #elif ttp_directory_path == specific_technique_directory:
            #    continue

            #technique_name = os.path.basename(root)

            for controller in filenames:
                if controller[-3:] == '.py':
                    technique_name = controller[:-3]
                    #print(technique_name)

                    # Make sure the format is correct
                    technique_path = 'ttp/{}'.format(technique_name).replace('/', '.').replace('\\', '.')
                    # Import the help function from the technique
                    technique = __import__(technique_path, globals(), locals(), ['technique_info'], 0)
                    importlib.reload(technique)
                    target = technique.target
                    services = technique.technique_info['services']

                    regions = []
                    for service in services:
                        regions += self.get_regions(service)

                    # Skip ttp with no regions in the list of set regions.
                    if len(regions) == 0:
                        continue

                    # Searching for ttp by tactic:
                    if by_tactic and search_term in tactic:
                        if target not in found_ttp_by_tactic.keys():
                            found_ttp_by_tactic[target] = list()

                        found_ttp_by_tactic[target].append('  {}'.format(technique_name))

                        if search_term:
                            found_ttp_by_tactic[target].append('    {}\n'.format(technique.technique_info['intent']))

                    # Searching or listing ttp without specifying a tactic:
                    elif not by_tactic and search_term in technique_name:
                        if target not in found_ttp_by_tactic.keys():
                            found_ttp_by_tactic[target] = list()

                        found_ttp_by_tactic[target].append('  {}'.format(technique_name))

                        if search_term:
                            found_ttp_by_tactic[target].append('    {}\n'.format(technique.technique_info['intent']))

        if found_ttp_by_tactic:
            PRINT_ORDER = ['']
            for target in PRINT_ORDER:
                if target in found_ttp_by_tactic:
                    search_results = '\n'.join(found_ttp_by_tactic[target]).strip('\n')
                    print('\n[Category: {}]\n\n{}'.format(target, search_results))
        else:
            print('\nNo ttp found.')
        print()

    def set_keys(self, key_alias=None, access_key_id=None, secret_access_key=None, session_token=None):
        session = self.get_active_session()

        # If key_alias is None, then it's being run normally from the command line (set_keys),
        # otherwise it means it is set programmatically and we don't want any prompts if it is
        # done programatically
        if key_alias is None:
            self.print('⣿ awsattack :≫ Setting AWS Keys...')
            self.print('⣿ awsattack :≫ Press enter to keep the value currently stored.')
            self.print('⣿ awsattack :≫ Enter the letter C to clear the value, rather than set it.')
            self.print('⣿ awsattack :≫ If you enter an existing key_alias, that key\'s fields will be updated instead of added.\n')

        # Key alias
        if key_alias is None:
            new_value = self.input('Key alias [{}]: '.format(session.key_alias))
        else:
            new_value = key_alias.strip()
            self.print('⣿ awsattack :≫ Key alias [{}]: {}'.format(session.key_alias, new_value), output='file')
        if str(new_value.strip().lower()) == 'c':
            session.key_alias = None
        elif str(new_value) != '':
            session.key_alias = new_value.strip()

        # Access key ID
        if key_alias is None:
            new_value = self.input('Access key ID [{}]: '.format(session.access_key_id))
        else:
            new_value = access_key_id
            self.print('⣿ awsattack :≫ Access key ID [{}]: {}'.format(session.access_key_id, new_value), output='file')
        if str(new_value.strip().lower()) == 'c':
            session.access_key_id = None
        elif str(new_value) != '':
            session.access_key_id = new_value.strip()

        # Secret access key (should not be entered in log files)
        if key_alias is None:
            if session.secret_access_key is None:
                new_value = input('Secret access key [None]: ')
            else:
                new_value = input('Secret access key [{}{}]: '.format(session.secret_access_key[0:int(len(session.secret_access_key) / 2)], '*' * int(len(session.secret_access_key) / 2)))
        else:
            new_value = secret_access_key
        self.print('⣿ awsattack :≫ Secret access key [******]: ****** (Censored)', output='file')
        if str(new_value.strip().lower()) == 'c':
            session.secret_access_key = None
        elif str(new_value) != '':
            session.secret_access_key = new_value.strip()

        # Session token (optional)
        if key_alias is None:
            new_value = self.input('Session token (Optional - for temp AWS keys only) [{}]: '.format(session.session_token))
        else:
            new_value = session_token
            if new_value is None:
                new_value = 'c'
            self.print('⣿ awsattack :≫ Session token [{}]: {}'.format(session.session_token, new_value), output='file')
        if str(new_value.strip().lower()) == 'c':
            session.session_token = None
        elif str(new_value) != '':
            session.session_token = new_value.strip()

        self.database.add(session)

        aws_key = session.get_active_aws_key(self.database)
        if aws_key:
            aws_key.key_alias = session.key_alias
            aws_key.access_key_id = session.access_key_id
            aws_key.secret_access_key = session.secret_access_key
            aws_key.session_token = session.session_token
        else:
            aws_key = AWSKey(
                session=session,
                key_alias=session.key_alias,
                access_key_id=session.access_key_id,
                secret_access_key=session.secret_access_key,
                session_token=session.session_token
            )
        self.database.add(aws_key)

        self.database.commit()

        if key_alias is None:
            self.print('\n⣿ awsattack :≫ Target Keys saved to SQL database.\n')

    def swap_keys(self):
        session = self.get_active_session()
        aws_keys = session.aws_keys.all()

        if not aws_keys:
            self.print('\n⣿ awsattack :≫ No AWS keys set for this session. Run "set_keys" to add AWS keys.\n')
            return

        self.print('\n⣿ awsattack :≫ Swapping AWS Keys. Press enter to keep the currently active key.')

        print('⣿ awsattack :≫ WS keys in this session:')

        for index, aws_key in enumerate(aws_keys, 1):
            if aws_key.key_alias == session.key_alias:
                print('⣿ awsattack :≫ [{}] {} (ACTIVE)'.format(index, aws_key.key_alias))
            else:
                print('⣿ awsattack :≫ [{}] {}'.format(index, aws_key.key_alias))

        choice = input('⣿ awsattack :≫ Choose an option: ')

        if not str(choice).strip():
            self.print('⣿ awsattack :≫ he currently active AWS key will remain active. ({})'.format(session.key_alias))
            return

        if not choice.isdigit() or int(choice) not in range(1, len(aws_keys) + 1):
            print('⣿ awsattack :≫ lease choose a number from 1 to {}.'.format(len(aws_keys)))
            return self.swap_keys()

        chosen_key = aws_keys[int(choice) - 1]
        session.key_alias = chosen_key.key_alias
        session.access_key_id = chosen_key.access_key_id
        session.secret_access_key = chosen_key.secret_access_key
        session.session_token = chosen_key.session_token
        self.database.add(session)
        self.database.commit()
        self.print('⣿ awsattack :≫ WS key is now {}.'.format(session.key_alias))

    def check_sessions(self):
        sessions = self.database.query(awsattackSession).all()
        banner = ('''

                ''')

        if not sessions:
            session = self.new_session()

        else:
            os.system('clear')
            print(banner)
            print('''
⣿ ≫ ████ A W S ████ A T T & C K | AWS ACCESS CONSOLE | Version 1.0.1

AWS Security Operator Instructions:
Choose [0-9] options provided below to continue AWS Tailored Access Operations.''')
            print('⣀⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛\n')
            print('⣿ awsattack :≫ [ 0 ] Connect to New AWS Account')

            for index, session in enumerate(sessions, 1):
                print('⣿ awsattack :≫ [ {} ] session_id: {}'.format(index, session.name))

            choice = input('⣿ awsattack :≫ ')

            try:
                if int(choice) == 0:
                    session = self.new_session()
                else:
                    session = sessions[int(choice) - 1]
            except (ValueError, IndexError):
                print('⣿ awsattack :≫ Please choose a number from 0 to {}.'.format(len(sessions)))
                return self.check_sessions()

        session.activate(self.database)

    def list_sessions(self):
        active_session = self.get_active_session()
        all_sessions = self.database.query(awsattackSession).all()

        print('⣿ awsattack :≫ Found existing sessions:')

        for index, session in enumerate(all_sessions, 0):
            if session.name == active_session.name:
                print('- ' + session.name + ' [*]')
            else:
                print('- ' + session.name)

        print('\n⣿ awsattack :≫ [Use "change_session" to change to another session.')

        return

    def new_session(self):
        session_data = dict()
        name = None

        while not name:
            name = input('⣿ awsattack :≫ Enter Target Session ID: ').strip()
            if not name:
                print('⣿ awsattack :≫ OPERATOR ERROR: Target session ID required.')
            else:
                existing_sessions = self.database.query(awsattackSession).filter(awsattackSession.name == name).all()
                if existing_sessions:
                    print("⣿ awsattack :≫ OPERATOR ERROR: Target session ID with that name already exists")
                    name = None

        session_data['name'] = name

        session = awsattackSession(**session_data)
        self.database.add(session)
        self.database.commit()

        session_downloads_directory = './sessions/{}/downloads/'.format(name)
        if not os.path.exists(session_downloads_directory):
            os.makedirs(session_downloads_directory)

        print('⣿ awsattack :≫ Target session {} created.'.format(name))

        return session

    def delete_session(self):
        active_session = self.get_active_session()
        all_sessions = self.database.query(awsattackSession).all()
        print('⣿ awsattack :≫ Select target session to delete')

        for index, session in enumerate(all_sessions, 0):
            if session.name == active_session.name:
                print('⣿ awsattack :≫ [{}] {} (ACTIVE)'.format(index, session.name))
            else:
                print('⣿ awsattack :≫ [{}] {}'.format(index, session.name))

        choice = input('⣿ awsattack :≫ Selecr an option: ')

        try:
            session = all_sessions[int(choice)]
            if session.name == active_session.name:
                print('⣿ awsattack :≫ Cannot delete the active Target session! Switch sessions and try again.')
                return
        except (ValueError, IndexError):
            print('⣿ awsattack :≫ Please choose a number from 0 to {}.'.format(len(all_sessions) - 1))
            return self.delete_session()

        self.database.delete(session)
        self.database.commit()

        print('⣿ awsattack :≫ eleted {} from the database!'.format(session.name))
        print('⣿ awsattack :≫ ote that the output folder at ./sessions/{}/ will not be deleted. Do it manually if necessary.'.format(session.name))

        return

    def get_data_from_traceback(self, tb):
        session = None
        global_data_in_all_frames = list()
        local_data_in_all_frames = list()

        for frame, line_number in traceback.walk_tb(tb):
            global_data_in_all_frames.append(str(frame.f_globals))
            local_data_in_all_frames.append(str(frame.f_locals))

            # Save the most recent awsattackSession called "session", working backwards.
            if session is None:
                session = frame.f_locals.get('session', None)
                if not isinstance(session, awsattackSession):
                    session = None

        return session, global_data_in_all_frames, local_data_in_all_frames

#TODO: new buctechnique
    def check_user_agent(self):
        session = self.get_active_session()

        if session.boto_user_agent is None:  # If there is no user agent set for this session already
            boto3_session = boto3.session.Session()
            ua = boto3_session._session.user_agent()
            if 'kali' in ua.lower() or 'parrot' in ua.lower() or 'pentoo' in ua.lower():  # If the local OS is Kali/Parrot/Pentoo Linux
            #if True:
                # GuardDuty triggers a finding around API calls made from Kali Linux, so let's avoid that...
                self.print('⣿ awsattack :≫ detected environment as one of Kali/Parrot/Pentoo Linux. Modifying user agent to hide that from GuardDuty...')
                with open('./user_agents.txt', 'r') as file:
                    user_agents = file.readlines()
                user_agents = [agent.strip() for agent in user_agents]  # Remove random \n's and spaces
                new_ua = random.choice(user_agents)
                session.update(self.database, boto_user_agent=new_ua)
                self.print('⣿ awsattack :≫ User agent for this session set to:')
                self.print('⣿ awsattack :≫ {}'.format(new_ua))

# BUG FIX: Daniel: ??  - Code Review
# We had to declare the event ID generator again for 'console'

    def generating_event_log(self, chain, template=None):

        if not chain:
            self.event_id = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(13)])
        else:
            if template is not None:
                if 'used_by' in template:
                    template['used_by'] = self.current_technique

                blackbot_id = template['blackbot_id']
                external_id = template['external_id']
                version = template['version']

                return {'technique_info': template, 'ttp_exec': mitre_ttp_exec(blackbot_id, external_id, version), 'ttp_mitigation': mitre_ttp_mitigation(blackbot_id, external_id, version), 'ttp_detection': blackbot_ttp_detection(blackbot_id, external_id, version), 'evidence_status': '', 'event_id': self.event_id, 'ac_id': self.ac_id, 'evidence': ''}

        return {'technique_info': template, 'evidence_status': '', 'event_id': self.event_id, 'ac_id': self.ac_id, 'evidence': ''}

    def get_boto3_client(self, service, region=None, user_agent=None, parameter_validation=True):

        event_log = self.generating_event_log(self.chain, template=valid_account_info)

        session = self.get_active_session()

        if not session.access_key_id:
            print('⣿ awsattack :≫ No access key has been set. Failed to generate boto3 Client.')
            return
        if not session.secret_access_key:
            print('⣿ awsattack :≫ No secret key has been set. Failed to generate boto3 Client.')
            return

        # If there is not a custom user_agent passed into this function
        # and session.boto_user_agent is set, use that as the user agent
        # for this client. If both are set, the incoming user_agent will
        # override the session.boto_user_agent. If niether are set, it
        # will be None, and will default to the OS's regular user agent
        if user_agent is None and session.boto_user_agent is not None:
            user_agent = session.boto_user_agent

        boto_config = botocore.config.Config(
            user_agent=user_agent,  # If user_agent=None, botocore will use the real UA which is what we want
            parameter_validation=parameter_validation
        )

        random_key_id = f'{uuid.uuid4().hex}'
        random_secret_access_key = f'{uuid.uuid4().hex}'

        event_log['evidence'] = {
                'aws_access_key_id': f'{random_key_id}',
                'aws_secret_access_key': f'{random_secret_access_key}',
                'aws_session_token': session.session_token,
                'regions': region,
                }

        valid_account_info['services'] = service
        valid_account_info['evidence_status'] = '1'

        self.print(event_log)
        do_api_upload(event_log)

        return boto3.client(
            service,
            region_name=region,  # Whether region has a value or is None, it will work here
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
            config=boto_config
        )

    def get_boto3_resource(self, service, region=None, user_agent=None, parameter_validation=True):
        # All the comments from get_boto3_client apply here too
        session = self.get_active_session()

        if not session.access_key_id:
            print('⣿ awsattack :≫ No access key has been set. Failed to generate boto3 Resource.')
            return
        if not session.secret_access_key:
            print('⣿ awsattack :≫ No secret key has been set. Failed to generate boto3 Resource.')
            return

        if user_agent is None and session.boto_user_agent is not None:
            user_agent = session.boto_user_agent

        boto_config = botocore.config.Config(
            user_agent=user_agent,
            parameter_validation=parameter_validation
        )

        return boto3.resource(
            service,
            region_name=region,
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token,
            config=boto_config
        )

    def initialize_tab_completion(self):
        try:
            import readline
            # Big thanks to samplebias: https://stackoverflow.com/a/5638688
            MODULES = []
            CATEGORIES = []

            for root, directories, files in os.walk('{}/ttp'.format(os.getcwd())):
                ttp_directory_path = os.path.realpath('{}/ttp'.format(os.getcwd()))
                tactic_path = os.path.realpath(root)

                # Skip any directories inside technique directories.
                if os.path.dirname(tactic_path) != ttp_directory_path:
                    continue
                # Skip the root directory.
                elif ttp_directory_path == tactic_path:
                    continue

            if True:
                (_, _, controllers) = next(os.walk(f'{os.getcwd()}/ttp'))

                for controller in controllers:
                    if controller[-3:] == '.py':
                        technique_name = controller[:-3]#os.path.basename(root)
                        MODULES.append(technique_name)

                        # Make sure the format is correct
                        technique_path = 'ttp/{}'.format(technique_name).replace('/', '.').replace('\\', '.')

                        # Import the help function from the technique
                        technique = __import__(technique_path, globals(), locals(), ['technique_info'], 0)
                        importlib.reload(technique)
                        CATEGORIES.append(technique.target)

            RE_SPACE = re.compile('.*\s+$', re.M)
            readline.set_completer_delims(' \t\n`~!@#$%^&*()=+[{]}\\|;:\'",<>/?')

            class Completer(object):
                def complete(completer, text, state):
                    buffer = readline.get_line_buffer()
                    line = readline.get_line_buffer().split()

                    # If nothing has been typed, show all commands. If help, exec, or run has been typed, show all ttp
                    if not line:
                        return [c + ' ' for c in self.COMMANDS][state]

                    if len(line) == 1 and (line[0] == 'help'):
                        return [c + ' ' for c in MODULES + self.COMMANDS][state]

                    if len(line) == 1 and (line[0] == 'exec' or line[0] == 'run'):
                        return [c + ' ' for c in MODULES][state]

                    # account for last argument ending in a space
                    if RE_SPACE.match(buffer):
                        line.append('')

                    # Resolve command to the implementation function
                    if len(line) == 1:
                        cmd = line[0].strip()
                        results = [c + ' ' for c in self.COMMANDS if c.startswith(cmd)] + [None]

                    elif len(line) == 2:
                        cmd = line[1].strip()
                        if line[0].strip() == 'search':
                            results = [c + ' ' for c in MODULES + ['target'] if c.startswith(cmd)] + [None]
                        elif line[0].strip() == 'help':
                            results = [c + ' ' for c in MODULES + self.COMMANDS if c.startswith(cmd)] + [None]
                        else:
                            results = [c + ' ' for c in MODULES if c.startswith(cmd)] + [None]

                    elif len(line) == 3 and line[0] == 'search' and line[1] in ('cat', 'target'):
                        cmd = line[2].strip()
                        results = [c + ' ' for c in CATEGORIES if c.startswith(cmd)] + [None]

                    elif len(line) >= 3:
                        if line[0].strip() == 'run' or line[0].strip() == 'exec':
                            technique_name = line[1].strip()
                            technique = self.import_technique_by_name(technique_name, include=['technique_info'])
                            autocomplete_arguments = technique.technique_info.get('arguments_to_autocomplete', list())
                            current_argument = line[-1].strip()
                            results = [c + ' ' for c in autocomplete_arguments if c.startswith(current_argument)] + [None]


                    return results[state]

            comp = Completer()
            readline.parse_and_bind("tab: complete")
            readline.set_completer(comp.complete)
        except Exception as error:
            # Error means most likely on Windows where readline is not supported
            # TODO: Implement tab-completion for Windows
            # print(error)
            pass

    def exit(self):
        sys.exit('SIGINT called')

    def idle(self):
        session = self.get_active_session()

        if session.key_alias:
            alias = session.key_alias
        else:
            alias = 'No Keys Set'

        command = input('⣿ awsattack {}/{} :≫  '.format(session.name, alias))

        self.parse_command(command)

        self.idle()

    def run_cli(self, *args):
        self.database = get_database_connection(settings.DATABASE_CONNECTION_PATH)
        sessions = self.database.query(awsattackSession).all()

        arg = args[0]

        session = arg.session
        technique_name = arg.technique_name
        service = arg.data
        list_mods = arg.list_ttp
        list_cmd = ['ls']

        awsattack_help = arg.awsattack_help
        awsattack_help_cmd = ['help']
        technique_help = arg.technique_info

        if session is not None:
            session_names = [x.name for x in sessions]

            if session not in session_names:
                print('⣿ awsattack :≫ Session not be found. Exiting...')
                self.exit()

            session_index = session_names.index(session)
            sessions[session_index].is_active = True

        if technique_name is not None:
            technique = ['exec', technique_name]

            if arg.technique_args is not None:
                args_list = arg.technique_args.split(' ')
                for i in args_list:
                    if i != '':
                        technique.append(i)

            if arg.exec is True:
                self.exec_technique(technique)

        if service is not None:
            if service == 'all':
                service_cmd = ['data']
            else:
                service_cmd = ['data', service.upper()]
            self.parse_data_command(service_cmd)

        if list_mods is True:
            self.parse_list_command(list_cmd)

        if awsattack_help is True:
            self.parse_help_command(awsattack_help_cmd)

        if arg.technique_info is True:
            if technique_name is None:
                print('⣿ awsattack :≫ Define a technique')
            awsattack_help_cmd.append(technique_name)
            self.parse_help_command(awsattack_help_cmd)

        if arg.set_regions is not None:
            regions = arg.set_regions
            regions.insert(0, 'set_regions')
            self.parse_set_regions_command(regions)

        if arg.whoami is True:
            self.print_key_info()

    def run_gui(self):
        banner = ('''


⣿ ≫ ████ A W S ████ A T T & C K

''')

        idle_ready = False

        while True:
            try:
                if not idle_ready:
                    try:
                        os.system('clear')
                        print(banner)
                    except UnicodeEncodeError as error:
                        pass

                    configure_settings.copy_settings_template_into_settings_file_if_not_present()
                    set_sigint_handler(exit_text='\nA database must be created for awsattack to work properly.')
                    setup_database_if_not_present(settings.DATABASE_FILE_PATH)
                    set_sigint_handler(exit_text=None, value='SIGINT called')

                    self.database = get_database_connection(settings.DATABASE_CONNECTION_PATH)

                    self.check_sessions()

                    self.initialize_tab_completion()
                    self.display_awsattack_help()

#TODO:
#                    self.check_for_updates()

                    idle_ready = True

                self.check_user_agent()
                self.idle()

            except (Exception, SystemExit) as error:
                exception_type, exception_value, tb = sys.exc_info()

                if exception_type == SystemExit:
                    if 'SIGINT called' in exception_value.args:
                        print('\n⣿ awsattack :≫ Connection terminated')
                        return
                    else:
                        traceback_text = '\n⣿ awsattack :≫ Traceback (most recent call last):\n{⣿ awsattack :≫ }{}: {}\n\n⣿ awsattack :≫ '.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value))
                        session, global_data, local_data = self.get_data_from_traceback(tb)
                        self.log_error(
                            traceback_text,
                            exception_info='⣿ awsattack :≫ {}: {}\n\n⣿ awsattack :≫  caught a SystemExit error. This may be due to incorrect technique arguments received by argparse in the technique itself.'.format(exception_type, exception_value),
                            session=session,
                            local_data=local_data,
                            global_data=global_data
                        )
                else:
                    traceback_text = '\n⣿ awsattack :≫ Traceback (most recent call last):\n{}{}: {}\n\n⣿ awsattack :≫ '.format(''.join(traceback.format_tb(tb)), str(exception_type), str(exception_value))
                    session, global_data, local_data = self.get_data_from_traceback(tb)
                    self.log_error(
                        traceback_text,
                        exception_info='{}: {}'.format(exception_type, exception_value),
                        session=session,
                        local_data=local_data,
                        global_data=global_data
                    )

                if not idle_ready:
                    print('⣿ awsattack :≫ WARNING: Unable to start. Try backing up awsattack\'s awsattack.db file and deleting the old version. If the error persists, try reinstalling awsattack in a new directory.')
                    return

    def run(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--session', required=False, default=None, help='<session name>', metavar='')
        parser.add_argument('--technique-name', required=False, default=None, help='<technique name>', metavar='')
        parser.add_argument('--data', required=False, default=None, help='<service name/all>', metavar='')
        parser.add_argument('--technique-args', default=None, help='<--technique-args=\'--regions us-east-1,us-east-1\'>', metavar='')
        parser.add_argument('--list-ttp', action='store_true', help='List arguments')
        parser.add_argument('--awsattack-help', action='store_true', help='List the awsattack help window')
        parser.add_argument('--technique-info', action='store_true', help='Get information on a specific technique, use --technique-name')
        parser.add_argument('--exec', action='store_true', help='exec technique')
        parser.add_argument('--set-regions', nargs='+', default=None, help='<region1 region2 ...> or <all> for all', metavar='')
        parser.add_argument('--whoami', action='store_true', help='Display information on current IAM user')
        args = parser.parse_args()

        if any([args.session, args.data, args.technique_args, args.exec, args.set_regions, args.whoami]):
            if args.session is None:
                print('⣿ awsattack :≫ ACTION: Launching awsattack from the CLI is required')
                exit()
            self.run_cli(args)
        elif any([args.list_ttp, args.awsattack_help, args.technique_info]):
#            self.check_for_updates()
            self.run_cli(args)
        else:
            self.run_gui()


if __name__ == '__main__':
    Main().run()
