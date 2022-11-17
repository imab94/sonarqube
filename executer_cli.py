"""
###############################################################################################
#                                                                                             #
#    Title       : executer_cli.py                                                            #
#    Description : This file is used to initialize tools and run them                         #
#                  on VM / dockers, by reading the configuration form                         #
#                  config parser.                                                             #
#                1. Commands written in tool_config.ini are formatted in generate_command()   #                                                              #
#                2. Commands are executed from execute_command()                              #
#                3. Output formatting is done in fetch_from_output()(if required)             #                                                                    #
#                3. Report is transfered to report path                                       #
#                                                                                             #
#                                                                                             #
#    Aricent-CopyRight (C) 2018 ARICENT. All rights Reserved.                                 #
#    REVISION HISTORY                                                                         #
#    Date                Author              Reason                                           #
#    22 May 2018         Komal      Initial Version                                           #
#                                                                                             #
######################################################################################
"""

from configparser import ConfigParser
import logging
import xml.etree.ElementTree as ET
import pexpect
import paramiko
from .conf import tool_errors, tool_status_resp, COVERITY_SUPPORTED_LANGUAGES, openvas_task_resp, COVERITY_VALID_DATA
from .conf import TOOL_ENV_VARIABLES
import time
from django.conf import settings
from toolscan.commons import log_dict
REPORT_PATH = settings.REPORT_PATH
SONARQUBE_HOME = TOOL_ENV_VARIABLES['SONARQUBE_HOME']
SONAR_SCANNER_HOME = TOOL_ENV_VARIABLES['SONAR_SCANNER_HOME']
from celery.contrib import rdb

log = logging.getLogger(__name__)


class ExecuteToolsCli(object):
    """
        Generic class to execute all tools
        CLI tools
    """

    def __init__(self, **kwargs):
        """
        Constructor of class
        :param kwargs: Class initializing arguments
        """        
        self.parser = ConfigParser()
        self._this_config, self._output_key = [None] * 2
        self.parser.read('{}/executer/tools_config.ini'.format(settings.BASE_DIR))
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.all_sections = self.parser.sections()
        step0_section = self._read_section_to_dict('{}_step0'.format(
            self.tool_name.lower()))
        self.status_dict = {
            'status': False,
            'message': [],
            'filetype': '',
            'path': ''
        }
        if self.tool_name.lower()=="nmap":
            self.installed_dir = "/dockertool/" + self.tool_name.lower() if  self.platform.lower() == 'docker' else "/root"
            self.tool_path = '/dockertool' if self.platform.lower() == 'docker' else "/root"
        else:
            self.installed_dir ="/home/" + self.tool_name.lower() if  self.platform.lower() == 'docker' else "/root"
            self.tool_path = '/home' if self.platform.lower() == 'docker' else "/root"
        self.conn = self.connect_tool(step0_section)
        self.report_name = "{}_{}_{}{}".format(
            self.tool_name, self.workspace_id,
            self.chunk_id, getattr(self, 'scan_choice', ''))
        #fixed name for sonarqube
        if self.tool_name.lower().find('sonarqube') != -1:
            self.report_name = "{}_{}".format(
                self.tool_name, self.workspace_id
               )

        self.sections = [x for x in self.all_sections if x.startswith(self.tool_name + '_step')
                         and not x.endswith('step0')]
        self.config = {section: self._read_section_to_dict(section) \
                       for section in self.sections}
        self.set_prerequisite_tool()
        self.execute_prebuild_script()

    def sonar_scan_dotnet(self):
        if hasattr(self, 'Dot_Net_Code_Scan') and self.Dot_Net_Code_Scan == True:
            log_dict.update({"msg": "Sonarqube Dotnet  tool scan started :- %s" % self.tool_name})
            log.info(log_dict)
            try:
                log_dict.update({"msg": "11111111"})
                log.info(log_dict)
                self.sections = ['sonarqube_step10', 'sonarqube_step11', 'sonarqube_step12']
                
                self.config = {section: self._read_section_to_dict(section) \
                        for section in self.sections}
                from scp import SCPClient
                tool_info = self.tool_info
                sonar_msbuild_path = tool_info.get('ms_build_path')
                sonar_server_host = tool_info.get('host')
                sonar_loing_token = '/d:sonar.login="a3902342682bf31b06f6643d69491467f6605d78"'
                build_path = self.target_info[0].get('attributes_values').get('build')
                code_path = self.target_info[0].get('attributes_values').get('code_path')
                sonar_scanner_begin = sonar_msbuild_path+' begin /k:"'+self.report_name+'" /d:sonar.host.url="http://'+sonar_server_host+':9000" '+sonar_loing_token
                sonar_scanner_build = build_path+" "+code_path+" /t:Rebuild"
                sonar_scanner_end = sonar_msbuild_path+' end '+sonar_loing_token
                log_dict.update({"msg": "22222222"})
                log.info(log_dict)
                file_name = '/tmp/_run.cmd'
                with open(file_name, 'w') as f:
                    f.write(sonar_scanner_begin+"\n")
                    f.write(sonar_scanner_build+"\n")
                    f.write(sonar_scanner_end)
                log_dict.update({"msg": "3333333"})
                log.info(log_dict)
                log_dict.update({"msg": "Sonarqube Dotnet cmd file created."})
                log.info(log_dict)

                try:
                    wpath = sonar_msbuild_path.replace('\\','/\\')
                    wpath = wpath.rsplit('\\',1)[0]
                    cmd = 'scp {} {}@{}:{}'.format(file_name,tool_info.get('window_user'),tool_info.get('window_host'),wpath)
                    child = pexpect.spawn(cmd)
                    log_dict.update({"scp cmd": cmd})
                    log.info(log_dict)
                    i = child.expect(['password:', r"yes/no"], timeout=30)
                    if i == 0:
                        child.sendline(tool_info.get('window_password'))
                    elif i == 1:
                        child.sendline("yes")
                        child.expect("password:", timeout=30)
                        child.sendline(tool_info.get('window_password'))
                    log_dict.update({"msg": "Sonarqube Dotnet cmd file sent."})
                    log.info(log_dict)
                    path = sonar_msbuild_path.rsplit('\\',1)[0]+"\\"+file_name[5:]
                    path = path.replace('\\','/')
                    path = path.replace(':','')
                    exe_cmd = "cmd.exe cygdrive/"+path

                    log_dict.update({"msg exe_cmd": exe_cmd})
                    log.info(log_dict)

                    time.sleep(5)
                    in_err = 'The process cannot access the file because it is being used by another process'
                    ssh_client=paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh_client.connect(hostname=tool_info.get('window_host'),username=tool_info.get('window_user'),password=tool_info.get('window_password'))
                    i = True
                    while i:
                        stdin,stdout,stderr = ssh_client.exec_command(exe_cmd)
                        log_dict.update({"msg": "Cmd file executed."})
                        log.info(log_dict)
                        err = ''.join(stderr.readlines())
                        out = ''.join(stdout.readlines())
                        final_output = str(out)+str(err)
                        if final_output.find(in_err) == -1:
                            i = False
                        time.sleep(2)
                    log_dict.update({"msg": "Cmd file executed."})
                    log.info(log_dict)
                    if final_output.find('EXECUTION SUCCESS') > 1:
                        pass
                    else:
                        self.status_dict['status'] = False
                        self.status_dict['message'] = err
                        log_dict.update({"msg": "Sonar Dotnet Execution-1 failed ==> "+err})
                        log.error(log_dict)
                except Exception as e:
                    self.status_dict['status'] = False
                    self.status_dict['message'] = str(e)
                    log_dict.update({"msg": "Sonar Dotnet Execution-2 failed ==> "+str(e)})
                    log.error(log_dict)
            except Exception as e:
                log_dict.update({"msg": "Sonar Dotnet Execution-3 failed ==> %s" % str(e)})
                log.error(log_dict)
                self.status_dict['status'] = False
                self.status_dict['message'] = str(e)

    def execute(self):
        """
            execute tool as per the `n` steps defined.
            iterate over each step and call the servie with the created payload,
            and save the response in the output key declared in config,
            which will be helpfull to subsequent API calls

            return False if any API failed or not able to return desired output key

        """
        self.sonar_scan_dotnet()
        log_dict.update({"msg": "Start tool scan :- %s" % self.tool_name})
        print("###################   ",self.tool_name)
        log.info(log_dict)
        if not self.status_dict['message']:
            for steps in self.sections:
                self._this_config = self.config.get(steps)
                self._output_key = self._this_config.get('output_key', str())
                log_dict.update({"msg": "%s...<Step: %s>..."
                                        % (self._this_config.get('label'),
                                           steps)})
                log.info(log_dict)
                _output = self.generate_cmd()
                if not _output:
                    continue
                _output = self.execute_cmd(_output)
                if _output == 'Continue to next step':
                    self._output_key = 'ignore_key'
                _output = self.fetch_command_output(_output)
                if not _output or self.status_dict['message']:
                    log_dict.update({"msg": "Fetching details from command "
                                            "output ==> %s" %
                                            self.status_dict['message']})
                    log.error(log_dict)
                    break
                self._safe_setattr(_output, self._output_key)

            return self.report_transfer(
                source_path='{}/{}.{}'.format(
                    self.tool_path, self.report_name, self.output_type),
                destination_path=REPORT_PATH + "/Workspace_run_id_{}/".format(
                    self.workspace_run_id))
        log_dict.update({"msg": "Execution failed ==> %s" % self.status_dict})
        log.error(log_dict)
        return self.status_dict

    def set_prerequisite_tool(self):
        if self.tool_name.lower() == 'syntribos':
            conf_file_path = self.custom_script_transfer(source_path=self.conf_file)
            self.report_transfer(
                transfer_type='remote-local',
                source_path=conf_file_path,
                destination_path=self.tool_path)
            self.run_param = "dry_run" if self.dry_run else "run"
            self.openstack_service = self.openstack_service.lower()
            self.conf_file_name = self.conf_file.split('/')[-1]
        #elif self.tool_name.lower() == 'zap' and getattr(self, 'conf_file', False):
        #    conf_file_path = self.custom_script_transfer(source_path=self.conf_file)
        #    self.report_transfer(
        #        transfer_type='remote-local',
        #        source_path=conf_file_path,
        #        destination_path=self.tool_path)

        elif self.tool_name.lower() == 'nmap' and ',' in self.targets:
            self.targets=self.targets.replace(',', '\n')

        elif self.tool_name.lower() == 'sonarqube':
            if self.platform.lower()=='docker':
                self.sonar_flag=True
            self.sonarqube_home = TOOL_ENV_VARIABLES['SONARQUBE_HOME']
            self.sonar_scanner_home = TOOL_ENV_VARIABLES['SONAR_SCANNER_HOME']
            self.sonar_url='http:\/\/{}:9000'.format(getattr(self,'host','localhost'))
            self.sonar_user='admin'

        elif self.tool_name.lower() == 'sonarqube6':
            if self.platform.lower()=='docker':
                self.sonar_flag=True
            self.sonarqube_home = TOOL_ENV_VARIABLES['SONARQUBE_HOME_6']
            self.sonar_scanner_home = TOOL_ENV_VARIABLES['SONAR_SCANNER_HOME_6']
            self.sonar_url='http:\/\/{}:9000'.format(getattr(self,'host','localhost'))
            self.sonar_user='admin'

        elif self.tool_name.lower() == 'coverity':
            self.arguments = self.arguments.strip()
            add_build = False
            add_no_command = False
            build_path =''
            if self.language in COVERITY_SUPPORTED_LANGUAGES.get('compiler', []) or self.build:
                # coverity takes care of running filesystem capture files (interpreter files) if present
                self.code_path = self.code_path.rstrip('/')
                add_build = True
                build_path = '{}/{}'.format(getattr(self, 'code_path', ''),
                                            getattr(self, 'build', '')) if getattr(self, 'code_path','') else self.build

            elif self.language in COVERITY_SUPPORTED_LANGUAGES.get('interpreter', []) or \
                            self.language.lower() == 'all':
                add_no_command = True
                build_path = '{}/{}'.format(getattr(self, 'code_path', ''),
                                            getattr(self, 'build', '')) if getattr(self, 'code_path','') else self.build

            if getattr(self, 'incremented_files', []):
                self._this_config = {}

                self.changed_files = ' '.join([i for i in self.incremented_files if i.startswith(getattr(self,'sub_dir',''))
                                               and (i.endswith('.c') or i.endswith('.h'))])
                if not self.changed_files:
                    self.status_dict['status']=True
                    self.status_dict['message']='No Changes observed Findings already posted for this repo'
                    log_dict.update({"msg": "No Changes observed Findings "
                                            "already posted for this repo"})
                    log.info(log_dict)

            self.build_dir = '/'.join(build_path.split('/')[0:-1]) if build_path else '/'.join(self.build.split('/')[0:-1])
            self.build_arg = ' --dir {}/havoc_analysis {} {}'. \
                format(self.build_dir,
                       " --no-command --fs-capture-search {}".format(self.code_path) if add_no_command else "",
                       build_path if add_build else self.code_path)
        sub_dir = '' if not getattr(self, 'sub_dir', '') else '{}{}'.format('/', getattr(self, 'sub_dir', ''))
        self.code_path = "{}/{}".format(getattr(self, 'code_path',''), sub_dir)

    def _read_section_to_dict(self, section):
        """
            convert each section data to a dictionary of steps in sections
        """
        return {k: self.parser.get(section, k) for k in self.parser.options(section)}

    def _safe_setattr(self, data, limitations):
        """
            iterate reponse dict and set only the output key as class variables
            if data is str or unicode, set outputkey as reponse data directly_output, self._output_ke
        """
        if isinstance(data, dict):
            for key, val in data.items():
                if key in limitations.split(','):
                    setattr(self, key, val)
        elif isinstance(data, list):
            for a, b in zip(data, limitations.split(',')):
                setattr(self, b, a)
        else:
            setattr(self, limitations, data)

    def connect_tool(self, section=None):
        """
        Connect tool using ssh
        :return: ssh_obj

        """
        self.output_type = section.get('output_type')
        if self.platform.lower() == 'docker':
            self.host = getattr(self, 'docker_host', '')
            self.host_user = getattr(self, 'docker_user', '')
            self.host_password = getattr(self, 'docker_password', '')

        conn_var = [getattr(self, k) for k in section.get('cmd_params').split(',')]
        if conn_var:
            _tries = int(section.get('tries', 1))
            _attempt = 1

            while _tries > 0 and _attempt <= _tries:
                log_dict.update({"msg": "%s...<step0>...<Attempt No: #%s>..."
                                        % (section.get('label'), _attempt)})
                log.info(log_dict)
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(
                        self.host,
                        username=getattr(self, 'host_user', ''),
                        password=getattr(self, 'host_password', '')
                    )
                    return client
                except:
                    log_dict.update(
                        {"msg": "Failed to establish ssh connection "
                                "with ==> %s" % self.tool_name})
                    log.error(log_dict)
                    self.status_dict['message'].append(
                        "Failed to establish ssh connection with {}".format(self.tool_name))
                    return self.status_dict

    def report_transfer(self, source_path, destination_path, log_name=None, transfer_type=None):
        """
        Transfer reports generated by different tools to local path

        :return: True or Exception
        """
        if log_name:
            split = source_path.split('/')
            suffix = "_{}_{}".format(self.workspace_run_id, self.chunk_id)
            renamed_log = split[-1].split('.')[0] + suffix + "." + split[-1].split('.')[1]
            renamed_path = "/".join(split[:-1]) + "/" + renamed_log
            cmd = 'mv {} {}'.format(source_path, renamed_path)
            self.execute_cmd(cmd)
            source_path = renamed_path
        time.sleep(5)
        if not self.status_dict['message']:
            try:
                cmd = 'scp {}@{}:{} {}'.format(
                    self.host_user,
                    self.host,
                    source_path,
                    destination_path) if not transfer_type else 'scp {} {}@{}:{}'. \
                    format(source_path, self.host_user, self.host, destination_path)
                child = pexpect.spawn(cmd)
                log_dict.update({"msg": "Generated command is:  %s" % cmd})
                log.info(log_dict)

                i = child.expect(['password:', r"yes/no"], timeout=30)
                if i == 0:
                    child.sendline(self.host_password)
                elif i == 1:
                    child.sendline("yes")
                    child.expect("password:", timeout=30)
                    child.sendline(self.host_password)
                data = child.read()
                if transfer_type:
                    return self.status_dict
                if 'ETA' or '100%' in data.decode('UTF-8'):
                    self.status_dict['path'] = "{}/Workspace_run_id_{}/{}.{}".format(
                        REPORT_PATH, self.workspace_run_id,
                        self.report_name, self.output_type)
                    self.status_dict['filetype'] = self.output_type
                    self.status_dict['status'] = True
                    cmd = 'rm -rf {} && rm -rf {}'.format(
                        source_path, self.code_path
                    ) if getattr(self, 'scan_choice', '') else 'rm -rf {}'.format(source_path)
                    self.execute_cmd(cmd)

                return self.status_dict
            except Exception as detail:
                log_dict.update({"msg": "Failed to transfer file to "
                                        "remote machine: %s" % str(detail)})
                log.error(log_dict)
                self.status_dict['message'].append("Failed to transfer file to remote machine: {}".format(str(detail)))
        return self.status_dict

    def generate_cmd(self):
        """
        Generates CLI command
        :return: formated command
        """
        _conf = self._this_config
        _ignore_condition = _conf.get('ignore_condition')
        if _ignore_condition and getattr(self, _ignore_condition, None):
            _cmd_formatter = _conf.get('ignore_cmd_params')
            resp = _conf.get('ignore_cmd').format(
                *[getattr(self, k) for k in _cmd_formatter.split(',')]) \
                if _cmd_formatter else _conf.get('ignore_cmd')
        else:
            _cmd_formatter = _conf.get('cmd_params')
            resp = _conf.get('cmd').format(
                *[getattr(self, k) for k in _cmd_formatter.split(',')]) \
                if _cmd_formatter else _conf.get('cmd')
        log_dict.update({"msg": "Generated command is : %s" % resp})
        log.info(log_dict)
        return resp

    def execute_cmd(self, data):
        """

        :param data: comand data to be executed
        :return: command output or Exception
        """
        _conf = self._this_config
        _ignore = _conf.get('ignore', None)
        _rerun = _conf.get('rerun', None)
        _docker_rerun = _conf.get('docker_rerun', None) and self.platform.lower()=='docker'
        cmd_output = []
        cmd_error = []

        try:
            time.sleep(int(_conf.get('sleep_time', 0)))
            stdin, stdout, stderr = self.conn.exec_command(data)
            for l in stdout:
                cmd_output.append(l.strip())
                log_dict.update({"msg": "Command output:%s" % l.strip()})
                log.info(log_dict)
            for l in stderr:
                cmd_error.append(l.strip())
                log_dict.update({"msg": "Error:%s" % l.strip()})
                log.info(log_dict)
            exit_status = stdout.channel.recv_exit_status()  # Blocking call
            if exit_status == 0:  # command ran successfully
                log_dict.update({"msg": "command executed:%s and output %s" %
                                        (data, cmd_output)})
                log.info(log_dict)
                return cmd_output
            elif _rerun or _docker_rerun:
                time.sleep(int(_conf.get('sleep_time', 0)))
                log_dict.update({"msg": "Rerun trigger received for"
                                        " %s" % _conf.get('label')})
                log.info(log_dict)
                return self.execute_cmd(data)
            elif _ignore or 'already running' in stdout.read().decode('utf-8'):
                return 'Continue to next step'
            else:
                self.status_dict['message'].append(
                    "Command failed with error: {}".format(cmd_error))
        except:
            self.conn.close()
            log_dict.update({"msg": "Failed to execute command ==> %s" % data})
            log.error(log_dict)
            self.status_dict['message'].append("Failed to execute command {}".format(data))
            return self.status_dict

    def fetch_command_output(self, data):
        """
        Fetches required value from command output
        :param data: command line output
        :return: required field to be extracted or error
        """
        resp = None
        _conf = self._this_config
        _fetch_atr = _conf.get('fetch_atr')
        check_pattern = _conf.get('fetch_pattern')
        set_var = getattr(self, _conf.get('compare_fetch_pattern')) if \
            _conf.get('compare_fetch_pattern') else None
        _skip = _conf.get('skip_fetch', None)
        if _skip:
            return "Continue to next step"
        if self.output_type == 'xml' and not resp:
            xmlstr = data[0]
            for error in tool_errors:
                if error in xmlstr.strip().lower():
                    self.status_dict['message'].append(tool_errors[error])
                    log_dict.update({"msg": "Error occurred ==>%s"
                                            % tool_errors[error]})
                    log.info(log_dict)
                    return self.status_dict
            root = ET.fromstring(xmlstr)
            status = root.attrib['status']
            if status not in tool_status_resp or status == '400':
                log_dict.update({"msg": "Either entity is already created or"
                                        " other issue, Status ==> %s" % status})
                log.info(log_dict)
                self.status_dict['message'].append(
                    "Either entity is already created or other issue, Status {} ".format(status))
                return self.status_dict
            elif status == '201':
                root.findall(".")
                resp = root.attrib[_fetch_atr]
            elif status == '200':
                for pattern in root.findall(check_pattern):
                    if set_var:
                        pattern_name = pattern.find('name').text
                        if pattern_name.strip().lower() == set_var.strip().lower():
                            resp = pattern.attrib[_fetch_atr]

                    else:
                        pattern = root.find(_fetch_atr)
                        resp = tool_status_resp.get(pattern.text, None) if pattern else ''
            elif status == '202':
                root.findall(".")
                resp = root.find(check_pattern).text
            else:
                resp = None
        elif self.output_type in ('csv', 'txt', 'json'):
            for elem in data:
                [self.status_dict['message'].append(tool_errors[error]) if error in elem else self.status_dict[
                    'message'] for error in tool_errors]

            if not self.status_dict['message'] == []:
                return self.status_dict
            resp = data
        return resp

    def custom_script_transfer(self, source_path, destination_path=settings.CUSTOM_SCRIPT_PATH):
        try:
            host = settings.SFTP_HOST
            port = settings.SFTP_PORT
            username = settings.SFTP_USERNAME
            password = settings.SFTP_PASSWORD
            transport = paramiko.Transport(host, port)
            source_path = "{}{}".format(settings.SFTP_STORAGE_CUSTOM_SCRIPT, source_path)
            file_name = source_path.split('/')[-1]
            if transport:
                log_dict.update({"msg": "Opening SFTP transport"})
                log.info(log_dict)
            transport.connect(username=username, password=password)

            sftp = paramiko.SFTPClient.from_transport(transport)
            if sftp:
                log_dict.update({"msg": "Connected to SFTP transport "
                                        "successfully"})
                log.info(log_dict)
                sftp.get(source_path, "{}/{}".format(destination_path, file_name))
                log_dict.update({"msg": "Custom script downloaded to %s"
                                        % destination_path})
                log.info(log_dict)
                sftp.close()
                transport.close()
                return "{}/{}".format(destination_path,file_name)
        except Exception as e:
            self.status_dict['message'] = "SFTP transport failed:  {}".format(e)
            log_dict.update({"msg": "SFTP transport ==> %s" % e})
            log.info(log_dict)

    def execute_prebuild_script(self):
        pre_build_path=''
        if getattr(self,'pre_build_path', ''):
            pre_build_path = "{}/{}".format(getattr(self,'code_path', ''),getattr(self,'pre_build_path', ''))
        
        status=False
        if self.scan_type.lower()=='static code review' and \
                (getattr(self,'language','') in COVERITY_SUPPORTED_LANGUAGES.get('compiler', [])) and pre_build_path:
            pre_build_dir = '/'.join(pre_build_path.split('/')[0:-1]) 
            cmd = "cd {} && sh {}".format(pre_build_dir, pre_build_path)
            self._this_config={}
            status = self.execute_cmd(cmd)
        return status
