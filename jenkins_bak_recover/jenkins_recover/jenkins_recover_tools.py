# -*- coding: utf-8 -*-
# @Time    : 2022/5/31 11:29
# @Author  : Tom_zc
# @FileName: jenkins_recover_tools.py
# @Software: PyCharm

import copy
import time
import jenkins
import argparse
import os
import subprocess
import xmltodict
import shutil
import json
import yaml
import base64
import traceback
from functools import wraps
from lxml import etree
from obs import ObsClient
from jenkinsapi.plugin import Plugin
from jenkinsapi.plugins import Plugins
from jenkinsapi import jenkins as jenkins_api
from jenkinsapi.credentials import Credentials2x, Credentials
from jenkinsapi.custom_exceptions import JenkinsAPIException

try:
    from StringIO import StringIO
    from urllib import urlencode
except ImportError:
    # Python3
    from io import BytesIO as StringIO
    from urllib.parse import urlencode


class GlobalConfig(object):
    current_path = os.getcwd()
    config_path = os.path.join(current_path, "jenkins_recover.yaml")
    job_dir_name = "jobs-config"
    view_dir_name = "view-config"
    node_dir_name = "node-config"
    cre_dir_name = "credentials-config"
    folder_dir_name = "folder-config"
    plugin_dir_name = "plugin-config"

    folder_name = "folder.yaml"
    plugin_name = "plugins.yaml"
    credentials_name = "credentials.yaml"

    user_name = "user.yaml"
    config_clouds_name = "config.xml"
    default_secret = b'YWJjQDEyMw=='

    obs_default_bucket = "obs-for-openeuler-developer"
    obs_default_obj = "jenkins-secret"
    obs_default_config = "jenkins-config"

    git_clone_cmd = "cd {} && git clone https://github.com/opensourceways/infra-jenkins.git"

    install_off_pkg_domain = ["jenkins.opengauss.org", "openeulerjenkins.osinfra.cn", "build.openlookeng.io", "build.mindspore.cn"]
    install_off_pkg_dir_name = "pkg"


def func_retry(tries=3, delay=1):
    """The wrapper of retry"""

    def deco_retry(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            for i in range(tries):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    print("e:{}, traceback:{}".format(e, traceback.print_exc()))
                    time.sleep(delay)
            else:
                raise Exception("func_retry: {} failed".format(fn.__name__))

        return inner

    return deco_retry


class JenkinsPlugins(Plugins):
    def __init__(self, *args, **kwargs):
        super(JenkinsPlugins, self).__init__(*args, **kwargs)

    def _install_specific_version(self, plugin):
        """Plugins that are not the latest version have to be uploaded."""
        download_link = plugin.get_download_link(
            update_center_dict=self.update_center_dict)
        downloaded_plugin = self._download_plugin(download_link)
        plugin_dependencies = self._get_plugin_dependencies(downloaded_plugin)
        self.jenkins_obj.install_plugins(plugin_dependencies)
        url = ('%s/pluginManager/uploadPlugin' % self.jenkins_obj.baseurl)
        requester = self.jenkins_obj.requester
        downloaded_plugin.seek(0)
        file = {"name": ("{}.hpi".format(str(plugin)), downloaded_plugin, "application/octet-stream"),
                "pluginUrl": ("", "")}
        requester.post_and_confirm_status(
            url, files=file,
            data={}, params={})


class JenkinsLib(jenkins_api.Jenkins):
    def __init__(self, *args, **kwargs):
        super(JenkinsLib, self).__init__(*args, **kwargs)

    def get_plugins(self, depth=1):
        """Get all the plugins"""
        url = self.get_plugins_url(depth=depth)
        return JenkinsPlugins(url, self)

    def get_credentials(self, cred_class=Credentials2x):
        """Get all the credentials"""
        if 'credentials' not in self.plugins:
            raise JenkinsAPIException('Credentials plugin not installed')
        if self.plugins['credentials'].version[0:4] == "1087":
            url = '%s/credentials/store/system/domain/_/' % self.baseurl
            return cred_class(url, self)
        elif int(self.plugins['credentials'].version[0:1]) == 1:
            url = '%s/credential-store/domain/_/' % self.baseurl
            return Credentials(url, self)
        else:
            url = '%s/credentials/store/system/domain/_/' % self.baseurl
            return cred_class(url, self)

    def create_credentials(self, dict_data, files=None, params=None):
        if 'credentials' not in self.plugins:
            raise JenkinsAPIException('Credentials plugin not installed')
        if self.plugins['credentials'].version[0:4] == "1087":
            url = '%s/credentials/store/system/domain/_/createCredentials' % self.baseurl
        elif int(self.plugins['credentials'].version[0:1]) == 1:
            url = '%s/credential-store/domain/_/createCredentials' % self.baseurl
        else:
            url = '%s/credentials/store/system/domain/_/createCredentials' % self.baseurl

        valid = self.requester.VALID_STATUS_CODES
        resp = self.requester.post_and_confirm_status(url, data=dict_data, files=files, params=params,
                                                      valid=valid)
        return resp

    # noinspection PyUnresolvedReferences
    def install_plugins(self, plugin_list, restart=True, force_restart=False,
                        wait_for_reboot=True, no_reboot_warning=False, no_restart=False):
        """install plugins"""
        plugins = [p if isinstance(p, Plugin) else Plugin(p)
                   for p in plugin_list]
        failed_list = list()
        for plugin in plugins:
            print("start to install:{}".format(plugin))
            try:
                self.install_plugin(plugin, restart=False, no_reboot_warning=True)
            except Exception as e:
                print(e)
                failed_list.append(plugin.shortName)
        if failed_list:
            return failed_list
        if no_restart:
            return []
        if force_restart or (restart and self.plugins.restart_required):
            self.safe_restart(wait_for_reboot=wait_for_reboot)
        elif self.plugins.restart_required and not no_reboot_warning:
            print(
                "System reboot is required, but automatic reboot is disabled. "
                "Please reboot manually."
            )

    # noinspection PyProtectedMember
    def install_off_line_plugins(self, path):
        """install off_line plugins"""
        _, file_name = os.path.split(path)
        with open(path, "rb") as f:
            content = f.read()
        downloaded_plugin = StringIO()
        downloaded_plugin.write(content)
        plugin_dependencies = self.plugins._get_plugin_dependencies(downloaded_plugin)
        self.install_plugins(plugin_dependencies, no_restart=True)
        url = '%s/pluginManager/uploadPlugin' % self.baseurl
        requester = self.requester
        downloaded_plugin.seek(0)
        cre = self.requester._get_crumb_data()
        file = {"name": (file_name, downloaded_plugin, "application/octet-stream"), "pluginUrl": ("", "")}
        response = requester.post_and_confirm_status(url, files=file, data={}, params=cre)
        return response

    def create_user(self, username, password, fullname, email):
        """use the default password to create user"""
        body = {
            "username": username,
            "$redact": ["password1", "password2"],
            "password1": password,
            "password2": password,
            "fullname": fullname,
            "email": email}
        url = "%s/securityRealm/createAccountByAdmin" % self.baseurl
        valid = self.requester.VALID_STATUS_CODES + [302, ]
        resp = self.requester.post_and_confirm_status(url, data=body,
                                                      valid=valid)
        return resp

    def create_clouds_config(self, body):
        """create clouds config"""
        url = "%s/configureClouds/configure" % self.baseurl
        valid = self.requester.VALID_STATUS_CODES + [302, ]
        resp = self.requester.post_and_confirm_status(url, data=body,
                                                      valid=valid)
        return resp

    def get_user_lists(self):
        """get username list"""
        url = "%s/securityRealm" % self.baseurl
        resp = self.requester.get_url(url)
        html_content = resp.content.decode("utf-8")
        html = etree.HTML(html_content)
        user_name_list = html.xpath("//td/a")
        user_list = list()
        for i in range(0, len(user_name_list), 2):
            username = user_name_list[i].text
            if username:
                user_list.append(username.strip())
        return user_list

    def get_config_xml(self):
        """Get config.xml by groovy script"""
        config_script = """println "cat /var/jenkins_home/config.xml".execute().text """
        return self.run_groovy_script(config_script)


class JenkinsTools(object):
    def __init__(self, *args, **kwargs):
        super(JenkinsTools, self).__init__(*args, **kwargs)

    @classmethod
    def parse_input_args(cls):
        """parse input args"""
        par = argparse.ArgumentParser()
        par.add_argument("-config_path", "--config_path", help="the config path of jenkins_bak.yaml",
                         required=False)
        args = par.parse_args()
        if args.config_path is None:
            config_path = GlobalConfig.config_path
        else:
            config_path = args.config_path
        return config_path

    @classmethod
    def check_params(cls, data):
        """check input params"""
        if not isinstance(data, dict):
            raise Exception("The yaml config must be dict")
        if data.get("jenkins_url") is None:
            raise Exception("The git_token of yaml is invalid")
        if data.get("jenkins_username") is None:
            raise Exception("The jenkins_username of yaml is invalid")
        if data.get("jenkins_password") is None:
            raise Exception("The jenkins_password of yaml is invalid")
        if data.get("bak_jenkins_domain") is None:
            raise Exception("The bak_jenkins_domain of yaml is invalid")
        if data.get("huaweiclound_obs_url") is None:
            raise Exception("The huaweiclound_obs_url of yaml is invalid")
        if data.get("huaweiclound_obs_ak") is None:
            raise Exception("The huaweiclound_obs_ak of yaml is invalid")
        if data.get("huaweiclound_obs_sk") is None:
            raise Exception("The huaweiclound_obs_sk of yaml is invalid")
        if data.get("jobs_list") is None:
            raise Exception("The jobs_list of yaml is invalid")

    @staticmethod
    def rmd_dir(dir_path):
        """remove dir"""
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)

    @staticmethod
    def load_yaml(file_path, method="load"):
        """load yaml
        method: load_all/load
        """
        yaml_load_method = getattr(yaml, method)
        with open(file_path, "r", encoding="utf-8") as file:
            content = yaml_load_method(file, Loader=yaml.FullLoader)
        return content

    @staticmethod
    def load_txt(file_path, is_json_loads=True):
        """load txt"""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return json.loads(content) if is_json_loads else content

    @staticmethod
    def execute_cmd(cmd):
        """execute cmd"""
        return subprocess.getoutput(cmd)

    @func_retry()
    def check_service_normal(self, config_dict):
        """check service normal"""
        jenkins_instance = jenkins.Jenkins(config_dict["jenkins_url"], config_dict["jenkins_username"],
                                           config_dict["jenkins_password"], timeout=180)
        jenkins_api_instance = JenkinsLib(config_dict["jenkins_url"], config_dict["jenkins_username"],
                                          config_dict["jenkins_password"], useCrumb=True, timeout=180)
        return jenkins_instance, jenkins_api_instance

    @staticmethod
    def base64_decode(token):
        """base64 decode"""
        content = base64.b64decode(token)
        return content.decode("utf-8")

    @staticmethod
    def create_job(jobs_list, job_name, jenkins_instance, job_content):
        """create job"""
        if jobs_list and job_name not in jobs_list:
            return
        if not jenkins_instance.job_exists(job_name):
            jenkins_instance.create_job(job_name, job_content)

    @staticmethod
    def create_credentials_tools(jenkins_api_instance, body_data, cre_info):
        """create credentials_files"""
        if cre_info["jenkins_class"] in [CredentialsTools.file_class, ]:
            file = {"file0": (cre_info["fileName"], cre_info['secretBytes'], "application/octet-stream")}
            jenkins_api_instance.create_credentials(body_data, files=file)
        else:
            jenkins_api_instance.create_credentials(body_data)

    @staticmethod
    def decode_secret(value):
        """decode secret"""
        content = base64.b64decode(value)
        return content.decode("utf-8").strip()

    @staticmethod
    def parse_hw_vpc(exists_clouds_name_list, clouds_class, clouds_temp):
        if clouds_class != "io.jenkins.plugins.huaweicloud.HuaweiVPC":
            exists_clouds_name_list.append(clouds_temp["name"])
        else:
            temp = clouds_temp["name"].split(sep="ecs-", maxsplit=1)
            exists_clouds_name_list.append(temp[1])


class CredentialsTools(object):
    password_class = "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl"
    secret_class = "org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl"
    ssh_class = "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey"
    ssh_direct_entry_class = "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$DirectEntryPrivateKeySource"
    gitlab_token_class = "com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl"
    gitee_token_class = "com.gitee.jenkins.connection.GiteeApiTokenImpl"
    github_token_class = "org.jenkinsci.plugins.github__branch__source.GitHubAppCredentials"
    openshift_class = "org.jenkinsci.plugins.kubernetes.credentials.OpenShiftBearerTokenCredentialImpl"
    x509_class = "org.jenkinsci.plugins.docker.commons.credentials.DockerServerCredentials"
    file_class = "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl"
    certificateCredentials_class = "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl"
    certificateCredentials_update_class = "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl$UploadedKeyStoreSource"
    token_class = "com.elasticbox.jenkins.k8s.plugin.auth.TokenCredentialsImpl"
    kubeconfig_class = "com.microsoft.jenkins.kubernetes.credentials.KubeconfigCredentials"
    fs_service_account_class = "org.jenkinsci.plugins.kubernetes.credentials.FileSystemServiceAccountCredential"
    ak_sk_class = "io.jenkins.plugins.huaweicloud.credentials.HWCAccessKeyCredentials"

    def __init__(self, *args, **kwargs):
        super(CredentialsTools, self).__init__(*args, **kwargs)

    @classmethod
    def get_credentials_templates(cls):
        templates = {
            cls.password_class: ["password"],
            cls.secret_class: ["secret"],
            cls.ssh_class: ["privateKey"],
            cls.gitlab_token_class: ["apiToken"],
            cls.gitee_token_class: ["apiToken"],
            cls.github_token_class: ["privateKey"],
            cls.openshift_class: ["password"],
            cls.x509_class: ["clientKey"],
            cls.file_class: ["secretBytes"],
            cls.certificateCredentials_class: ["password", "uploadedKeystoreBytes"],
            cls.token_class: ["token"],
            cls.kubeconfig_class: ["content"],
            cls.ak_sk_class: ["accessKey", "secretKey"],
        }
        return templates

    @classmethod
    def get_password_templates(cls):
        """if have usernameSecret, Please add"""
        #  "usernameSecret": true,
        return {"": "0", "credentials": {"scope": "GLOBAL",
                                         "$redact": "password",
                                         "usernameSecret": False,
                                         "id": "",
                                         "description": "",
                                         "username": "",
                                         "password": "",
                                         "stapler-class": cls.password_class,
                                         "$class": cls.password_class}}

    @classmethod
    def get_github_token_templates(cls):
        """if have privateKey or owner, Please add"""
        # "privateKey": "4", "owner": "5"
        return {"": "1", "credentials": {"id": "",
                                         "description": "",
                                         "appID": "",
                                         "apiUri": "",
                                         "owner": "",
                                         "stapler-class": cls.github_token_class,
                                         "$class": cls.github_token_class}}

    @classmethod
    def get_gitlab_token_templates(cls):
        return {"": "2", "credentials": {"scope": "GLOBAL",
                                         "$redact": "apiToken",
                                         "id": "",
                                         "description": "",
                                         "apiToken": "",
                                         "stapler-class": cls.gitlab_token_class,
                                         "$class": cls.gitlab_token_class}}

    @classmethod
    def get_gitee_token_templates(cls):
        return {"": "3", "credentials": {"scope": "GLOBAL",
                                         "$redact": "apiToken",
                                         "id": "",
                                         "description": "",
                                         "apiToken": "",
                                         "stapler-class": cls.gitee_token_class,
                                         "$class": cls.gitee_token_class}}

    @classmethod
    def get_openshift_templates(cls):
        """if have usernameSecret, Please add"""
        #  "usernameSecret": True,
        return {"": "4", "credentials": {"scope": "GLOBAL",
                                         "$redact": "password",
                                         "usernameSecret": False,
                                         "id": "",
                                         "description": "",
                                         "username": "",
                                         "password": "",
                                         "stapler-class": cls.openshift_class,
                                         "$class": cls.openshift_class}}

    @classmethod
    def get_ssh_private_templates(cls, is_private_key=False):
        """if have usernameSecret or privateKeySource, Please add
        "usernameSecret": True,
        "privateKeySource": {
                             "value": "0",
                             "privateKey": "private_keyadskjlfajkl;sdkj;fkjlasdkjlfkjlaskjldfkjl;jkalsdkjfas",
                             "stapler-class": cls.ssh_direct_entry_class,
                             "$class": cls.ssh_direct_entry_class
                            },
        """
        ssh_p_templates = {"": "5", "credentials": {"scope": "GLOBAL",
                                                    "$redact": "passphrase",
                                                    "id": "",
                                                    "description": "",
                                                    "username": "",
                                                    "usernameSecret": False,
                                                    "passphrase": "",
                                                    "stapler-class": cls.ssh_class,
                                                    "$class": cls.ssh_class}}
        if is_private_key:
            ssh_p_templates["credentials"]["privateKeySource"] = {
                "value": "0",
                "privateKey": "",
                "stapler-class": cls.ssh_direct_entry_class,
                "$class": cls.ssh_direct_entry_class
            }
        return ssh_p_templates

    @classmethod
    def get_secret_file_templates(cls):
        return {"": "6", "credentials": {"scope": "GLOBAL",
                                         "id": "",
                                         "description": "",
                                         "file": "file0",
                                         "stapler-class": cls.file_class,
                                         r"$class": cls.file_class}}

    @classmethod
    def get_secret_text_templates(cls):
        return {"": "7", "credentials": {"scope": "GLOBAL",
                                         "$redact": "secret",
                                         "id": "",
                                         "description": "",
                                         "secret": "",
                                         "stapler-class": cls.secret_class,
                                         "$class": cls.secret_class}}

    @classmethod
    def get_x509_client_templates(cls):
        return {"": "8", "credentials": {"scope": "GLOBAL",
                                         "id": "",
                                         "clientKeySecret": "",
                                         "clientCertificate": "",
                                         "serverCaCertificate": "",
                                         "description": "",
                                         "stapler-class": cls.x509_class,
                                         "$class": cls.x509_class}}

    @classmethod
    def get_certificate_templates(cls):
        return {"": "9", "credentials": {"scope": "GLOBAL",
                                         "keyStoreSource": {"value": "1",
                                                            "uploadedKeystore": "",
                                                            "stapler-class": cls.certificateCredentials_update_class,
                                                            "$class": cls.certificateCredentials_update_class,
                                                            },
                                         "id": "",
                                         "password": "",
                                         "description": "",
                                         "stapler-class": cls.certificateCredentials_class,
                                         "$class": cls.certificateCredentials_class}}

    @classmethod
    def get_ak_sk_templates(cls):
        return {"": "9", "credentials": {"scope": "GLOBAL",
                                         "id": "",
                                         "accessKey": "",
                                         "secretKey": "",
                                         "description": "",
                                         "stapler-class": cls.ak_sk_class,
                                         "$class": cls.ak_sk_class}}

    @classmethod
    def get_params(cls, cre_info):
        if cre_info['jenkins_class'] == cls.password_class:
            cre = cls.get_password_templates()
            cre['credentials']['username'] = cre_info['username'] or ""
            cre['credentials']['password'] = cre_info['password']
            cre['credentials']['id'] = cre_info["id"]
            cre['credentials']['description'] = cre_info["description"] or ""
            cre['credentials']['stapler-class'] = cre_info["jenkins_class"]
            cre['credentials']['$class'] = cre_info["jenkins_class"]
        elif cre_info["jenkins_class"] == cls.ssh_class:
            is_private_key = int(cre_info["key_type"]) == 0
            cre = cls.get_ssh_private_templates(is_private_key)
            cre['credentials']['username'] = cre_info['username'] or ""
            cre['credentials']['id'] = cre_info["id"]
            cre['credentials']['description'] = cre_info["description"] or ""
            cre['credentials']['passphrase'] = cre_info["passphrase"]
            cre['credentials']['stapler-class'] = cre_info["jenkins_class"]
            cre['credentials']['$class'] = cre_info["jenkins_class"]
            if is_private_key:
                cre["credentials"]["privateKeySource"]["privateKey"] = cre_info["privateKeySource"]["privateKey"]
        elif cre_info['jenkins_class'] == cls.secret_class:
            cre = cls.get_secret_text_templates()
            cre['credentials']['id'] = cre_info["credential_id"]
            cre['credentials']['description'] = cre_info["description"] or ""
            cre['credentials']['secret'] = cre_info["secret"]
        elif cre_info["jenkins_class"] == cls.gitee_token_class:
            cre = cls.get_gitee_token_templates()
            cre['credentials']['id'] = cre_info["credential_id"]
            cre['credentials']['description'] = cre_info["description"] or ""
            cre['credentials']['apiToken'] = cre_info["apiToken"]
        elif cre_info["jenkins_class"] == cls.github_token_class:
            cre = cls.get_github_token_templates()
            cre['credentials']['id'] = cre_info["credential_id"]
            cre['credentials']['description'] = cre_info["description"] or ""
            cre['credentials']['appID'] = cre_info["appID"]
            cre['credentials']['apiUri'] = cre_info["apiUri"]
            cre['credentials']['privateKey'] = cre_info["privateKey"]
            # cre['credentials']['owner'] = cre_info["owner"]
        elif cre_info["jenkins_class"] == cls.gitlab_token_class:
            cre = cls.get_gitlab_token_templates()
            cre['credentials']['id'] = cre_info["credential_id"]
            cre['credentials']['description'] = cre_info["description"] or ""
            cre['credentials']['apiToken'] = cre_info["apiToken"]
        elif cre_info["jenkins_class"] == cls.openshift_class:
            cre = cls.get_openshift_templates()
            cre['credentials']['id'] = cre_info["credential_id"]
            cre['credentials']['description'] = cre_info["description"] or ""
            cre['credentials']['username'] = cre_info["username"] or ""
            cre['credentials']['password'] = cre_info["credential_id"]
        elif cre_info["jenkins_class"] == cls.secret_class:
            cre = cls.get_secret_text_templates()
            cre['credentials']['id'] = cre_info["credential_id"]
            cre['credentials']['description'] = cre_info["description"] or ""
            cre['credentials']['secret'] = cre_info["credential_id"]
        elif cre_info["jenkins_class"] == cls.x509_class:
            cre = cls.get_x509_client_templates()
            cre['credentials']['id'] = cre_info["credential_id"]
            cre['credentials']['description'] = cre_info["description"] or ""
            cre['credentials']['clientKeySecret'] = cre_info["clientKey"]
            cre['credentials']['clientCertificate'] = cre_info["clientCertificate"]
            cre['credentials']['serverCaCertificate'] = cre_info["serverCaCertificate"]
        elif cre_info["jenkins_class"] == cls.certificateCredentials_class:
            cre = cls.get_certificate_templates()
            cre['credentials']['id'] = cre_info["credential_id"]
            cre['credentials']['description'] = cre_info["description"] or ""
            cre['credentials']['password'] = cre_info["password"]
            cre['credentials']['keyStoreSource']["uploadedKeystore"] = cre_info["keyStoreSource"][
                "uploadedKeystoreBytes"]
        elif cre_info["jenkins_class"] == cls.file_class:
            cre = cls.get_secret_file_templates()
            cre['credentials']['id'] = cre_info["credential_id"]
            cre['credentials']['description'] = cre_info["description"] or ""
        elif cre_info["jenkins_class"] == cls.ak_sk_class:
            cre = cls.get_ak_sk_templates()
            cre['credentials']['id'] = cre_info["credential_id"]
            cre['credentials']['description'] = cre_info["description"] or ""
            cre['credentials']['accessKey'] = cre_info["accessKey"] or ""
            cre['credentials']['secretKey'] = cre_info["secretKey"] or ""
        else:
            print("get_params cant to judge jenkins_class:{}, id:{}".format(cre_info["jenkins_class"],
                                                                            cre_info["credential_id"]))
            raise Exception("secret need to adapter...")
        return cre


class CloudsBaseTools(object):
    def __init__(self, *args, **kwargs):
        super(CloudsBaseTools, self).__init__(*args, **kwargs)

    @classmethod
    def _parse_return(cls, list_data):
        if len(list_data) == 0:
            return ""
        elif len(list_data) == 1:
            return list_data[0]
        else:
            return list_data


class K8sCloudsTools(CloudsBaseTools):
    def __init__(self, *args, **kwargs):
        super(K8sCloudsTools, self).__init__(*args, **kwargs)

    @classmethod
    def gen_k8s_pod_config(cls, pod_labels):
        pod_list = list()
        if isinstance(pod_labels, list):
            for pod_temp in pod_labels:
                for pod_class, pod_dict in pod_temp.items():
                    pod_list.append({
                        "key": pod_dict["key"],
                        "value": pod_dict["value"],
                        "stapler-class": pod_class,
                        "$class": pod_class,
                    })
        else:
            pod_temp = pod_labels
            for pod_class, pod_dict in pod_temp.items():
                pod_list.append({
                    "key": pod_dict["key"],
                    "value": pod_dict["value"],
                    "stapler-class": pod_class,
                    "$class": pod_class,
                })
        return cls._parse_return(pod_list)

    @classmethod
    def _gen_k8s_templates_volume(cls, volumes):
        volumes_list = list()
        if isinstance(volumes, list):
            for volumes_temp in volumes:
                for volume_class, volume_dict in volumes_temp.items():
                    volume_dict.update(
                        {
                            "stapler-class": volume_class,
                            "$class": volume_class,
                        }
                    )
                    volumes_list.append(volume_dict)
        else:
            for volume_class, volume_dict in volumes.items():
                volume_dict.update(
                    {
                        "stapler-class": volume_class,
                        "$class": volume_class,
                    }
                )
                volumes_list.append(volume_dict)
        return cls._parse_return(volumes_list)

    @classmethod
    def _gen_k8s_templates_containers_env_vars(cls, env_vars):
        env_vars_list = list()
        if isinstance(env_vars, list):
            for env_vars_temp in env_vars:
                for env_vars_class, env_vars_dict in env_vars_temp.items():
                    if isinstance(env_vars_dict, list):
                        for temp in env_vars_dict:
                            temp.update({
                                "stapler-class": env_vars_class,
                                "$class": env_vars_class,
                            })
                            env_vars_list.append(temp)
                    else:
                        env_vars_dict.update({
                            "stapler-class": env_vars_class,
                            "$class": env_vars_class,
                        })
                        env_vars_list.append(env_vars_dict)
        elif isinstance(env_vars, dict):
            for env_vars_class, env_vars_dict in env_vars.items():
                if isinstance(env_vars_dict, list):
                    for temp in env_vars_dict:
                        temp.update({
                            "stapler-class": env_vars_class,
                            "$class": env_vars_class,
                        })
                        env_vars_list.append(temp)
                else:
                    env_vars_dict.update({
                        "stapler-class": env_vars_class,
                        "$class": env_vars_class,
                    })
                    env_vars_list.append(env_vars_dict)
        return cls._parse_return(env_vars_list)

    @classmethod
    def _gen_k8s_templates_containers(cls, containers):
        containers_list = list()
        if isinstance(containers, list):
            for containers_temp in containers:
                for containers_class, containers_dict in containers_temp.items():
                    temp_dict = copy.deepcopy(containers_dict)
                    containers_env_vars = copy.deepcopy(temp_dict["envVars"])
                    del temp_dict["envVars"]
                    temp_dict["envVars"] = cls._gen_k8s_templates_containers_env_vars(containers_env_vars)
                    temp_dict["runAsUser"] = temp_dict["runAsUser"] if "runAsUser" in temp_dict.keys() else ""
                    temp_dict["runAsGroup"] = temp_dict["runAsGroup"] if "runAsGroup" in temp_dict.keys() else ""
                    temp_dict["stapler-class"] = containers_class
                    temp_dict["$class"] = containers_class
                    containers_list.append(temp_dict)
        else:
            for containers_class, containers_dict in containers.items():
                temp_dict = copy.deepcopy(containers_dict)
                containers_env_vars = copy.deepcopy(temp_dict["envVars"])
                del temp_dict["envVars"]
                if containers_env_vars:
                    temp_dict["envVars"] = cls._gen_k8s_templates_containers_env_vars(containers_env_vars)
                temp_dict["runAsUser"] = temp_dict["runAsUser"] if "runAsUser" in temp_dict.keys() else ""
                temp_dict["runAsGroup"] = temp_dict["runAsGroup"] if "runAsGroup" in temp_dict.keys() else ""
                temp_dict["stapler-class"] = containers_class
                temp_dict["$class"] = containers_class
                containers_list.append(temp_dict)
        return cls._parse_return(containers_list)

    @classmethod
    def _gen_k8s_templates_images_pull_secrets(cls, image_pull_secrets):
        image_pull_secrets_list = list()
        if isinstance(image_pull_secrets, list):
            for image_pull_sec_temp in image_pull_secrets:
                for img_pull_sec_class, img_pull_sec_dict in image_pull_sec_temp.items():
                    image_pull_secrets_list.append({
                        "name": img_pull_sec_dict["name"],
                        "stapler-class": img_pull_sec_class,
                        "$class": img_pull_sec_class,
                    })
        else:
            for img_pull_sec_class, img_pull_sec_dict in image_pull_secrets.items():
                image_pull_secrets_list.append({
                    "name": img_pull_sec_dict["name"],
                    "stapler-class": img_pull_sec_class,
                    "$class": img_pull_sec_class,
                })
        return cls._parse_return(image_pull_secrets_list)

    @classmethod
    def _gen_k8s_templates_env_vas(cls, env_vars):
        env_vars_list = list()
        if isinstance(env_vars, list):
            for env_vars_temp in env_vars:
                for env_vars_class, env_vars_info in env_vars_temp.items():
                    if isinstance(env_vars_info, list):
                        env_vars_temp.update(
                            {
                                "stapler-class": env_vars_class,
                                "$class": env_vars_class,
                            }
                        )
                        env_vars_list.append(env_vars_temp)
                    else:
                        env_vars_info.update(
                            {
                                "stapler-class": env_vars_class,
                                "$class": env_vars_class,
                            }
                        )
                        env_vars_list.append(env_vars_info)
        else:
            for env_vars_class, env_vars_info in env_vars.items():
                if isinstance(env_vars_info, list):
                    for env_vars_temp in env_vars_info:
                        env_vars_temp.update(
                            {
                                "stapler-class": env_vars_class,
                                "$class": env_vars_class,
                            }
                        )
                        env_vars_list.append(env_vars_temp)
                else:
                    env_vars_info.update(
                        {
                            "stapler-class": env_vars_class,
                            "$class": env_vars_class,
                        }
                    )
                    env_vars_list.append(env_vars_info)
        return cls._parse_return(env_vars_list)

    @classmethod
    def _gen_k8s_templates_parse(cls, templates_temp):
        templates_list = list()
        for templates_class, templates_dict in templates_temp.items():
            temp_dict = copy.deepcopy(templates_dict)
            instance_cap = temp_dict["instanceCap"]
            slave_conn_timeout = temp_dict["slaveConnectTimeout"]
            volumes = temp_dict["volumes"]
            containers = temp_dict["containers"]
            image_pull_secrets = temp_dict["imagePullSecrets"]
            env_vars = temp_dict["envVars"]
            yaml_merge_strategy = temp_dict["yamlMergeStrategy"]["@class"]

            del temp_dict["instanceCap"]
            del temp_dict["slaveConnectTimeout"]
            del temp_dict["volumes"]
            del temp_dict["containers"]
            del temp_dict["imagePullSecrets"]
            del temp_dict["yamlMergeStrategy"]
            del temp_dict["envVars"]
            temp_dict["instanceCapStr"] = instance_cap
            temp_dict["slaveConnectTimeoutStr"] = slave_conn_timeout
            temp_dict["slaveConnectTimeoutStr"] = slave_conn_timeout
            temp_dict["yamlMergeStrategy"] = {
                "stapler-class": yaml_merge_strategy,
                "$class": yaml_merge_strategy,
            }
            temp_dict["inheritFrom"] = temp_dict["inheritFrom"] if "inheritFrom" in temp_dict.keys() else ""
            temp_dict["nodeUsageMode"] = temp_dict[
                "nodeUsageMode"] if "nodeUsageMode" in temp_dict.keys() else "EXCLUSIVE"
            if env_vars:
                env_vars_temp = cls._gen_k8s_templates_env_vas(env_vars)
                temp_dict["envVars"] = env_vars_temp
            if volumes:
                volumes_temp = cls._gen_k8s_templates_volume(volumes)
                temp_dict["volumes"] = volumes_temp
            if containers:
                temp_dict["containers"] = cls._gen_k8s_templates_containers(containers)
            if image_pull_secrets:
                temp_dict["imagePullSecrets"] = cls._gen_k8s_templates_images_pull_secrets(image_pull_secrets)
            temp_dict["stapler-class"] = templates_class
            temp_dict["$class"] = templates_class
            templates_list.append(temp_dict)
        return cls._parse_return(templates_list)

    @classmethod
    def gen_k8s_templates_config(cls, templates):
        templates_list = list()
        if isinstance(templates, list):
            for templates_temp in templates:
                templates_info = cls._gen_k8s_templates_parse(templates_temp)
                templates_list.append(templates_info)
        else:
            templates_list = cls._gen_k8s_templates_parse(templates)
        return cls._parse_return(templates_list)

    @staticmethod
    def parse_k8s_config(clouds_dict):
        body_data = copy.deepcopy(clouds_dict)
        pod_retention_class = copy.deepcopy(body_data["podRetention"]["@class"])
        container_cap = copy.deepcopy(body_data["containerCap"])
        max_req_per_host = copy.deepcopy(body_data["maxRequestsPerHost"])
        pod_labels = copy.deepcopy(body_data["podLabels"])
        templates = copy.deepcopy(body_data["templates"])
        del body_data["@plugin"]
        del body_data["podRetention"]
        del body_data["containerCap"]
        del body_data["maxRequestsPerHost"]
        del body_data["podLabels"]
        del body_data["templates"]
        body_data["podRetention"] = {
            "$class": pod_retention_class,
            "stapler-class": pod_retention_class,
        }
        body_data["$class"] = "org.csanchez.jenkins.plugins.kubernetes.KubernetesCloud"
        body_data["stapler-class"] = "org.csanchez.jenkins.plugins.kubernetes.KubernetesCloud"
        body_data["jnlpregistry"] = body_data["jnlpregistry"] if "jnlpregistry" in body_data else ""
        body_data["credentialsId"] = body_data["credentialsId"] if "credentialsId" in body_data else ""
        body_data["jenkinsTunnel"] = body_data["jenkinsTunnel"] if "jenkinsTunnel" in body_data else ""
        body_data["includeUser"] = body_data["includeUser"] if "includeUser" in body_data else ""
        body_data["containerCapStr"] = container_cap
        body_data["maxRequestsPerHostStr"] = max_req_per_host
        body_data[""] = "1"
        # pod_label的处理
        body_data["podLabels"] = K8sCloudsTools.gen_k8s_pod_config(pod_labels)
        # templates的处理
        body_data["templates"] = K8sCloudsTools.gen_k8s_templates_config(templates)
        return body_data


class DockerCloudsTools(CloudsBaseTools):
    def __init__(self, *args, **kwargs):
        super(DockerCloudsTools, self).__init__(*args, **kwargs)

    @classmethod
    def gen_docker_api_config(cls, docker_api):
        docker_api_copy = copy.deepcopy(docker_api)
        if "dockerHost" in docker_api_copy:
            if "@plugin" in docker_api['dockerHost']:
                del docker_api_copy["dockerHost"]["@plugin"]
        return docker_api_copy

    @classmethod
    def _gen_docker_templates_connector(cls, connector):
        connector_list = list()
        if isinstance(connector, list):
            for conn_dict_temp in connector:
                conn_class = conn_dict_temp["@class"]
                del conn_dict_temp["@class"]
                conn_dict_temp["stapler-class"] = conn_class
                conn_dict_temp["$class"] = conn_class
                connector_list.append(conn_dict_temp)
        else:
            conn_class = connector["@class"]
            del connector["@class"]
            connector["stapler-class"] = conn_class
            connector["$class"] = conn_class
            connector_list.append(connector)
        return cls._parse_return(connector_list)

    @classmethod
    def _gen_docker_templates_base(cls, docker_template_base):
        if "image" in docker_template_base.keys() and docker_template_base["image"] is None:
            docker_template_base["image"] = ""
        return docker_template_base

    @classmethod
    def gen_docker_templates_config(cls, templates_temp):
        templates_list = list()
        for templates_class, templates_dict in templates_temp.items():
            temp_dict = copy.deepcopy(templates_dict)
            instance_cap = temp_dict["instanceCap"]
            connector = temp_dict["connector"]
            docker_template_base = temp_dict["dockerTemplateBase"]
            del temp_dict["configVersion"]
            del temp_dict["instanceCap"]
            del temp_dict["connector"]
            # del temp_dict["dockerTemplateBase"]
            temp_dict["instanceCapStr"] = instance_cap
            if connector:
                temp_dict["connector"] = cls._gen_docker_templates_connector(connector)
            if docker_template_base:
                temp_dict["dockerTemplateBase"] = cls._gen_docker_templates_base(docker_template_base)
            templates_list.append(temp_dict)
        return cls._parse_return(templates_list)

    @staticmethod
    def parse_docker_config(clouds_dict):
        body_data = copy.deepcopy(clouds_dict)
        if "templates" in body_data:
            templates = copy.deepcopy(body_data["templates"])
        else:
            templates = None
        docker_api = copy.deepcopy(body_data["dockerApi"])
        del body_data["@plugin"]
        body_data["$class"] = "com.nirima.jenkins.plugins.docker.DockerCloud"
        body_data["stapler-class"] = "com.nirima.jenkins.plugins.docker.DockerCloud"
        if docker_api:
            body_data["dockerApi"] = DockerCloudsTools.gen_docker_api_config(docker_api)
        if templates:
            body_data["templates"] = DockerCloudsTools.gen_docker_templates_config(templates)
        return body_data


class HuaWeiVpcTools(CloudsBaseTools):
    def __init__(self, *args, **kwargs):
        super(HuaWeiVpcTools, self).__init__(*args, **kwargs)

    @classmethod
    def gen_hw_vpc_templates_config(cls, templates_temp):
        templates_list = list()
        for templates_class, templates_dict in templates_temp.items():
            temp_dict = copy.deepcopy(templates_dict)
            instance_cap = temp_dict["instanceCap"]
            img_type = temp_dict.get("imgType")
            del temp_dict["instanceCap"]
            del temp_dict["imgType"]
            temp_dict["instanceCapStr"] = instance_cap
            if img_type:
                temp_dict["imgID"] = img_type["imageId"]
            templates_list.append(temp_dict)
        return cls._parse_return(templates_list)

    @staticmethod
    def parse_vpc_config(clouds_dict):
        body_data = copy.deepcopy(clouds_dict)
        name = copy.deepcopy(clouds_dict["name"])
        instance_cap = copy.deepcopy(clouds_dict["instanceCap"])
        if "templates" in body_data:
            templates = copy.deepcopy(body_data["templates"])
        else:
            templates = None
        del body_data["@plugin"]
        del clouds_dict["name"]
        del clouds_dict["instanceCap"]
        body_data["cloudName"] = name
        body_data["instanceCapStr"] = instance_cap
        body_data["$class"] = "io.jenkins.plugins.huaweicloud.HuaweiVPC"
        body_data["stapler-class"] = "io.jenkins.plugins.huaweicloud.HuaweiVPC"
        if templates:
            body_data["templates"] = HuaWeiVpcTools.gen_hw_vpc_templates_config(templates)
        return body_data


# noinspection PyTypeChecker
class JenkinsStepTools(object):
    def __init__(self, *args, **kwargs):
        super(JenkinsStepTools, self).__init__(*args, **kwargs)

    @func_retry()
    def create_plugins(self, jenkins_instance, jenkins_api_instance, infra_jenkins_path, domain):
        exist_plugins = jenkins_instance.get_plugins_info()
        exist_plugins_short_name = [plugins["shortName"] for plugins in exist_plugins]

        domain_path = os.path.join(infra_jenkins_path, domain)
        if domain in GlobalConfig.install_off_pkg_domain:
            full_path = os.path.join(infra_jenkins_path, GlobalConfig.install_off_pkg_dir_name, domain)
            if os.path.exists(full_path):
                for file_name in os.listdir(full_path):
                    if file_name.split(".hpi")[0] not in exist_plugins_short_name:
                        jenkins_api_instance.install_off_line_plugins(os.path.join(full_path, file_name))
        plugins_path = os.path.join(domain_path, GlobalConfig.plugin_dir_name, GlobalConfig.plugin_name)
        plugins_infos = JenkinsTools.load_txt(plugins_path)
        plugins_infos_dict = dict()
        for plugin in plugins_infos:
            if plugin['shortName'] in exist_plugins_short_name:
                continue
            temp = {'shortName': plugin['shortName'], 'version': str(plugin['version'])}
            plugins_infos_dict[plugin['shortName']] = temp
        if plugins_infos_dict:
            failed_list = jenkins_api_instance.install_plugins(plugins_infos_dict.values(), force_restart=True)
        else:
            failed_list = list()
        if failed_list:
            print("First to failed to create plugins：:{}".format(",".join(failed_list)))
            failed_plugins_list = list()
            for plugin in failed_list:
                temp = {'shortName': plugin, 'version': "latest"}
                failed_plugins_list.append(temp)
            if failed_plugins_list:
                failed_again_list = jenkins_api_instance.install_plugins(failed_plugins_list, force_restart=True)
                if failed_again_list:
                    raise Exception("Seconds to failed to create plugins:{}".format(",".join(failed_again_list)))

    @func_retry(tries=2)
    def check_plugins(self, jenkins_instance, domain_path):
        exist_plugins = jenkins_instance.get_plugins_info()
        exist_plugins_short_name = [plugins["shortName"] for plugins in exist_plugins]
        plugins_path = os.path.join(domain_path, GlobalConfig.plugin_dir_name, GlobalConfig.plugin_name)
        plugins_infos = JenkinsTools.load_txt(plugins_path)
        for plugin in plugins_infos:
            if plugin['shortName'] in exist_plugins_short_name:
                continue
            else:
                raise Exception("Plugins:{} is not installed".format(plugin['shortName']))

    @staticmethod
    def request_obs_data(obs_client, key=GlobalConfig.obs_default_obj):
        content = str()
        resp = obs_client.getObject(GlobalConfig.obs_default_bucket, key, loadStreamInMemory=False)
        if resp.status < 300:
            print('request_obs_data: requestId:', resp.requestId)
            while True:
                chunk = resp.body.response.read(65536)
                if not chunk:
                    break
                content = "{}{}".format(content, chunk.decode("utf-8"))
            resp.body.response.close()
        else:
            raise Exception('key:{},errorCode:{},errorMessage:{}'.format(key, resp.errorCode, resp.errorMessage))
        return content

    @func_retry()
    def create_credentials_step(self, jenkins_api_instance, obs_client, domain, jenkins_tools=None):
        if jenkins_tools is None:
            jenkins_tools = JenkinsTools()
        content = self.request_obs_data(obs_client)
        all_config_dict_data = json.loads(content)
        config_dict_data = all_config_dict_data[domain]
        credentials_templates = CredentialsTools.get_credentials_templates()
        credentials_copy_dict = copy.deepcopy(config_dict_data)
        for cre_id, cre_infor in config_dict_data.items():
            jenkins_class = cre_infor['jenkins_class']
            need_parse_secret = credentials_templates.get(jenkins_class, [])
            for secret in need_parse_secret:
                if cre_infor.get(secret) is not None:
                    credentials_copy_dict[cre_id][secret] = jenkins_tools.decode_secret(
                        config_dict_data[cre_id][secret])
                elif cre_infor.get("keyStoreSource") is not None:
                    credentials_copy_dict[cre_id]["keyStoreSource"][secret] = jenkins_tools.decode_secret(
                        config_dict_data[cre_id]["keyStoreSource"][secret])
                elif cre_infor.get("privateKeySource") is not None:
                    credentials_copy_dict[cre_id]["privateKeySource"][secret] = jenkins_tools.decode_secret(
                        config_dict_data[cre_id]["privateKeySource"][secret])
                elif cre_infor.get("kubeconfigSource") is not None:
                    credentials_copy_dict[cre_id]["kubeconfigSource"][secret] = jenkins_tools.decode_secret(
                        config_dict_data[cre_id]["kubeconfigSource"][secret])
                else:
                    raise Exception("parse_secret need adapter")
        credentials_data = jenkins_api_instance.get_credentials().credentials
        for cre_id, cre_info in credentials_copy_dict.items():
            if cre_id in credentials_data.keys():
                continue
            if cre_info["jenkins_class"] == CredentialsTools.fs_service_account_class:
                continue
            cre = CredentialsTools.get_params(cre_info)
            if not cre:
                continue
            body_data = dict()
            body_data['json'] = str(cre)
            jenkins_tools.create_credentials_tools(jenkins_api_instance, body_data, cre_info)

    @func_retry(tries=2)
    def check_credentials(self, jenkins_api_instance, obs_client, domain):
        credentials_data = jenkins_api_instance.get_credentials().credentials
        content = self.request_obs_data(obs_client)
        all_config_dict_data = json.loads(content)
        config_dict_data = all_config_dict_data[domain]
        un_install_list = [cre_id for cre_id, cre_info in config_dict_data.items() if
                           cre_info["jenkins_class"] == CredentialsTools.fs_service_account_class]
        failed_set = set(config_dict_data.keys()) - set(credentials_data.keys()) - set(un_install_list)
        if failed_set:
            raise Exception("Credentials:{} is not installed".format(failed_set))

    @func_retry()
    def create_node(self, jenkins_instance, domain_path):
        node_path = os.path.join(domain_path, GlobalConfig.node_dir_name)
        all_nodes = jenkins_instance.get_nodes()
        all_node_names = [node['name'] for node in all_nodes]
        for file in os.listdir(node_path):
            file_path = os.path.join(node_path, file)
            node_content = JenkinsTools.load_txt(file_path, is_json_loads=False)
            node_dict_data = xmltodict.parse(node_content)
            if node_dict_data.get("slave") is None:
                continue
            node_name = node_dict_data['slave']['name']
            if node_name in all_node_names:
                print("node_name:{} is existed".format(node_name))
                continue
            node_num_exe = node_dict_data['slave']["numExecutors"]
            node_description = node_dict_data['slave'].get("description", "")
            node_remote_fs = node_dict_data['slave']['remoteFS']
            node_label = node_dict_data['slave']['label']
            node_launcher = dict(node_dict_data['slave']['launcher'])
            launcher_params = copy.deepcopy(node_launcher)
            if "sshHostKeyVerificationStrategy" in launcher_params.keys():
                del launcher_params["sshHostKeyVerificationStrategy"]
            jenkins_instance.create_node(node_name,
                                         numExecutors=node_num_exe,
                                         nodeDescription=node_description,
                                         remoteFS=node_remote_fs,
                                         labels=node_label,
                                         launcher=node_launcher['@class'],
                                         launcher_params=launcher_params)

    @func_retry(tries=2)
    def check_node(self, jenkins_instance, domain_path):
        node_path = os.path.join(domain_path, GlobalConfig.node_dir_name)
        all_nodes = jenkins_instance.get_nodes()
        all_node_names = [node['name'] for node in all_nodes]
        for file in os.listdir(node_path):
            file_path = os.path.join(node_path, file)
            node_content = JenkinsTools.load_txt(file_path, is_json_loads=False)
            node_dict_data = xmltodict.parse(node_content)
            if node_dict_data.get("slave") is None:
                continue
            node_name = node_dict_data['slave']['name']
            if node_name in all_node_names:
                continue
            else:
                raise Exception("Node:{} is not installed".format(node_name))

    # noinspection PyMethodMayBeStatic
    def recursion_create_job(self, jobs_path, file, jobs_list, jenkins_instance):
        file_path = os.path.join(jobs_path, file)
        for file_sub in os.listdir(file_path):
            file_sub_path = os.path.join(file_path, file_sub)
            print("current create job path:{}".format(file_sub_path))
            if os.path.isfile(file_sub_path):
                job_content = JenkinsTools.load_txt(file_sub_path, is_json_loads=False)
                dir_name = file_sub_path.split(GlobalConfig.job_dir_name)[-1][1:]
                job_name = dir_name.rsplit(sep=".", maxsplit=1)[0]
                print("create job:{}".format(job_name))
                JenkinsTools.create_job(jobs_list, job_name, jenkins_instance, job_content)
            else:
                self.recursion_create_job(file_path, file_sub, jobs_list, jenkins_instance)

    @func_retry()
    def create_job(self, jenkins_instance, domain_path, jobs_list):
        jobs_path = os.path.join(domain_path, GlobalConfig.job_dir_name)
        for file in os.listdir(jobs_path):
            if file.endswith(".xml"):
                file_path = os.path.join(jobs_path, file)
                job_content = JenkinsTools.load_txt(file_path, is_json_loads=False)
                job_name = file.rsplit(sep=".", maxsplit=1)[0]
                JenkinsTools.create_job(jobs_list, job_name, jenkins_instance, job_content)
            else:
                self.recursion_create_job(jobs_path, file, jobs_list, jenkins_instance)

    # noinspection PyMethodMayBeStatic
    def recursion_check_job(self, jobs_path, file, jobs_list, jenkins_instance):
        file_path = os.path.join(jobs_path, file)
        for file_sub in os.listdir(file_path):
            file_sub_path = os.path.join(file_path, file_sub)
            print("check job path:{}".format(file_sub_path))
            if os.path.isfile(file_sub_path):
                dir_name = file_sub_path.split(GlobalConfig.job_dir_name)[-1][1:]
                job_name = dir_name.rsplit(sep=".", maxsplit=1)[0]
                if jobs_list and job_name not in jobs_list:
                    continue
                if not jenkins_instance.job_exists(job_name):
                    raise Exception("Job:{} is not installed".format(job_name))
            else:
                self.recursion_check_job(file_path, file_sub, jobs_list, jenkins_instance)

    @func_retry(tries=2)
    def check_job(self, jenkins_instance, domain_path, jobs_list):
        jobs_path = os.path.join(domain_path, GlobalConfig.job_dir_name)
        for file in os.listdir(jobs_path):
            if file.endswith(".xml"):
                job_name = file.rsplit(sep=".", maxsplit=1)[0]
                if jobs_list and job_name not in jobs_list:
                    continue
                if not jenkins_instance.job_exists(job_name):
                    raise Exception("Job:{} is not installed".format(job_name))
            else:
                self.recursion_check_job(jobs_path, file, jobs_list, jenkins_instance)

    @func_retry()
    def create_folder(self, jenkins_instance, domain_path):
        folder_path = os.path.join(domain_path, GlobalConfig.job_dir_name)
        for path, dir_list, file_list in os.walk(folder_path):
            for dir_name in dir_list:
                full_path = os.path.join(path, dir_name)
                folder = full_path.split(GlobalConfig.job_dir_name)[-1][1:]
                jenkins_instance.create_folder(folder, ignore_failures=True)

    @func_retry(tries=2)
    def check_folder(self, jenkins_instance, domain_path):
        folder_path = os.path.join(domain_path, GlobalConfig.job_dir_name)
        for path, dir_list, file_list in os.walk(folder_path):
            for dir_name in dir_list:
                full_path = os.path.join(path, dir_name)
                folder = full_path.split(GlobalConfig.job_dir_name)[-1][1:]
                if not jenkins_instance.is_folder(folder):
                    raise Exception("Folder:{} is not installed".format(folder))

    @func_retry()
    def create_view(self, jenkins_instance, domain_path):
        view_path = os.path.join(domain_path, GlobalConfig.view_dir_name)
        for path, dir_list, file_list in os.walk(view_path):
            for file in file_list:
                file_path = os.path.join(path, file)
                view_name = file.split(".")[0]
                view_content = JenkinsTools.load_txt(file_path, is_json_loads=False)
                if not jenkins_instance.view_exists(view_name):
                    jenkins_instance.create_view(view_name, view_content)

    @func_retry(tries=2)
    def check_view(self, jenkins_instance, domain_path):
        view_path = os.path.join(domain_path, GlobalConfig.view_dir_name)
        for path, dir_list, file_list in os.walk(view_path):
            for file in file_list:
                view_name = file.split(".")[0]
                if not jenkins_instance.view_exists(view_name):
                    raise Exception("View:{} is not installed".format(view_name))

    @func_retry()
    def create_user(self, jenkins_api_instance, domain_path, jenkins_tools=None):
        if jenkins_tools is None:
            jenkins_tools = JenkinsTools()
        user_path = os.path.join(domain_path, GlobalConfig.cre_dir_name, GlobalConfig.user_name)
        users_infos = jenkins_tools.load_yaml(user_path)
        password = jenkins_tools.base64_decode(GlobalConfig.default_secret)
        exist_user_list = jenkins_api_instance.get_user_lists()
        for name, user_info in users_infos.items():
            if name in exist_user_list:
                print("user:{} is exist".format(name))
            else:
                ret = jenkins_api_instance.create_user(name, password, user_info["full_name"], user_info["email"])
                print("user:{} create info:{} {} result:{}".format(name, user_info["full_name"], user_info["email"],
                                                                   str(ret)))

    @func_retry(tries=2)
    def check_user(self, jenkins_api_instance, domain_path, jenkins_tools=None):
        if jenkins_tools is None:
            jenkins_tools = JenkinsTools()
        user_path = os.path.join(domain_path, GlobalConfig.cre_dir_name, GlobalConfig.user_name)
        users_infos = jenkins_tools.load_yaml(user_path)
        exist_user_list = jenkins_api_instance.get_user_lists()
        not_create_user = set(users_infos.keys()) - set(exist_user_list)
        if not_create_user:
            print("User:{} is not installed".format(not_create_user))

    @func_retry()
    def create_cloud_config(self, jenkins_api_instance, obs_client, domain):
        cloud_config_content = self.request_obs_data(obs_client, key=GlobalConfig.obs_default_config)
        cloud_config_dict = json.loads(cloud_config_content)
        cloud_config_obj = xmltodict.parse(cloud_config_dict[domain])
        clouds_order_dict = cloud_config_obj["hudson"]["clouds"]
        clouds_dict = json.loads(json.dumps(clouds_order_dict))
        body_data = list()
        if not isinstance(clouds_dict, dict):
            print("Cloud config is empty...")
            return
        for clouds_class, clouds_info in clouds_dict.items():
            if clouds_class == "org.csanchez.jenkins.plugins.kubernetes.KubernetesCloud":
                if isinstance(clouds_info, list):
                    for clouds_temp in clouds_info:
                        print("start to parse k8s clouds:{}".format(clouds_temp["name"]))
                        body_data.append(K8sCloudsTools.parse_k8s_config(clouds_temp))
                else:
                    print("start to parse k8s clouds:{}".format(clouds_info["name"]))
                    body_data.append(K8sCloudsTools.parse_k8s_config(clouds_info))
            elif clouds_class == "com.nirima.jenkins.plugins.docker.DockerCloud":
                if isinstance(clouds_info, list):
                    for clouds_temp in clouds_info:
                        print("start to parse docker clouds:{}".format(clouds_temp["name"]))
                        clouds_result = DockerCloudsTools.parse_docker_config(clouds_temp)
                        body_data.append(clouds_result)
                else:
                    print("start to parse docker clouds:{}".format(clouds_info["name"]))
                    clouds_result = DockerCloudsTools.parse_docker_config(clouds_info)
                    body_data.append(clouds_result)
            elif clouds_class == "io.jenkins.plugins.huaweicloud.HuaweiVPC":
                if isinstance(clouds_info, list):
                    for clouds_temp in clouds_info:
                        print("start to parse huawei vpc clouds:{}".format(clouds_temp["name"]))
                        body_data.append(HuaWeiVpcTools.parse_vpc_config(clouds_temp))
                else:
                    print("start to parse huawei vpc clouds:{}".format(clouds_info["name"]))
                    body_data.append(HuaWeiVpcTools.parse_vpc_config(clouds_info))
        body_cloud_data = {"cloud": body_data, "core:apply": ""}
        data = "json={}".format(json.dumps(body_cloud_data))
        ret = jenkins_api_instance.create_clouds_config(data)
        print("create clouds config:{}".format(ret))

    @func_retry(tries=2)
    def check_cloud_config(self, jenkins_api_instance, obs_client, domain):
        cloud_config_content = self.request_obs_data(obs_client, key=GlobalConfig.obs_default_config)
        cloud_config_dict = json.loads(cloud_config_content)
        cloud_config_obj = xmltodict.parse(cloud_config_dict[domain])
        clouds_order_dict = cloud_config_obj["hudson"]["clouds"]
        clouds_dict = json.loads(json.dumps(clouds_order_dict))
        if not isinstance(clouds_dict, dict):
            print("Cloud config is empty...")
            return
        clouds_name_list = list()
        for clouds_class, clouds_info in clouds_dict.items():
            if isinstance(clouds_info, list):
                for clouds_temp in clouds_info:
                    clouds_name_list.append(clouds_temp["name"])
            else:
                clouds_name_list.append(clouds_info["name"])
        cur_config_xml = jenkins_api_instance.get_config_xml()
        cur_cloud_config_obj = xmltodict.parse(cur_config_xml)
        cur_clouds_order_dict = cur_cloud_config_obj["hudson"]["clouds"]
        cur_clouds_dict = json.loads(json.dumps(cur_clouds_order_dict))
        exists_clouds_name_list = list()
        if isinstance(cur_clouds_dict, dict):
            print("Check cloud config is empty...")
            for clouds_class, clouds_info in cur_clouds_dict.items():
                if isinstance(clouds_info, list):
                    for clouds_temp in clouds_info:
                        JenkinsTools.parse_hw_vpc(exists_clouds_name_list, clouds_class, clouds_temp)
                else:
                    JenkinsTools.parse_hw_vpc(exists_clouds_name_list, clouds_class, clouds_info)
        not_create_clouds = set(clouds_name_list) - set(exists_clouds_name_list)
        if not_create_clouds:
            raise Exception("Clouds:{} is not installed".format(not_create_clouds))


def main():
    """
    处理逻辑：
        1.github上拉取项目infra-jenkins.  这里需要用户名和密码 或者token
        2.获取jenkins的用户名和密码
        3.开始处理还原处理：
            1.安装插件
            2.安装凭证
            3.安装节点
            4.安装folder
            5.安装view
            6.安装job
    """
    config_path = JenkinsTools.parse_input_args()
    config_dict = JenkinsTools.load_yaml(config_path)
    JenkinsTools.check_params(config_dict)
    print("**************1.jenkins recover tools analytic parameter**************")
    repo_name = GlobalConfig.git_clone_cmd.split(r"/")[-1].split(r".")[0]
    print("**************2.jenkins recover tools recover*****************************")
    jenkins_tools = JenkinsTools()
    jenkins_step_tools = JenkinsStepTools()
    infra_jenkins_path = os.path.join(GlobalConfig.current_path, repo_name)
    jenkins_tools.rmd_dir(infra_jenkins_path)
    result = jenkins_tools.execute_cmd(GlobalConfig.git_clone_cmd.format(GlobalConfig.current_path))
    if "error" in result or "fatal" in result:
        raise Exception("git clone {} failed:{}.".format(repo_name, result))
    website_domains_lists = list()
    infra_jenkins_sub_dir = os.listdir(infra_jenkins_path)
    if config_dict["bak_jenkins_domain"] in infra_jenkins_sub_dir:
        website_domains_lists.append(config_dict['bak_jenkins_domain'])
    else:
        raise Exception("Failed: bak_jenkins_domain not in the sub dir of infra_jenkins.")
    jenkins_instance = jenkins.Jenkins(config_dict["jenkins_url"], config_dict["jenkins_username"],
                                       config_dict["jenkins_password"], timeout=180)
    jenkins_api_instance = JenkinsLib(config_dict["jenkins_url"], config_dict["jenkins_username"],
                                      config_dict["jenkins_password"], useCrumb=True, timeout=180)
    obs_client = ObsClient(access_key_id=config_dict["huaweiclound_obs_ak"],
                           secret_access_key=config_dict["huaweiclound_obs_sk"],
                           server=config_dict["huaweiclound_obs_url"])
    for domain in website_domains_lists:
        domain_path = os.path.join(infra_jenkins_path, domain)
        # 1.安装插件
        print("###############1.start to install plugins:{}####################".format(domain))
        jenkins_step_tools.create_plugins(jenkins_instance, jenkins_api_instance, infra_jenkins_path, domain)
        jenkins_instance, jenkins_api_instance = jenkins_tools.check_service_normal(config_dict)
        # 2.安装凭证
        print("###############2.start to create credentials:{}####################".format(domain))
        jenkins_step_tools.create_credentials_step(jenkins_api_instance, obs_client, domain)
        # 3.安装node
        print("###############3.start to create node:{}####################".format(domain))
        jenkins_step_tools.create_node(jenkins_instance, domain_path)
        # 4.创建folder
        print("###############4.start to create folder:{}####################".format(domain))
        jenkins_step_tools.create_folder(jenkins_instance, domain_path)
        # 5.创建jobs
        print("###############5.start to create jobs:{}####################".format(domain))
        jenkins_step_tools.create_job(jenkins_instance, domain_path, config_dict["jobs_list"])
        # 6.创建view
        print("###############6.start to create view:{}####################".format(domain))
        jenkins_step_tools.create_view(jenkins_instance, domain_path)
        # 7.创建user
        print("###############7.start to create user:{}####################".format(domain))
        jenkins_step_tools.create_user(jenkins_api_instance, domain_path)
        # 8.创建clouds
        print("###############8.start to create clouds config:{}####################".format(domain))
        jenkins_step_tools.create_cloud_config(jenkins_api_instance, obs_client, domain)
        # 10.检查插件
        print("###############10.start to check plugins:{}####################".format(domain))
        jenkins_step_tools.check_plugins(jenkins_instance, domain_path)
        # 11.检查凭证
        print("###############11.start to check credentials:{}####################".format(domain))
        jenkins_step_tools.check_credentials(jenkins_api_instance, obs_client, domain)
        # 12.检查node
        print("###############12.start to check node:{}####################".format(domain))
        jenkins_step_tools.check_node(jenkins_instance, domain_path)
        # 13.检查folder
        print("###############13.start to check folder:{}####################".format(domain))
        jenkins_step_tools.check_folder(jenkins_instance, domain_path)
        # 14.检查jobs
        print("###############14.start to check jobs:{}####################".format(domain))
        jenkins_step_tools.check_job(jenkins_instance, domain_path, config_dict["jobs_list"])
        # 15.检查view
        print("###############15.start to check view:{}####################".format(domain))
        jenkins_step_tools.check_view(jenkins_instance, domain_path)
        # 16.检查user
        print("###############16.start to check user:{}####################".format(domain))
        jenkins_step_tools.check_user(jenkins_api_instance, domain_path)
        # 17.检查clouds
        print("###############17.start to check clouds config:{}####################".format(domain))
        jenkins_step_tools.check_cloud_config(jenkins_api_instance, obs_client, domain)
        # 18.开始清理环境
        print("###############18.start to clean env#######################".format(domain))
        jenkins_tools.rmd_dir(infra_jenkins_path)
    print("************************finish*************************")


if __name__ == '__main__':
    main()
