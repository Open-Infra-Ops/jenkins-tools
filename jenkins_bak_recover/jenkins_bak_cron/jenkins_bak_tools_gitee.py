# -*- coding: utf-8 -*-
# @Time    : 2022/5/31 10:35
# @Author  : Tom_zc
# @FileName: jenkins_bak_tools.py
# @Software: PyCharm

import jenkins
import json
import os
import time
import base64
import yaml
import subprocess
import shutil
import traceback
import xmltodict
import copy
from collections import defaultdict
from functools import wraps
from obs import ObsClient
from jenkinsapi import jenkins as jenkins_api
from jenkinsapi.credentials import Credentials2x, Credentials
from jenkinsapi.custom_exceptions import JenkinsAPIException
from tempfile import TemporaryDirectory
from lxml import etree


class GlobalConfig(object):
    """Global Config"""
    job_dir_name = "jobs-config"
    view_dir_name = "view-config"
    node_dir_name = "node-config"
    cre_dir_name = "credentials-config"
    folder_dir_name = "folder-config"
    plugin_dir_name = "plugin-config"

    plugin_name = "plugins.yaml"

    user_name = "user.yaml"
    config_security_name = "config_security.html"
    config_tools_name = "config_tools.html"
    config_system_name = "config_system.html"

    config_clouds_name = "config.xml"

    obs_default_bucket = "obs-for-openeuler-developer"
    obs_default_obj = "jenkins-secret"
    obs_default_config = "jenkins-config"
    git_clone_cmd = "cd {} && git clone https://{}:{}@gitee.com/opensourceway/{}.git"
    git_commit_push_cmd = "cd {} && " \
                          "git add . && " \
                          "git commit -am {} && " \
                          "git push -u origin main"


def func_retry(tries=3, delay=1):
    """The wrapper of retry"""

    def deco_retry(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            for i in range(tries):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    print("There happen:{},traceback:{}".format(e, traceback.print_exc()))
                    time.sleep(delay)
            else:
                raise Exception("func_retry: {} failed".format(fn.__name__))

        return inner

    return deco_retry


# noinspection DuplicatedCode
class JenkinsLib(jenkins_api.Jenkins):
    def get_credentials(self, cred_class=Credentials2x):
        """Get all credentials"""
        if 'credentials' not in self.plugins:
            raise JenkinsAPIException('Credentials plugin not installed')

        elif self.plugins['credentials'].version[0:4] == "1087":
            url = '%s/credentials/store/system/domain/_/' % self.baseurl
            return cred_class(url, self)

        elif int(self.plugins['credentials'].version[0:1]) == 1:
            url = '%s/credential-store/domain/_/' % self.baseurl
            return Credentials(url, self)
        else:
            url = '%s/credentials/store/system/domain/_/' % self.baseurl
            return cred_class(url, self)

    def get_secret_by_credential_id(self, credential_id):
        """Get a single credentials by credentials id"""
        if 'credentials' not in self.plugins:
            raise JenkinsAPIException('Credentials plugin not installed')
        elif self.plugins['credentials'].version[0:4] == "1087":
            url = '%s/credentials/store/system/domain/_/credential/%s/update' % (self.baseurl, credential_id)
        elif int(self.plugins['credentials'].version[0:1]) == 1:
            url = '%s/credential-store/domain/_/credential/%s/update' % (self.baseurl, credential_id)
        else:
            url = '%s/credentials/store/system/domain/_/credential/%s/update' % (self.baseurl, credential_id)
        valid = self.requester.VALID_STATUS_CODES
        resp = self.requester.post_and_confirm_status(url, data='', valid=valid)
        return resp

    def get_secret_by_xml(self):
        """Get a credentials xml by credentials groovy script"""
        credentials_script = """println "cat /var/jenkins_home/credentials.xml".execute().text """
        return self.run_groovy_script(credentials_script)

    def get_user_info(self, username):
        """Get user info by username"""
        url = "%s/user/%s/configure" % (self.baseurl, username)
        resp = self.requester.get_url(url)
        return resp.content.decode("utf-8")

    def get_all_user(self):
        """Get all user"""
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

    def get_user_dict(self):
        """Get all user info: full_name and email"""
        act_users_list = self.get_all_user()
        ret_dict = defaultdict(dict)
        for username in act_users_list:
            userinfo = self.get_user_info(username)
            html = etree.HTML(userinfo)
            full_name = html.xpath("//input[@name='_.fullName']/@value")[0]
            email = html.xpath("//input[@name='email.address']/@value")[0]
            ret_dict[username] = {
                "full_name": str(full_name),
                "email": str(email),
            }
        return ret_dict

    def get_configure_security(self):
        """Get configure global security"""
        url = '%s/configureSecurity' % (self.baseurl,)
        valid = self.requester.VALID_STATUS_CODES
        resp = self.requester.post_and_confirm_status(url, data='', valid=valid)
        return resp.content.decode("utf-8")

    def get_configure(self):
        """Get configure system"""
        url = '%s/configure' % (self.baseurl,)
        valid = self.requester.VALID_STATUS_CODES
        resp = self.requester.post_and_confirm_status(url, data='', valid=valid)
        return resp.content.decode("utf-8")

    def get_configure_tools(self):
        """Get global tool configure"""
        url = '%s/configureTools' % (self.baseurl,)
        valid = self.requester.VALID_STATUS_CODES
        resp = self.requester.post_and_confirm_status(url, data='', valid=valid)
        return resp.content.decode("utf-8")

    def get_config_xml(self):
        """Get config.xml by groovy script"""
        config_script = """println "cat /var/jenkins_home/config.xml".execute().text """
        return self.run_groovy_script(config_script)

    def get_decode_secret(self, secret_str):
        """Decode secret"""
        script = """println hudson.util.Secret.decrypt("%s")""" % (secret_str,)
        return self.run_groovy_script(script)

    def get_decode_secret_bytes(self, secret_bytes):
        """Decode secret bytes"""
        script = """println(new String(com.cloudbees.plugins.credentials.SecretBytes.fromString("%s").getPlainData(), "ASCII"))""" % (
            secret_bytes)
        return self.run_groovy_script(script)


class CredentialsTools(object):
    """Credentials Tools"""
    password_class = "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl"
    secret_class = "org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl"
    ssh_class = "com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey"
    gitlab_token_class = "com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl"
    gitee_token_class = "com.gitee.jenkins.connection.GiteeApiTokenImpl"
    github_token_class = "org.jenkinsci.plugins.github__branch__source.GitHubAppCredentials"
    openshift_class = "org.jenkinsci.plugins.kubernetes.credentials.OpenShiftBearerTokenCredentialImpl"
    x509_class = "org.jenkinsci.plugins.docker.commons.credentials.DockerServerCredentials"
    file_class = "org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl"
    certificateCredentials_class = "com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl"
    token_class = "com.elasticbox.jenkins.k8s.plugin.auth.TokenCredentialsImpl"
    kubeconfig_class = "com.microsoft.jenkins.kubernetes.credentials.KubeconfigCredentials"
    ak_sk_class = "io.jenkins.plugins.huaweicloud.credentials.HWCAccessKeyCredentials"

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


class JenkinsTools(object):

    @classmethod
    def check_params(cls, data):
        """Check input params"""
        if not isinstance(data, dict):
            raise Exception("The yaml config must be dict")
        if data.get("git_token") is None:
            raise Exception("The git_token of yaml is invalid")
        if data.get("huaweiclound_obs_url") is None:
            raise Exception("The huaweiclound_obs_url of yaml is invalid")
        if data.get("huaweiclound_obs_ak") is None:
            raise Exception("The huaweiclound_obs_ak of yaml is invalid")
        if data.get("huaweiclound_obs_sk") is None:
            raise Exception("The huaweiclound_obs_sk of yaml is invalid")
        if not isinstance(data.get("jenkins_info"), list):
            raise Exception("The jenkins_info of yaml is invalid")
        for jenkins_dict in data["jenkins_info"]:
            if jenkins_dict.get("url") is None:
                raise Exception("The domain of jenkins_info is invalid")
            if jenkins_dict.get("username") is None:
                raise Exception("The username of jenkins_info is invalid")
            if jenkins_dict.get("password") is None:
                raise Exception("The password of jenkins_info is invalid")

    @classmethod
    def load_yaml(cls, file_path, method="load"):
        """Load yaml config"""
        yaml_load_method = getattr(yaml, method)
        with open(file_path, "r", encoding="utf-8") as file:
            content = yaml_load_method(file, Loader=yaml.FullLoader)
        return content

    @staticmethod
    def create_dir(dir_path):
        """Create dir"""
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

    @staticmethod
    def rmd_dir(dir_path):
        """Remove dir"""
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)

    @staticmethod
    def dump_xml(full_path, content):
        """Dump xml"""
        dir_path = os.path.dirname(full_path)
        JenkinsTools.create_dir(dir_path)
        with open(full_path, "w", encoding="utf-8") as f1:
            f1.write(content)

    @staticmethod
    def dump_yaml(file_path, write_data):
        """Dump yaml: write_data must be list or dict"""
        dir_path = os.path.dirname(file_path)
        JenkinsTools.create_dir(dir_path)
        if not isinstance(write_data, (dict, list)):
            raise Exception("input params:{} fault.".format(write_data))
        with open(file_path, "w") as f:
            yaml.dump(write_data, f)

    @staticmethod
    def base64_decode(token):
        """Base64 decode"""
        content = base64.b64decode(token)
        return json.loads(content)

    @staticmethod
    def base64_encode(data):
        """Base64 encode"""
        if not isinstance(data, bytes):
            data = bytes(data, encoding="utf8")
        return base64.b64encode(data)

    @staticmethod
    def execute_cmd(cmd):
        """Execute cmd3"""
        return subprocess.getoutput(cmd)

    @classmethod
    def get_credentials_info(cls, jenkins_api_instance):
        """Get credentials info"""
        credentials_xml = jenkins_api_instance.get_secret_by_xml()
        credentials_dict = xmltodict.parse(credentials_xml)
        credentials_list = \
            credentials_dict['com.cloudbees.plugins.credentials.SystemCredentialsProvider']['domainCredentialsMap'][
                'entry']['java.util.concurrent.CopyOnWriteArrayList']
        class_info = dict()
        for info in credentials_list:
            info_list = credentials_list[info]
            if isinstance(info_list, list):
                for temp in info_list:
                    copy_temp = copy.deepcopy(json.loads(json.dumps(temp)))
                    copy_temp.update({"jenkins_class": info})
                    if temp.get("projectId"):
                        class_info[temp["projectId"]] = copy_temp
                    else:
                        class_info[temp["id"]] = copy_temp
            else:
                copy_temp = copy.deepcopy(json.loads(json.dumps(info_list)))
                copy_temp.update({"jenkins_class": info})
                if info_list.get("projectId"):
                    class_info[info_list["projectId"]] = copy_temp
                else:
                    class_info[info_list["id"]] = copy_temp
        return class_info

    @classmethod
    def credentials_supplement(cls, credentials_dict, credentials_conf_dict):
        """Get credentials supplement"""
        for cre_id, cre_info in credentials_dict.items():
            for key, value in cre_info.items():
                if key not in credentials_conf_dict[cre_id].keys():
                    credentials_conf_dict[cre_id][key] = value

    @classmethod
    def get_secret(cls, jenkins_api_instance, secret, value):
        if secret in ["secretBytes", "uploadedKeystoreBytes"]:
            b = jenkins_api_instance.get_decode_secret_bytes(value)
        else:
            b = jenkins_api_instance.get_decode_secret(value)
        return b

    @classmethod
    def parse_secret(cls, jenkins_api_instance, credentials_dict, domain):
        """Parse the Credentials"""
        secret_dict = defaultdict(dict)
        credentials_templates = CredentialsTools.get_credentials_templates()
        credentials_copy_dict = copy.deepcopy(credentials_dict)
        for cre_id, cre_infor in credentials_dict.items():
            jenkins_class = cre_infor['jenkins_class']
            need_parse_secret = credentials_templates.get(jenkins_class, [])
            for secret in need_parse_secret:
                if cre_infor.get(secret) is not None:
                    b = cls.get_secret(jenkins_api_instance, secret, cre_infor[secret])
                    credentials_copy_dict[cre_id][secret] = cls.base64_encode(b).decode("utf-8")
                elif cre_infor.get("keyStoreSource") is not None:
                    b = cls.get_secret(jenkins_api_instance, secret, cre_infor["keyStoreSource"][secret])
                    credentials_copy_dict[cre_id]["keyStoreSource"][secret] = cls.base64_encode(b).decode("utf-8")
                elif cre_infor.get("privateKeySource") is not None:
                    b = cls.get_secret(jenkins_api_instance, secret, cre_infor["privateKeySource"][secret])
                    credentials_copy_dict[cre_id]["privateKeySource"][secret] = cls.base64_encode(b).decode("utf-8")
                elif cre_infor.get("kubeconfigSource") is not None:
                    b = cls.get_secret(jenkins_api_instance, secret, cre_infor["kubeconfigSource"][secret])
                    credentials_copy_dict[cre_id]["kubeconfigSource"][secret] = cls.base64_encode(b).decode("utf-8")
                else:
                    raise Exception("parse_secret need adapter")
        secret_dict[domain] = credentials_copy_dict
        return secret_dict

    @func_retry()
    def upload_obs_data(self, obs_client, upload_data, upload_key=GlobalConfig.obs_default_obj):
        """Upload obs data"""
        if not isinstance(upload_data, dict):
            raise Exception("upload_data must be dict")
        content = str()
        resp = obs_client.getObject(GlobalConfig.obs_default_bucket, upload_key, loadStreamInMemory=False)
        if resp.status < 300:
            while True:
                chunk = resp.body.response.read(65536)
                if not chunk:
                    break
                content = "{}{}".format(content, chunk.decode("utf-8"))
            resp.body.response.close()
        elif resp.errorCode == "NoSuchKey":
            print("Key:{} is not exist, need to create".format(upload_key))
        else:
            print('errorCode:', resp.errorCode)
            print('errorMessage:', resp.errorMessage)
            raise Exception("get object failed：{}....".format(upload_key))
        if content:
            read_dict_data = json.loads(content)
        else:
            read_dict_data = dict()
        for domain, domain_info in upload_data.items():
            read_dict_data[domain] = domain_info
        new_content = json.dumps(read_dict_data)
        response = obs_client.putContent(GlobalConfig.obs_default_bucket, upload_key, new_content)
        if response.status != 200:
            raise Exception("upload credentials failed!")


# noinspection DuplicatedCode
def bak_jenkins():
    """
    处理逻辑：
        1.读取jenkins_bak.yaml配置文件
        2.获取信息，进行base64解码
        3.获取所有job, 获取job模板
        4.获取所有的view, 生成view模板
        5.获取所有的credentialsId，生成credentialsId模板
        7.获取所有的node，生成node模板
        8.获取所有的plugin，生成plugin模板
        9.推到github上
    """
    url = os.getenv('url')
    username = os.getenv('username')
    password = os.getenv('password')
    git_token = os.getenv('git_token')
    git_user = os.getenv('git_user')
    domain = os.getenv("bak_domain")
    repo_name = os.getenv("repo_name")
    huaweiclound_obs_url = os.getenv('huaweiclound_obs_url')
    huaweiclound_obs_ak = os.getenv('huaweiclound_obs_ak')
    huaweiclound_obs_sk = os.getenv('huaweiclound_obs_sk')
    print("**************1.jenkins bak tools bak*****************************")
    with TemporaryDirectory() as dirname:
        infra_jenkins_path = os.path.join(dirname, repo_name)
        result = JenkinsTools.execute_cmd(GlobalConfig.git_clone_cmd.format(dirname, git_user, git_token, repo_name))
        if "error" in result or "fatal" in result:
            raise Exception("git clone {} failed:{}.".format(repo_name, result))
        domain_path = os.path.join(infra_jenkins_path, domain)
        JenkinsTools.rmd_dir(domain_path)
        print("###############1.jenkins bak tools start to work with {}#########".format(domain))
        jenkins_instance = jenkins.Jenkins(url, username, password, timeout=180)
        obs_client = ObsClient(access_key_id=huaweiclound_obs_ak,
                               secret_access_key=huaweiclound_obs_sk,
                               server=huaweiclound_obs_url)
        print("###############2.jenkins bak tools start to bak jobs and folder config#########")
        all_jobs = jenkins_instance.get_all_jobs()
        total_job = list()
        for job in all_jobs:
            if job['_class'] == "com.cloudbees.hudson.plugins.folder.Folder":
                continue
            total_job.append(job["fullname"])
        for job_name in total_job:
            job_content = jenkins_instance.get_job_config(job_name)
            if job_name.endswith(r".xml"):
                job_name_temp = job_name
            else:
                job_name_temp = "{}.xml".format(job_name)
            job_path = os.path.join(domain_path, GlobalConfig.job_dir_name, job_name_temp)
            JenkinsTools.dump_xml(job_path, job_content)
        print("###############3.jenkins bak tools start to bak views config#########")
        all_views = jenkins_instance.get_views()
        for view in all_views:
            view_config = jenkins_instance.get_view_config(view["name"])
            view_path = os.path.join(domain_path, GlobalConfig.view_dir_name, "{}.xml".format(view["name"]))
            JenkinsTools.dump_xml(view_path, view_config)
        print("###############4.jenkins bak tools start to bak node config#########")
        all_nodes = jenkins_instance.get_nodes()
        for node in all_nodes:
            node_name = node["name"]
            if node_name == "Built-In Node" or node_name == "master":
                continue
            node_config = jenkins_instance.get_node_config(node_name)
            nodes_path = os.path.join(domain_path, GlobalConfig.node_dir_name, "{}.xml".format(node_name))
            JenkinsTools.dump_xml(nodes_path, node_config)
        print("###############5.jenkins bak tools start to bak plugins config#########")
        all_plugins = jenkins_instance.get_plugins_info()
        plugins_path = os.path.join(domain_path, GlobalConfig.plugin_dir_name, GlobalConfig.plugin_name)
        JenkinsTools.dump_xml(plugins_path, json.dumps(all_plugins))
        print("###############6.jenkins bak tools start to bak credentials config#########")
        jenkins_api_instance = JenkinsLib(url, username, password, timeout=180, useCrumb=True)
        # credentials_data = jenkins_api_instance.get_credentials().credentials
        # credentials_dict = {key: value.__dict__ for key, value in credentials_data.items()}
        # credentials_conf_dict = JenkinsTools.get_credentials_info(jenkins_api_instance)
        # JenkinsTools.credentials_supplement(credentials_dict, credentials_conf_dict)
        # secret_dict = JenkinsTools.parse_secret(jenkins_api_instance, credentials_conf_dict, domain)
        # JenkinsTools().upload_obs_data(obs_client, secret_dict)
        print("###############7.jenkins bak tools start to bak user infor#########")
        user_dict = jenkins_api_instance.get_user_dict()
        user_config_path = os.path.join(domain_path, GlobalConfig.cre_dir_name, GlobalConfig.user_name)
        JenkinsTools.dump_yaml(user_config_path, dict(user_dict))
        print("###############8.jenkins bak tools start to bak configure security#########")
        configure_security_info = jenkins_api_instance.get_configure_security()
        configure_security_path = os.path.join(domain_path, GlobalConfig.cre_dir_name,
                                               GlobalConfig.config_security_name)
        JenkinsTools.dump_xml(configure_security_path, configure_security_info)
        print("###############9.jenkins bak tools start to bak configure system#########")
        configure_info = jenkins_api_instance.get_configure()
        configure_info_path = os.path.join(domain_path, GlobalConfig.cre_dir_name, GlobalConfig.config_system_name)
        JenkinsTools.dump_xml(configure_info_path, configure_info)
        print("###############10.jenkins bak tools start to bak configure tools#########")
        configure_tools = jenkins_api_instance.get_configure_tools()
        configure_tools_path = os.path.join(domain_path, GlobalConfig.cre_dir_name, GlobalConfig.config_tools_name)
        JenkinsTools.dump_xml(configure_tools_path, configure_tools)
        print("###############11.jenkins bak tools start to bak clouds config#########")
        clouds_config_info = jenkins_api_instance.get_config_xml()
        clouds_config_content = {domain: clouds_config_info}
        JenkinsTools().upload_obs_data(obs_client, clouds_config_content, GlobalConfig.obs_default_config)
        print("********2.jenkins bak tools push remote github/gitee*****")
        commit_msg = "commit_{}_{}".format(domain, str(int(time.time())))
        cmd = GlobalConfig.git_commit_push_cmd.format(infra_jenkins_path, commit_msg)
        result = JenkinsTools.execute_cmd(cmd)
        if "error" in result or "fatal" in result:
            raise Exception("push {} failed:{}.".format(repo_name, result))
        print("***********************4.finish*************************")


if __name__ == '__main__':
    bak_jenkins()
