# -*- coding: utf-8 -*-
# @Time    : 2022/5/27 11:00
# @Author  : Tom_zc
# @FileName: jenkins_tools.py
# @Software: PyCharm

import jenkins
import argparse
import json
import os


class GlobalConfig(object):
    create_job_templates_path = os.path.join(os.path.dirname(__file__), "create_job_templates.xml")
    create_execute_shell_path = os.path.join(os.path.dirname(__file__), "create_execute_shell.sh")
    modify_job_templates_path = os.path.join(os.path.dirname(__file__), "modify_job_templates.xml")
    modify_execute_shell_path = os.path.join(os.path.dirname(__file__), "modify_execute_shell.sh")
    create_view_path = os.path.join(os.path.dirname(__file__), "create_view_templates.xml")
    modify_view_path = os.path.join(os.path.dirname(__file__), "modify_view_templates.xml")
    command_list = ["create_job", "modify_job", "query_job", "query_jobs", "create_build",
                    "query_build", "create_view", "modify_view", "query_view", "query_views"]


# noinspection DuplicatedCode
class JenkinsTools(object):

    def __init__(self, url=None, username=None, password=None):
        self._jenkins = jenkins.Jenkins(url, username, password)

    def create_job(self, name, config_xml):
        return self._jenkins.create_job(name, config_xml)

    def modify_job(self, name, config_xml):
        return self._jenkins.reconfig_job(name, config_xml)

    def query_job(self, name):
        job_content = self._jenkins.get_job_info(name)
        print("query_job:{}".format(json.dumps(job_content, indent=4)))

    def query_jobs(self):
        job_content = self._jenkins.get_all_jobs()
        print("query_jobs:{}".format(json.dumps(job_content, indent=4)))

    def create_build(self, name):
        self._jenkins.build_job(name)

    def query_build(self, name, number):
        build_content = self._jenkins.get_build_info(name, int(number))
        print("query_build: job name:{},  query_build:{}".format(name, json.dumps(build_content, indent=4)))

    def query_job_config(self, name):
        return self._jenkins.get_job_config(name)

    def get_view_config(self, name):
        return self._jenkins.get_view_config(name)

    def create_view(self, name, config_xml):
        return self._jenkins.create_view(name=name, config_xml=config_xml)

    def modify_view(self, name, config_xml):
        return self._jenkins.reconfig_view(name, config_xml=config_xml)

    def query_view(self, name):
        content = self._jenkins.get_view_config(name)
        print("query_view:{}".format(json.dumps(content, indent=4)))
        return content

    def query_views(self):
        content = self._jenkins.get_views()
        print("query_views:{}".format(json.dumps(content, indent=4)))


class ArgParseTools(object):
    @staticmethod
    def parse_input_args():
        par = argparse.ArgumentParser()
        par.add_argument("-c", "--command",
                         help="""the command of 
                                 /create_job/modify_job/query_job/query_jobs
                                 /create_build/query_build
                                 /create_view/modify_view/query_view/query_views""",
                         required=True)
        par.add_argument("-n", "--name", help="the name of job or build", required=False)
        par.add_argument("-number", "--number", help="the number of build", required=False)
        par.add_argument("-url", "--url", help="The url of jenkins", required=False)
        par.add_argument("-u", "--username", help="the username of jenkins user", required=False)
        par.add_argument("-p", "--password", help="the password of jenkins user", required=False)
        args = par.parse_args()
        return args


class JenkinsHelper(object):
    @staticmethod
    def load_job_xml(job_path=None, shell_path=None):
        if job_path is None:
            job_path = GlobalConfig.create_job_templates_path
        if shell_path is None:
            shell_path = GlobalConfig.create_execute_shell_path
        with open(job_path, "r") as f1:
            templates = f1.read()
        with open(shell_path, "r") as f2:
            shell_command = f2.read()
        content = templates.format(shell_command=shell_command)
        if not content:
            raise Exception("jenkins_tools: create_job_templates.xml is invalid")
        return content

    @staticmethod
    def dump_job_xml(content, job_path=None, shell_path=None):
        if job_path is None:
            job_path = GlobalConfig.modify_job_templates_path
        if shell_path is None:
            shell_path = GlobalConfig.modify_execute_shell_path
        try:
            temp1 = content.split(r"<command>")
            temp2 = temp1[1].split(r"</command>")
            templates = temp1[0] + r"<command>{shell_command}</command>" + temp2[1]
            shell_command = temp2[0]
            with open(job_path, "w") as f1:
                f1.write(templates)
            with open(shell_path, "w") as f2:
                f2.write(shell_command)
        except Exception as e:
            print(e)
            raise Exception("dump_xml:{}".format(e))

    @staticmethod
    def load_view_xml(view_path=None):
        if view_path is None:
            view_path = GlobalConfig.create_view_path
        with open(view_path, "r") as f1:
            templates = f1.read()
        return templates

    @staticmethod
    def dump_view_xml(content, view_path=None):
        if view_path is None:
            view_path = GlobalConfig.modify_view_path
        with open(view_path, "w") as f1:
            f1.write(content)

    @staticmethod
    def parse_yaml_args():
        input_args = ArgParseTools.parse_input_args()
        print("**************1.jenkins tools analytic parameter**************")
        if input_args.command is None or input_args.command not in GlobalConfig.command_list:
            raise Exception("jenkins_tools: command is invalid!")
        if input_args.name is None and input_args.command not in ["query_jobs", "query_views"]:
            raise Exception("jenkins_tools: name is invalid!")
        return input_args.__dict__

    @staticmethod
    def switch_command(jenkins_tools, input_dict, content=None):
        command = input_dict["command"]
        if command == "create_job":
            jenkins_tools.create_job(input_dict["name"], config_xml=content)
        elif command == "modify_job":
            jenkins_tools.modify_job(input_dict["name"], config_xml=content)
        elif command == "query_job":
            jenkins_tools.query_job(input_dict["name"])
            job_content = jenkins_tools.query_job_config(input_dict['name'])
            JenkinsHelper.dump_job_xml(job_content)
        elif command == "query_jobs":
            jenkins_tools.query_jobs()
        elif command == "create_build":
            jenkins_tools.create_build(input_dict["name"])
        elif command == "query_build":
            jenkins_tools.query_build(input_dict['name'], input_dict["number"])
        elif command == "create_view":
            jenkins_tools.create_view(input_dict['name'], content)
        elif command == "modify_view":
            jenkins_tools.modify_view(input_dict['name'], content)
        elif command == "query_view":
            view_content = jenkins_tools.query_view(input_dict['name'])
            JenkinsHelper.dump_view_xml(view_content)
        elif command == "query_views":
            jenkins_tools.query_views()


def main():
    input_dict = JenkinsHelper.parse_yaml_args()
    if input_dict.get("command") == "create_job":
        content = JenkinsHelper.load_job_xml()
    elif input_dict.get("command") == "modify_job":
        content = JenkinsHelper.load_job_xml(GlobalConfig.modify_job_templates_path,
                                             GlobalConfig.modify_execute_shell_path)
    elif input_dict.get("command") == "create_view":
        content = JenkinsHelper.load_view_xml()
    elif input_dict.get("command") == "modify_view":
        content = JenkinsHelper.load_view_xml(GlobalConfig.modify_view_path)
    else:
        content = None
    input_dict_str = ",".join([str("{}:{}".format(key, value)) for key, value in input_dict.items()])
    print("jenkins_tools receive params:{}".format(input_dict_str))
    print("**************2.jenkins tools execute tools*******************")
    jenkins_tools = JenkinsTools(input_dict.get("url"), input_dict.get("username"), input_dict.get("password"))
    JenkinsHelper.switch_command(jenkins_tools, input_dict, content)
    print("**************3.success***************************************")


if __name__ == '__main__':
    main()
