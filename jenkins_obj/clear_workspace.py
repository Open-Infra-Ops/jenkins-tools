# -*- coding: utf-8 -*-
# @Time    : 2024/2/2 15:42
# @Author  : Tom_zc
# @FileName: clear_workspace.py
# @Software: PyCharm

import argparse
import jenkins
import xmltodict
from collections import OrderedDict


def get_template_from_clean_up_plugin(version):
    clean_up_plugin_dict = OrderedDict()
    plugin_info = OrderedDict()
    plugin_class = OrderedDict()
    plugin_info["@plugin"] = "ws-cleanup@{}".format(version)
    plugin_class["@class"] = "empty-list"
    plugin_info["patterns"] = plugin_class
    plugin_info["deleteDirs"] = 'false'
    plugin_info["skipWhenFailed"] = 'false'
    plugin_info["cleanWhenSuccess"] = 'true'
    plugin_info["cleanWhenUnstable"] = 'true'
    plugin_info["cleanWhenFailure"] = 'true'
    plugin_info["cleanWhenNotBuilt"] = 'true'
    plugin_info["cleanWhenAborted"] = 'true'
    plugin_info["notFailBuild"] = 'false'
    plugin_info["cleanupMatrixParent"] = 'false'
    plugin_info["externalDelete"] = None
    plugin_info["disableDeferredWipeout"] = 'false'
    clean_up_plugin_dict["hudson.plugins.ws__cleanup.WsCleanup"] = plugin_info
    return clean_up_plugin_dict


class ArgParseTools(object):
    @staticmethod
    def parse_input_args():
        par = argparse.ArgumentParser()
        par.add_argument("-url", "--url", help="The url of jenkins", required=False)
        par.add_argument("-u", "--username", help="the username of jenkins user", required=False)
        par.add_argument("-p", "--password", help="the password of jenkins user", required=False)
        args = par.parse_args()
        return args


def main():
    args = ArgParseTools.parse_input_args()
    jenkins_imp = jenkins.Jenkins(url=args.url, username=args.username, password=args.password)
    jobs = jenkins_imp.get_all_jobs()
    ws_clean_up = jenkins_imp.get_plugin_info("ws-cleanup")
    for job in jobs:
        if job["_class"] == "hudson.model.FreeStyleProject":
            print("start to wipeout job workspace:{}".format(job["fullname"]))
            jenkins_imp.wipeout_job_workspace(job["fullname"])
            job_config_str = jenkins_imp.get_job_config(job["fullname"])
            job_config = xmltodict.parse(job_config_str)
            publishers = job_config["project"]["publishers"]
            if publishers is None:
                template = get_template_from_clean_up_plugin(ws_clean_up["version"])
                job_config["project"]["publishers"] = template
                job_xml = xmltodict.unparse(job_config, pretty=True)
                jenkins_imp.reconfig_job(job["fullname"], job_xml)
                print("job:{} craete the cleanup config".format(job["fullname"]))
            elif "hudson.plugins.ws__cleanup.WsCleanup" not in publishers.keys():
                template = get_template_from_clean_up_plugin(ws_clean_up["version"])
                job_config["project"]["publishers"].update(template)
                job_xml = xmltodict.unparse(job_config, pretty=True)
                jenkins_imp.reconfig_job(job["fullname"], job_xml)
                print("job:{} add the cleanup config".format(job["fullname"]))


if __name__ == '__main__':
    main()
