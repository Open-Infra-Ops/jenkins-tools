# -*- coding: utf-8 -*-
# @Time    : 2024/2/2 15:42
# @Author  : Tom_zc
# @FileName: clear_workspace.py
# @Software: PyCharm

import argparse
import jenkins
import xmltodict

clean_up_plugin = '''<publishers>
    <hudson.plugins.ws__cleanup.WsCleanup plugin="ws-cleanup@{}">
    <patterns class="empty-list"/>
    <deleteDirs>false</deleteDirs>
    <skipWhenFailed>false</skipWhenFailed>
    <cleanWhenSuccess>true</cleanWhenSuccess>
    <cleanWhenUnstable>true</cleanWhenUnstable>
    <cleanWhenFailure>true</cleanWhenFailure>
    <cleanWhenNotBuilt>true</cleanWhenNotBuilt>
    <cleanWhenAborted>true</cleanWhenAborted>
    <notFailBuild>false</notFailBuild>
    <cleanupMatrixParent>false</cleanupMatrixParent>
    <externalDelete></externalDelete>
    <disableDeferredWipeout>false</disableDeferredWipeout>
    </hudson.plugins.ws__cleanup.WsCleanup>
  </publishers>'''


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
    clean_up_full_plugin = clean_up_plugin.format(ws_clean_up["version"])
    for job in jobs:
        if job["_class"] == "hudson.model.FreeStyleProject":
            print("start to wipeout job workspace:{}".format(job["fullname"]))
            jenkins_imp.wipeout_job_workspace(job["fullname"])
            job_config_str = jenkins_imp.get_job_config(job["fullname"])
            job_config = xmltodict.parse(job_config_str)
            publishers = job_config["project"]["publishers"]
            if publishers is None:
                new_config = job_config_str.replace(r"<publishers/>", clean_up_full_plugin)
                jenkins_imp.reconfig_job(job["fullname"], new_config)
                print("reconfig job success:{}".format(job["fullname"]))
            job_config_str = jenkins_imp.get_job_config(job["fullname"])
            print(job_config_str)


if __name__ == '__main__':
    main()
