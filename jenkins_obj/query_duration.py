#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2024/10/9 17:53
# @Author  : Tom_zc
# @FileName: query_duration.py
# @Software: PyCharm
import os
import threading
import logging
import time
import random
import statistics
import csv
import traceback
from logging import handlers
from functools import wraps
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED

import click
import jenkins
from jenkinsapi import jenkins as jenkins_api


class Logger:
    level_relations = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'crit': logging.CRITICAL
    }

    def __init__(self, filename, level='info', when='D', back_count=3,
                 fmt='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'):
        self.logger = logging.getLogger(filename)
        format_str = logging.Formatter(fmt)
        self.logger.setLevel(self.level_relations.get(level))
        sh = logging.StreamHandler()
        sh.setFormatter(format_str)
        th = handlers.TimedRotatingFileHandler(filename=filename, when=when, backupCount=back_count, encoding='utf-8')
        th.setFormatter(format_str)
        self.logger.addHandler(sh)
        self.logger.addHandler(th)


BASE_DIR = os.path.basename(__file__)
cur_file_name = "{}.log".format(BASE_DIR.split(".")[0])
logger = Logger(cur_file_name).logger

cache_file_path = os.path.join(os.path.dirname(BASE_DIR), "cache.txt")


# noinspection DuplicatedCode
def func_retry(tries=3, delay=3):
    """The wrapper of func_retry"""

    def deco_retry(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            for i in range(tries):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    logger.info("fn:{},e:{},traceback:{}".format(fn.__name__, e, traceback.print_exc()))
                    time.sleep(delay)
            else:
                logger.info("fn:{} failed".format(fn.__name__))
                return None

        return inner

    return deco_retry


class CSVtools(object):
    @classmethod
    def get_cur_date(cls):
        return datetime.now().strftime("%Y_%m_%d_%H_%M_%S")

    @classmethod
    def parse_data(cls, line):
        list_data = line.split(r'"')
        new_list_data = list_data[0].split(",")
        if len(list_data) > 1:
            data = ",".join(list_data[-2].split(","))
            new_list_data[-1] = data
        new_list_data[-1] = new_list_data[-1].replace("\n", "")
        return new_list_data

    @classmethod
    def write_csv(cls, filename):
        with open('{}_{}.csv'.format(filename, cls.get_cur_date()), 'w', newline="", encoding="utf8") as file:
            writer = csv.writer(file)
            writer.writerow(["任务名称", "最大值", "最小值", "平均值", "值列表"])
            cache_data = LocalCache.read_cache()
            for data in cache_data:
                new_data = cls.parse_data(data)
                logger.info("read data from cache:{}".format(new_data))
                writer.writerow(new_data)


class LocalCache(object):
    _lock = threading.Lock()
    _data = list()

    @classmethod
    def read_job_name_by_cache(cls):
        if os.path.exists(cache_file_path):
            exist_job_name = list()
            with open(cache_file_path, "r") as f:
                lines = f.readlines()
            for line in lines:
                exist_job_name.append(line.split(",")[0])
            return exist_job_name
        else:
            return list()

    @classmethod
    def read_cache(cls):
        if os.path.exists(cache_file_path):
            with open(cache_file_path, "r") as f:
                return f.readlines()
        else:
            return list()

    @classmethod
    def write_data(cls, result):
        with cls._lock:
            line = ",".join([str(i) for i in result])
            with open(cache_file_path, "a+") as cache_file_handler:
                cache_file_handler.write(line + "\n")


# noinspection PyProtectedMember
@func_retry()
def workflow(job_names, url, username, password):
    start_time = int(time.time())
    logger.info("start to handler the job:{}".format(",".join(job_names)))
    jenkins_api_obj = jenkins_api.Jenkins(url, username, password, timeout=5)
    jenkins_imp = jenkins.Jenkins(url=url, username=username, password=password, timeout=5)
    for job_name in job_names:
        logger.info("handing the job:{}".format(job_name))
        list_data = list()
        builds_info = jenkins_api_obj.get_job(job_name)._data.get("builds")
        for build_info in builds_info:
            job_data = jenkins_imp.get_build_info(job_name, build_info["number"])
            if job_data["result"] == "SUCCESS":
                list_data.append(round(job_data["duration"] / 1000, 2))
        if list_data:
            result = [job_name, max(list_data), min(list_data), round(statistics.mean(list_data), 2),
                      ",".join([str(i) for i in list_data])]
        else:
            result = [job_name, 0, 0, 0, ""]
        LocalCache.write_data(result)
    end_time = int(time.time())
    logger.info("end to handler the job:{}, and total spend:{}".format(",".join(job_names), str(end_time - start_time)))


# path:
# multiarch/src-openeuler/x86-64/
# multiarch/src-openeuler/aarch64/
# multiarch/src-openeuler/trigger/
# filename:
# x86_64_csv/aarch64_csv/trigger_csv
@click.command()
@click.option("--url", help='The url of jenkins')
@click.option("--username", help='the username of jenkins user')
@click.option("--password", help='the password of jenkins user')
@click.option("--path", help='the prefix of job path')
@click.option("--filename", help='the output the filename')
def main(url, username, password, path, filename):
    batch_size = 50
    filtered_job = list()
    all_tasks = list()

    # start to filter job
    logger.info("-" * 10 + "start to filter the job that match the prefix path" + "-" * 10)
    jenkins_api_obj = jenkins_api.Jenkins(baseurl=url,
                                          username=username,
                                          password=password,
                                          timeout=180)
    for job_name in jenkins_api_obj.get_jobs_list():
        logger.info("start to filter the job:{}".format(job_name))
        if job_name.startswith(path):
            logger.info("find the job:{}".format(job_name))
            filtered_job.append(job_name)

    # delete the deduplicated data from cache
    logger.info("find the need to all_data_count:{}".format(len(filtered_job)))
    exist_job_name = LocalCache.read_job_name_by_cache()
    filtered_job = list(set(filtered_job) - set(list(exist_job_name)))

    logger.info("find the need to handler_data_count:{}".format(len(filtered_job)))

    # multi thread to batch handler
    executor = ThreadPoolExecutor(max_workers=50)
    for job_index in range(0, len(filtered_job), batch_size):
        splits_list = filtered_job[job_index:job_index + batch_size]
        all_tasks.append(executor.submit(workflow, splits_list, url, username, password))
        time.sleep(random.uniform(60, 120))
    wait(all_tasks, return_when=ALL_COMPLETED)

    # write to filename
    CSVtools.write_csv(filename)


if __name__ == '__main__':
    main()
