#
# Licensed to Dagda under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Dagda licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

import datetime
from analysis.static.os import os_info_extractor
from analysis.static.dependencies import dep_info_extractor
from log.dagda_logger import DagdaLogger
from driver import docker_driver
from multiprocessing import Pool
import requests



# Analyzer class

class RemoteAnalyzer:

    # -- Public methods

    # Analyzer Constructor
    def __init__(self, dagda_server_host='127.0.0.1', dagda_server_port='5000', dagba_server_timeout='2'):
        super(RemoteAnalyzer, self).__init__()
        self.dagda_server_host = dagda_server_host
        self.dagda_server_port = dagda_server_port
        self.dagba_server_timeout = dagba_server_timeout
        self.dagba_request = requests
        try:
            self.dockerDriver = docker_driver.DockerDriver()
        except:
            print( "Error loading docker driver {0} occured: {1!r}".format(type(ex).__name__, ex.args))
            exit(1)


    # Chek api status
    def check_api_status(self):
        return 0


    # Evaluate image from image name or container id
    def evaluate_image(self, image_name, container_id):
        # Init
        data = {}

        # -- Static analysis
        # Get OS packages
        if image_name:  # Scans the docker image
            os_packages = os_info_extractor.get_soft_from_docker_image(self.dockerDriver, image_name)
        else:  # Scans the docker container
            os_packages = os_info_extractor.get_soft_from_docker_container_id(self.dockerDriver, container_id)
            image_name = self.dockerDriver.get_docker_image_name_by_container_id(container_id)
        # Get programming language dependencies
        dependencies = None
        try:
            dependencies = dep_info_extractor.get_dependencies_from_docker_image(self.dockerDriver, image_name)
        except Exception as ex:
            message = "Unexpected exception of type {0} occured: {1!r}".format(type(ex).__name__,  ex.args)
            DagdaLogger.get_logger().error(message)
            data['status'] = message

        # -- Prepare output
        if dependencies is not None:
            data['status'] = 'Completed'
        else:
            dependencies = []

        data['image_name'] = image_name
        data['timestamp'] = datetime.datetime.now().timestamp()
        data['static_analysis'] = self.generate_static_analysis(os_packages, dependencies)

        # -- Return
        return data

    # Generates the result of the static analysis
    def generate_static_analysis(self, os_packages, dependencies):
        data = {}
        data['os_packages'] = self.generate_os_report(os_packages)
        data['prog_lang_dependencies'] = self.generate_dependencies_report(dependencies)
        return data

    # Generates dependencies report
    def generate_dependencies_report(self, dependencies):
        data = {}
        dep_details = {}
        dep_details['java'] = []
        dep_details['python'] = []
        dep_details['nodejs'] = []
        dep_details['js'] = []
        dep_details['ruby'] = []
        dep_details['php'] = []
        for dependency in dependencies:
            d = {}
            splitted_dep = dependency.split("#")
            d['product'] = splitted_dep[1]
            d['version'] = splitted_dep[2]
            vulnerabilities_temp = []
            vulnerabilities = []
            vulnerabilities_temp = self.get_api_vulnerabilities(package['product'], package['version'])
            if 'err' in vulnerabilities_temp:
                vulnerabilities = []
            else:
                vulnerabilities = vulnerabilities_temp
            p['vulnerabilities'] = vulnerabilities
            dep_details[splitted_dep[0]].append(d)
        # Prepare output
        data['vuln_dependencies'] = len(dep_details['java']) + len(dep_details['python']) + \
                                    len(dep_details['nodejs']) + len(dep_details['js']) + \
                                    len(dep_details['ruby']) + len(dep_details['php'])
        data['dependencies_details'] = dep_details
        # Return
        return data

    # Generates os report
    def generate_os_report(self, os_packages):
        data = {}
        products_status = []
        vuln_products = 0
        for package in os_packages:
            p = {}
            p['product'] = package['product']
            p['version'] = package['version']
            vulnerabilities_temp = []
            vulnerabilities = []
            vulnerabilities_temp = self.get_api_vulnerabilities(package['product'], package['version'])
            if 'err' in vulnerabilities_temp:
                vulnerabilities = []
            else:
                vulnerabilities = vulnerabilities_temp
            p['vulnerabilities'] = vulnerabilities
            if len(p['vulnerabilities']) > 0:
                p['is_vulnerable'] = True
                vuln_products += 1
            else:
                p['is_vulnerable'] = False
            products_status.append(p)
        # Prepare output
        data['total_os_packages'] = len(products_status)
        data['vuln_os_packages'] = vuln_products
        data['ok_os_packages'] = data['total_os_packages'] - vuln_products
        data['os_packages_details'] = products_status
        # Return
        return data

    def get_api_vulnerabilities(self, product, version=None):
        filt_prod = product.replace("-", " ").replace("_", " ")
        output = []
        if not version:
            prod_version = filt_prod
        else:
            prod_version = filt_prod + '/' + version

        try:
            output = self.dagba_request.get('http://' + self.dagda_server_host + ':' + str(self.dagda_server_port) + \
                                      '/v1/vuln/products/' + prod_version, timeout=self.dagba_server_timeout).json()
        except requests.exceptions.Timeout:
            output = "Timeout asking the API"
        except requests.exceptions.ConnectionError:
            output = "Api is not accesible"

        return output
