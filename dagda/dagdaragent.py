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

from ragent import analyzer_agent
import argparse

def save_report_html(data,template,output):
    # generate html-output
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath='templates/'))
    template = env.get_template(template)
    html = template.render(data)
    with open(output, 'w') as f:
        f.write(html)

def parse_arguments():
    """
    Parses commandline arguments
    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser('Dagda remote agent')
    parser.add_argument('-i', '--docker_image', type=str, help='Image to analize', required=True)
    parser.add_argument('-s', '--server', type=str, help='Dagda Server', required=True)
    parser.add_argument('-p', '--port', type=int, help='Dagda Server Port', required=True)
    parser.add_argument('-t', '--timeout', type=int, help='Vulnerabilities query Dagda Server timeout')
    args = parser.parse_args()
    return args

# -- Main function
def main():
    args = parse_arguments()
    if args.timeout:
        timeout = args.timeout
    else:
        timeout = 5
    agent_cli = analyzer_agent.RemoteAnalyzer(dagda_server_host=args.server,dagda_server_port=args.port,
                                              dagba_server_timeout=timeout)
    output = agent_cli.evaluate_image(args.docker_image, None)
    print (output)



if __name__ == "__main__":
    main()
