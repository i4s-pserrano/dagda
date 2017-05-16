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
import datetime
import jinja2

HTML_DAGDA = """
<!DOCTYPE html>
<html>
<head>
  <style>
  * {
    font-family: helvetica;
  }
    .table-container {
      position:relative;
      width:80%;
      margin:0 auto;
    }
    table {
        width:100%;
    }
    table tr {
      height:50px;
      vertical-align: middle;
      /*text-align: center;*/
      border-bottom:1px solid black;
      font-size: 18px;
    }
    /*table tr:nth-child(even) {
        background-color: #eee;
    }
    table tr:nth-child(odd) {
       background-color:#fff;
    }*/
    table th {
        font-size: 20px;
        background-color: blue;
        color: white;
        height:50px;
        vertical-align: middle;
    }
    .header {
      background-color: rgb(9, 79, 164);
    }
    .failed {
      background-color: rgba(255, 0, 0, 0.25);
    }
    .timeout {
      background-color: rgba(232, 127, 15, 0.25);
    }
    .ok {
      background-color: rgba(46, 204, 113, 0.25);
    }
  </style>
</head>
<body>
  <div class="table-container">
  <center>
    <h1>Dagda Analisys</h1>
  </center>
  <table border=1>
    <tr>
       <th>Image Name</th><td><center><strong> {{ data['image_name'] }} </strong> </center> </td>
       <th>Analisys executed time</th><td><center> {{ data['timestamp']|format_date_ES }} </center></td>
    </tr>
  </table>
  <table border=1>
    <tr>
       <th>Total OS packages</th><td><center> {{ data['static_analysis']['os_packages']['total_os_packages'] }} </center></td>
       <th>Total Vuln OS packages</th>
       <td>
        <center>
          {% if data['static_analysis']['os_packages']['vuln_os_packages'] > 0 %}
            {% set fontcolor="red" %}
          {% else %}
            {% set fontcolor="black" %}
          {% endif %}
          <font color="{{fontcolor}}" ><b>{{ data['static_analysis']['os_packages']['vuln_os_packages'] }}</b> </font>
        </center>
      </td>
       <th>Total OK packages</th><td><center> {{ data['static_analysis']['os_packages']['ok_os_packages'] }} </center></td>
    </tr>
  </table>
  <br>
  <table border=1>
    <tr border=1>
      <th>Product</th> <th>version</th> <th>Is vulnerable</th><th>Data</th></td>
    </tr>
    {% for product in data['static_analysis']['os_packages']['os_packages_details'] -%}
    <tr border=1>
      <td>{{ product['product'] }}</td>
      <td>{{ product['version'] }}</td>
      <td>
        {% if product['is_vulnerable'] %}
          {% set fontcolor="red" %}
        {% else %}
          {% set fontcolor="black" %}
        {% endif %}
        <font color="{{fontcolor}}"><b>{{ product['is_vulnerable'] }}</b></font>
      </td>
      <td>
          {% for vulnerability in product.vulnerabilities %}
            {% for key, value in vulnerability.items() %}
              {% if 'CVE' in key %}
                  <a target="_blank" href="https://nvd.nist.gov/vuln/detail/{{ key }}">{{key}}</a> - <span>Score: <b>{{value['cvss_base']}}</b></span> <span>cvss exploit: <b>{{value["cvss_exploit"]}}</b></span> <span>Summary:{{value["summary"]}}</span><br>
              {% elif 'BID' in key %}
                  {% set ID = key.split('-') %}
                  <a target="_blank" href="http://www.securityfocus.com/bid/{{ID[1]}}">{{key}}</a> - <span>Class: <b>{{value['class']}}</b></span> <span>local: <b>{{value["local"]}}</b></span> <span>remote: <b>{{value["remote"]}}</b></span>
                    <span>Afected CVE: {% for sub_cve in value["cve"] %}<a target="_blank" href="https://nvd.nist.gov/vuln/detail/{{ sub_cve}}">{{sub_cve}}</a> {%- endfor %}
                  </span> <span>Summary:{{value["title"]}}</span><br>
                  {% else %}
                  {% set ID = key.split('-') %}
                  <a target="_blank" href="https://www.exploit-db.com/exploits/{{ID[1]}}/">{{key}}</a> - <span>AttackType:<b>{{value['type']}}</b></span> <span>Platform:<b>{{value["platform"]}}</b></span> <span>Port:<b>{{value["port"]}}</b></span> <span>Summary:{{value["description"]}}</span><br>
              {% endif %}
            {%- endfor %}
          {%- endfor %}
      </td>
    </tr>
    {%- endfor %}
  </table>
  </div>
</body>
</html>
"""


def format_date_ES(unix_timestamp):
    value = datetime.datetime.fromtimestamp(unix_timestamp)
    return value.strftime('%d-%m-%Y %H:%M:%S')


def save_report_html(data,output):
    # Generate html-output
    env = jinja2.Environment()
    env.filters['format_date_ES'] = format_date_ES
    template = env.from_string(HTML_DAGDA)
    html = template.render(data=data)
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
    parser.add_argument('-f', '--file', help='save output to a html format on this file')
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
    if args.file:
        save_report_html(output,args.file)



if __name__ == "__main__":
    main()
