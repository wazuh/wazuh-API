#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from sys import argv, exit, path
from getopt import getopt, GetoptError
from os import path as os_path
import json
import signal
import logging
import time
import asyncio

error_wazuh_package = 0
exception_error = None
try:
    new_path = '/var/ossec'
    if not os_path.exists(new_path):
        current_path = path[0].split('/')
        new_path = "/{0}/{1}".format(current_path[1], current_path[2])
    new_framework_path = "{}/framework".format(new_path)
    path.append(new_framework_path)
    from wazuh import Wazuh
    wazuh = Wazuh(ossec_path=new_path)
    from wazuh.exception import WazuhException
    from wazuh.cluster.dapi import dapi
    from wazuh.cluster.cluster import read_config
except (ImportError, SyntaxError) as e:
    error = str(e)
    error_wazuh_package = -1
except WazuhException as e:
    error_wazuh_package = -3
    error = e.message
    error_code = e.code
except Exception as e:
    error = str(e)
    if str(e).startswith("Error 4000"):
        error_wazuh_package=-1
    else:
        error_wazuh_package = -2
        exception_error = e


def print_json(data, error=0):
    output = {'error': error}

    if error == 0:
        key = 'data'
    else:
        key = 'message'

    output[key] = data

    if pretty:
        print(json.dumps(output, indent=4))
    else:
        print(json.dumps(output))


def is_json(myjson):
    try:
        json_object = json.loads(myjson)
    except:
        return False

    return json_object


def get_stdin(msg):
    stdin = input(msg)
    return stdin


def signal_handler(n_signal, frame):
    exit(1)


def usage():
    help_msg = '''
    Wazuh Control

    \t-p, --pretty       Pretty JSON
    \t-d, --debug        Debug mode
    \t-l, --list         List functions
    \t-h, --help         Help
    '''
    print(help_msg)
    exit(1)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    request = {}
    pretty = False
    debug = False
    list_f = False

    # Read and check arguments
    try:
        opts, args = getopt(argv[1:], "pdlh", ["pretty", "debug", "list", "help"])
        n_args = len(opts)
        if not (0 <= n_args <= 2):
            print("Incorrect number of arguments.\nTry '--help' for more information.")
            exit(1)
    except GetoptError as err_args:
        print(str(err_args))
        print("Try '--help' for more information.")
        exit(1)

    for o, a in opts:
        if o in ("-p", "--pretty"):
            pretty = True
        elif o in ("-d", "--debug"):
            debug = True
        elif o in ("-l", "--list"):
            list_f = True
        elif o in ("-h", "--help"):
            usage()
        else:
            print("Wrong argument combination.")
            print("Try '--help' for more information.")
            exit(1)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    if not list_f:
        stdin = get_stdin("")
        request = is_json(stdin)
        if not request:
            print_json("Wazuh-Python Internal Error: Bad JSON input", 1000)
            exit(1)

    if error_wazuh_package < 0:
        if error_wazuh_package == -1:
            print_json("Wazuh-Python Internal Error: {0}".format(error), 1000)
        if error_wazuh_package == -2:
            print_json("Wazuh-Python Internal Error: uncaught exception: {0}".format(exception_error), 1000)
        if error_wazuh_package == -3:
            print_json(error, error_code)
        exit(0)  # error code 0 shows the msg in the API response.

    if 'function' not in request:
        print_json("Wazuh-Python Internal Error: 'JSON input' must have the 'function' key", 1000)
        exit(1)

    if 'ossec_path' not in request:
        print_json("Wazuh-Python Internal Error: 'JSON input' must have the 'ossec_path' key", 1000)
        exit(1)

    # Main
    try:
        wazuh = Wazuh(ossec_path=request['ossec_path'])

        cluster_config = read_config()
        executable_name = "Wazuh API"
        master_ip = cluster_config['nodes'][0]
        if cluster_config['node_type'] != 'master' and cluster_config['disabled'] == 'no':
            raise WazuhException(3019, {"EXECUTABLE_NAME": executable_name, "MASTER_IP": master_ip})

        before = time.time()

        if list_f:
            print_json(sorted(dapi.get_functions()))
            exit(0)

        request['from_cluster'] = False
        data = asyncio.run(dapi.DistributedAPI(input_json=request, logger=logging.getLogger(),
                                               debug=debug, pretty=pretty).distribute_function())
        after = time.time()
        logging.debug("Total time: {}".format(after - before))
        logging.debug("Size of all received data: {}".format(len(data)))

        print(data)

    except WazuhException as e:
        print_json(e.message, e.code)
        if debug:
            raise
    except Exception as e:
        print_json("Wazuh-Python Internal Error: {0}".format(str(e)), 1000)
        if debug:
            raise
