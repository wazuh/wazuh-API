/**
 * Wazuh RESTful API
 * Copyright (C) 2015-2020 Wazuh, Inc. All rights reserved.
 * Wazuh.com
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


var router = require('express').Router();

/**
 * @api {get} /experimental/syscollector/packages Get packages info of all agents
 * @apiName GetPackages
 * @apiGroup Packages
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [vendor] Filters by vendor.
 * @apiParam {String} [name] Filters by name.
 * @apiParam {String} [architecture] Filters by architecture.
 * @apiParam {String} [format] Filters by format.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [version] Filter by version name.
 *
 * @apiDescription Returns the agent's packages info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/packages?pretty&sort=-name&limit=2"
 *
 */
router.get('/syscollector/packages', function (req, res) {
    var filters = {'vendor': 'encoded_uri', 'name': 'alphanumeric_param',
                   'architecture': 'alphanumeric_param', 'format': 'alphanumeric_param', 
                   'version' : 'alphanumeric_param'};
    templates.array_request("/experimental/syscollector/packages", req, res, "syscollector", {}, filters);
})

/**
 * @api {get} /experimental/syscollector/os Get os info of all agents
 * @apiName GetOS
 * @apiGroup OS
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [os_name] Filters by os_name.
 * @apiParam {String} [architecture] Filters by architecture.
 * @apiParam {String} [os_version] Filters by os_version.
 * @apiParam {String} [version] Filters by version.
 * @apiParam {String} [release] Filters by release.
 *
 * @apiDescription Returns the agent's os info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/os?pretty"
 *
 */
router.get('/syscollector/os', function (req, res) {
    var filters = {'os_name': 'alphanumeric_param', 'architecture': 'alphanumeric_param',
                   'os_version': 'alphanumeric_param', 'version': 'alphanumeric_param', 
                   'release': 'alphanumeric_param'
                  };
    templates.array_request("/experimental/syscollector/os", req, res, "syscollector", {}, filters);
})

/**
 * @api {get} /experimental/syscollector/hardware Get hardware info of all agents
 * @apiName GetHardware
 * @apiGroup Hardware
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [ram_free] Filters by ram_free.
 * @apiParam {String} [ram_total] Filters by ram_total.
 * @apiParam {String} [cpu_cores] Filters by cpu_cores.
 * @apiParam {String} [cpu_mhz] Filters by cpu_mhz.
 * @apiParam {String} [cpu_name] Filters by cpu_name.
 * @apiParam {String} [board_serial] Filters by board_serial.
 *
 * @apiDescription Returns the agent's hardware info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/hardware?pretty"
 *
 */
router.get('/syscollector/hardware', function (req, res) {
    var filters = {'ram_free': 'numbers', 'ram_total': 'numbers', 'cpu_cores': 'numbers', 
                   'cpu_mhz': 'alphanumeric_param', 'cpu_name': 'alphanumeric_param',
                   'board_serial': 'alphanumeric_param'
                };
    templates.array_request("/experimental/syscollector/hardware", req, res, "syscollector", {}, filters);
})

/**
 * @api {get} /experimental/syscollector/processes Get processes info of all agents
 * @apiName GetProcesses
 * @apiGroup Processes
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {Number} [pid] Filters by process pid.
 * @apiParam {String} [state] Filters by process state.
 * @apiParam {Number} [ppid] Filters by process parent pid.
 * @apiParam {String} [egroup] Filters by process egroup.
 * @apiParam {String} [euser] Filters by process euser.
 * @apiParam {String} [fgroup] Filters by process fgroup.
 * @apiParam {String} [name] Filters by process name.
 * @apiParam {Number} [nlwp] Filters by process nlwp.
 * @apiParam {Number} [pgrp] Filters by process pgrp.
 * @apiParam {Number} [priority] Filters by process priority.
 * @apiParam {String} [rgroup] Filters by process rgroup.
 * @apiParam {String} [ruser] Filters by process ruser.
 * @apiParam {String} [sgroup] Filters by process sgroup.
 * @apiParam {String} [suser] Filters by process suser.
 *
 * @apiDescription Returns the agent's processes info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/processes?pretty&limit=2&sort=priority"
 *
 */
router.get('/syscollector/processes', function (req, res) {
    var filters = {'pid': 'numbers', 'state': 'alphanumeric_param', 'ppid': 'numbers',
                   'egroup': 'alphanumeric_param', 'euser': 'alphanumeric_param', 
                   'fgroup': 'alphanumeric_param', 'name': 'alphanumeric_param', 
                   'nlwp': 'numbers', 'pgrp': 'numbers', 'priority': 'numbers',
                   'rgroup': 'alphanumeric_param', 'ruser': 'alphanumeric_param',
                   'sgroup': 'alphanumeric_param', 'suser': 'alphanumeric_param'
                };
    templates.array_request("/experimental/syscollector/processes", req, res, "syscollector", {}, filters);
})

/**
 * @api {get} /experimental/syscollector/ports Get ports info of all agents
 * @apiName GetPorts
 * @apiGroup Ports
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {Number} [pid] Filters by pid.
 * @apiParam {String} [protocol] Filters by protocol.
 * @apiParam {String} [local_ip] Filters by local_ip.
 * @apiParam {Number} [local_port] Filters by local_port.
 * @apiParam {String} [remote_ip] Filters by remote_ip.
 * @apiParam {Number} [tx_queue] Filters by tx_queue.
 * @apiParam {String} [state] Filters by state.
 * @apiParam {String} [process] Filters by process.
 *
 * @apiDescription Returns the agent's ports info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/ports?pretty&limit=2&sort=protocol"
 *
 */
router.get('/syscollector/ports', function (req, res) {
    var filters = {'protocol': 'alphanumeric_param', 'local_ip': 'alphanumeric_param',
                   'local_port': 'numbers', 'remote_ip': 'alphanumeric_param',
                   'tx_queue': 'numbers', 'state': 'alphanumeric_param',
                   'pid': 'numbers', 'process': 'alphanumeric_param'
                };
    templates.array_request("/experimental/syscollector/ports", req, res, "syscollector", {}, filters);
})

/**
 * @api {get} /experimental/syscollector/netaddr Get network address info of all agents
 * @apiName GetNetaddr
 * @apiGroup Netaddr
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [proto] Filters by proto.
 * @apiParam {String} [address] Filters by address.
 * @apiParam {String} [broadcast] Filters by broadcast.
 * @apiParam {String} [netmask] Filters by netmask.
 *
 * @apiDescription Returns the agent's network address info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/netaddr?pretty&limit=2&sort=proto"
 *
 */
router.get('/syscollector/netaddr', function (req, res) {
    var filters = {'iface': 'alphanumeric_param', 'proto': 'alphanumeric_param', 'address': 'alphanumeric_param',
                   'broadcast': 'alphanumeric_param', 'netmask': 'alphanumeric_param',
                };
    templates.array_request("/experimental/syscollector/netaddr", req, res, "syscollector", {}, filters);
})

/**
 * @api {get} /experimental/syscollector/netproto Get network protocol info of all agents
 * @apiName GetNetproto
 * @apiGroup Netproto
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [iface] Filters by iface.
 * @apiParam {String} [type] Filters by type.
 * @apiParam {String} [gateway] Filters by gateway.
 * @apiParam {String} [dhcp] Filters by dhcp.
 *
 * @apiDescription Returns the agent's network protocol info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/netproto?pretty&limit=2&sort=type"
 *
 */
router.get('/syscollector/netproto', function (req, res) {
    var filters = {'iface': 'alphanumeric_param', 'type': 'alphanumeric_param',
                   'gateway': 'alphanumeric_param', 'dhcp': 'alphanumeric_param'
                };
    templates.array_request("/experimental/syscollector/netproto", req, res, "syscollector", {}, filters);
})

/**
 * @api {get} /experimental/syscollector/netiface Get network interface info of all agents
 * @apiName GetNetiface
 * @apiGroup Netiface
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [name] Filters by name.
 * @apiParam {String} [adapter] Filters by adapter.
 * @apiParam {String} [type] Filters by type.
 * @apiParam {String} [state] Filters by state.
 * @apiParam {String} [mtu] Filters by mtu.
 * @apiParam {String} [tx_packets] Filters by tx_packets.
 * @apiParam {String} [rx_packets] Filters by rx_packets.
 * @apiParam {String} [tx_bytes] Filters by tx_bytes.
 * @apiParam {String} [rx_bytes] Filters by rx_bytes.
 * @apiParam {String} [tx_errors] Filters by tx_errors.
 * @apiParam {String} [rx_errors] Filters by rx_errors.
 * @apiParam {String} [tx_dropped] Filters by tx_dropped.
 * @apiParam {String} [rx_dropped] Filters by rx_dropped.
 *
 * @apiDescription Returns the agent's network interface info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/netiface?pretty&limit=2"
 *
 */
router.get('/syscollector/netiface', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /experimental/syscollector/netiface");

    var data_request = { 'function': '/experimental/syscollector/netiface', 'arguments': {} };
    var filters = {'name': 'alphanumeric_param', 'adapter': 'alphanumeric_param', 
                   'type': 'alphanumeric_param', 'state': 'alphanumeric_param', 
                   'mtu': 'numbers', 'tx_packets': 'numbers', 'rx_packets': 'numbers', 
                   'tx_bytes': 'numbers', 'rx_bytes': 'numbers', 'tx_errors': 'numbers',
                   'rx_errors': 'numbers', 'tx_dropped': 'numbers', 'rx_dropped': 'numbers'
                };
    templates.array_request("/experimental/syscollector/netiface", req, res, "syscollector", {}, filters);
})

/**
 * @api {get} /experimental/ciscat/results Get CIS-CAT results
 * @apiName GetCiscat
 * @apiGroup Results
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [benchmark] Filters by benchmark.
 * @apiParam {String} [profile] Filters by evaluated profile.
 * @apiParam {Number} [pass] Filters by passed checks.
 * @apiParam {Number} [fail] Filters by failed checks.
 * @apiParam {Number} [error] Filters by encountered errors.
 * @apiParam {Number} [notchecked] Filters by not checked.
 * @apiParam {Number} [unknown] Filters by unknown results.
 * @apiParam {Number} [score] Filters by final score.
 *
 * @apiDescription Returns the agent's ciscat results info.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/ciscat/results?pretty&sort=-score"
 *
 */
router.get('/ciscat/results', function (req, res) {
    var filters = {'benchmark': 'alphanumeric_param', 'profile': 'alphanumeric_param', 
                   'pass': 'alphanumeric_param', 'fail': 'alphanumeric_param',
                   'error': 'numbers', 'notchecked': 'numbers',
                   'unknown': 'numbers', 'score': 'numbers'
                };
    templates.array_request("/experimental/ciscat/results", req, res, "ciscat", {}, filters);
})

/**
 * @api {delete} /experimental/syscheck Clear syscheck database
 * @apiName DeleteSyscheck
 * @apiGroup Clear
 *
 *
 * @apiDescription Clears the syscheck database for all agents.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/experimental/syscheck?pretty"
 *
 */
router.delete('/syscheck', function(req, res) {
    logger.debug(req.connection.remoteAddress + " DELETE /experimental/syscheck");

    apicache.clear("syscheck");

    var data_request = {'function': 'DELETE/experimental/syscheck', 'arguments': {}};
    data_request['arguments']['all_agents'] = 1;
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
