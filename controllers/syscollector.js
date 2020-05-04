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
 * @api {get} /syscollector/:agent_id/os Get os info
 * @apiName GetOs_agent
 * @apiGroup OS
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {String} [select] List of selected fields separated by commas.
 *
 * @apiDescription Returns the agent's OS info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/os?pretty"
 *
 */
router.get('/:agent_id/os', function(req, res) {
    templates.object_request("/syscollector/:agent_id/os", req, res, "syscollector", {'agent_id': 'numbers'}, {});
})

/**
 * @api {get} /syscollector/:agent_id/hardware Get hardware info
 * @apiName GetHardware_agent
 * @apiGroup Hardware
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {String} [select] List of selected fields separated by commas.
 *
 * @apiDescription Returns the agent's hardware info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/hardware?pretty"
 *
 */
router.get('/:agent_id/hardware', function(req, res) {
    templates.object_request("/syscollector/:agent_id/hardware", req, res, "syscollector", {'agent_id': 'numbers'}, {});
})

/**
 * @api {get} /syscollector/:agent_id/packages Get packages info
 * @apiName GetPackages_agent
 * @apiGroup Packages
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [q] Query to filter results by.
 * @apiParam {String} [vendor] Filters by vendor.
 * @apiParam {String} [name] Filters by name.
 * @apiParam {String} [architecture] Filters by architecture.
 * @apiParam {String} [format] Filters by format.
 * @apiParam {String} [version] Filters by version.
 *
 * @apiDescription Returns the agent's packages info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/packages?pretty&limit=2&offset=10&sort=-name"
 *
 */
router.get('/:agent_id/packages', function(req, res) {
    var filters = {'vendor': 'encoded_uri', 'name': 'alphanumeric_param',
                   'architecture': 'alphanumeric_param', 'format': 'alphanumeric_param', 
                   'version' : 'alphanumeric_param'};
    templates.array_request("/syscollector/:agent_id/packages", req, res, "syscollector", {'agent_id': 'numbers'}, filters);
})

/**
 * @api {get} /syscollector/:agent_id/processes Get processes info
 * @apiName GetProcesses_agent
 * @apiGroup Processes
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [q] Query to filter results by.
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
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/processes?pretty&limit=2&offset=10&sort=-name"
 *
 */
router.get('/:agent_id/processes', function (req, res) {
    var filters = {'pid': 'numbers', 'state': 'alphanumeric_param', 'ppid': 'numbers',
                   'egroup': 'alphanumeric_param', 'euser': 'alphanumeric_param', 
                   'fgroup': 'alphanumeric_param', 'name': 'alphanumeric_param', 
                   'nlwp': 'numbers', 'pgrp': 'numbers', 'priority': 'numbers',
                   'rgroup': 'alphanumeric_param', 'ruser': 'alphanumeric_param',
                   'sgroup': 'alphanumeric_param', 'suser': 'alphanumeric_param'
                };
    templates.array_request("/syscollector/:agent_id/processes", req, res, "syscollector", {'agent_id': 'numbers'}, filters);
})


/**
 * @api {get} /syscollector/:agent_id/ports Get ports info of an agent
 * @apiName GetPorts_agent
 * @apiGroup Ports
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [q] Query to filter results by.
 * @apiParam {Number} [pid] Filters by pid.
 * @apiParam {String} [protocol] Filters by protocol.
 * @apiParam {String} [local_ip] Filters by local_ip.
 * @apiParam {Number} [local_port] Filters by local_port.
 * @apiParam {String} [remote_ip] Filters by remote_ip.
 * @apiParam {Number} [tx_queue] Filters by tx_queue.
 * @apiParam {String} [state] Filters by state.
 *
 * @apiDescription Returns the agent's ports info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/ports?pretty&sort=-protocol&limit=2"
 *
 */
router.get('/:agent_id/ports', function (req, res) {
    var filters = {'protocol': 'alphanumeric_param', 'local_ip': 'alphanumeric_param',
                   'local_port': 'numbers', 'remote_ip': 'alphanumeric_param',
                   'tx_queue': 'numbers', 'state': 'alphanumeric_param',
                   'pid': 'numbers', 'process': 'alphanumeric_param'
                  };
    templates.array_request("/syscollector/:agent_id/ports", req, res, "syscollector", {'agent_id': 'numbers'}, filters);
})

/**
 * @api {get} /syscollector/:agent_id/netaddr Get network address info of an agent
 * @apiName GetNetaddr_agent
 * @apiGroup Netaddr
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [q] Query to filter results by.
 * @apiParam {String} [iface] Filters by interface name.
 * @apiParam {String} [proto] Filters by proto.
 * @apiParam {String} [address] Filters by address.
 * @apiParam {String} [broadcast] Filters by broadcast.
 * @apiParam {String} [netmask] Filters by netmask.
 *
 * @apiDescription Returns the agent's network address info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/netaddr?pretty&limit=2&sort=proto"
 *
 */
router.get('/:agent_id/netaddr', function (req, res) {
   var filters = {'iface': 'alphanumeric_param', 'proto': 'alphanumeric_param', 
                  'address': 'alphanumeric_param', 'broadcast': 'alphanumeric_param',
                  'netmask': 'alphanumeric_param'
                };
    templates.array_request("/syscollector/:agent_id/netaddr", req, res, "syscollector", {'agent_id': 'numbers'}, filters);
})

/**
 * @api {get} /syscollector/:agent_id/netproto Get network protocol info of an agent
 * @apiName GetNetproto_agent
 * @apiGroup Netproto
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
* @apiParam {String} [q] Query to filter results by.
 * @apiParam {String} [iface] Filters by iface.
 * @apiParam {String} [type] Filters by type.
 * @apiParam {String} [gateway] Filters by gateway.
 * @apiParam {String} [dhcp] Filters by dhcp.
 *
 * @apiDescription Returns the agent's network protocol info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/netproto?pretty&limit=2&sort=type"
 *
 */
router.get('/:agent_id/netproto', function (req, res) {
    var filters = {'iface': 'alphanumeric_param', 'type': 'alphanumeric_param',
                   'gateway': 'alphanumeric_param', 'dhcp': 'alphanumeric_param'
                  };
    templates.array_request("/syscollector/:agent_id/netproto", req, res, "syscollector", {'agent_id': 'numbers'}, filters);
})

/**
 * @api {get} /syscollector/:agent_id/netiface Get network interface info of an agent
 * @apiName GetNetiface_agent
 * @apiGroup Netiface
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [q] Query to filter results by.
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
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/netiface?pretty&limit=2&sort=state"
 *
 */
router.get('/:agent_id/netiface', function (req, res) {
    var filters = {'name': 'alphanumeric_param', 'adapter': 'alphanumeric_param',
                   'type': 'alphanumeric_param', 'state': 'alphanumeric_param', 
                   'mtu': 'numbers', 'tx_packets': 'numbers', 'rx_packets': 'numbers', 
                   'tx_bytes': 'numbers', 'rx_bytes': 'numbers', 'tx_errors': 'numbers',
                   'rx_errors': 'numbers', 'tx_dropped': 'numbers', 'rx_dropped': 'numbers'
                  };
    templates.array_request("/syscollector/:agent_id/netiface", req, res, "syscollector", {'agent_id': 'numbers'}, filters);
})


/**
 * @api {get} /syscollector/:agent_id/hotfixes Get hotfixes info
 * @apiName GetHotfixes_agent
 * @apiGroup Hotfixes
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [q] Query to filter results by.
 * @apiParam {String} [hotfix] Filters by hotfix.
 *
 * @apiDescription Returns all hotfixes installed by Microsoft(R) in Windows(R) systems (KB... fixes)
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/001/hotfixes?pretty&limit=2"
 *
 */
router.get('/:agent_id/hotfixes', function(req, res) {
    var filters = {'hotfix': 'alphanumeric_param'};
    templates.array_request("/syscollector/:agent_id/hotfixes", req, res, "syscollector", {'agent_id': 'numbers'}, filters);
})


module.exports = router;
