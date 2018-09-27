/**
 * API RESTful for OSSEC
 * Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
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
 * @apiParam {String} [select] List of selected fields.
 *
 * @apiDescription Returns the agent's OS info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/os?pretty"
 *
 */
router.get('/:agent_id/os', function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/os");

    var data_request = {'function': '/syscollector/:agent_id/os', 'arguments': {}};
    var filters = {'select':'select_param'};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /syscollector/:agent_id/hardware Get hardware info
 * @apiName GetHardware_agent
 * @apiGroup Hardware
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {String} [select] List of selected fields.
 *
 * @apiDescription Returns the agent's hardware info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/hardware?pretty"
 *
 */
router.get('/:agent_id/hardware', function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/hardware");

    var data_request = {'function': '/syscollector/:agent_id/hardware', 'arguments': {}};

    var filters = {'select':'select_param'};


    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters']  = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)


    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
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
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [vendor] Filters by vendor.
 * @apiParam {String} [name] Filters by name.
 * @apiParam {String} [architecture] Filters by architecture.
 * @apiParam {String} [format] Filters by format.
 * @apiParam {String} [version] Filters by version.
 *
 * @apiDescription Returns the agent's packages info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/packages?pretty&limit=2&offset=10&sort=-name"
 *
 */
router.get('/:agent_id/packages', function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/packages");

    var data_request = {'function': '/syscollector/:agent_id/packages', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param',
                   'search':'search_param', 'select':'select_param',
                    'vendor': 'alphanumeric_param', 'name': 'alphanumeric_param',
                    'architecture': 'alphanumeric_param', 'format': 'alphanumeric_param', 'version' : 'alphanumeric_param'};


    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters']  = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('vendor' in req.query)
        data_request['arguments']['filters']['vendor'] = req.query.vendor;
    if ('name' in req.query)
        data_request['arguments']['filters']['name'] = req.query.name;
    if ('architecture' in req.query)
        data_request['arguments']['filters']['architecture'] = req.query.architecture;
    if ('format' in req.query)
        data_request['arguments']['filters']['format'] = req.query.format;
    if ('version' in req.query)
        data_request['arguments']['filters']['version'] = req.query.version;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
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
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {Number} [pid] Filters by process pid.
 * @apiParam {String} [egroup] Filters by process egroup.
 * @apiParam {String} [euser] Filters by process euser.
 * @apiParam {String} [fgroup] Filters by process fgroup.
 * @apiParam {Number} [nlwp] Filters by process nlwp.
 * @apiParam {Number} [pgrp] Filters by process pgrp.
 * @apiParam {Number} [priority] Filters by process priority.
 * @apiParam {String} [rgroup] Filters by process rgroup.
 * @apiParam {String} [ruser] Filters by process ruser.
 * @apiParam {String} [sgroup] Filters by process sgroup.
 * @apiParam {String} [suser] Filters by process suser.
 *
 * @apiDescription Returns the agent's processes info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/processes?pretty&limit=2&offset=10&sort=-name"
 *
 */
router.get('/:agent_id/processes', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/processes");

    var data_request = { 'function': '/syscollector/:agent_id/processes', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'pid': 'numbers', 'state': 'alphanumeric_param', 'ppid': 'numbers',
        'egroup': 'alphanumeric_param',
        'euser': 'alphanumeric_param', 'fgroup': 'alphanumeric_param',
        'name': 'alphanumeric_param', 'nlwp': 'numbers',
        'pgrp': 'numbers', 'priority': 'numbers',
        'rgroup': 'alphanumeric_param', 'ruser': 'alphanumeric_param',
        'sgroup': 'alphanumeric_param', 'suser': 'alphanumeric_param'
    };


    if (!filter.check(req.params, { 'agent_id': 'numbers' }, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('state' in req.query)
        data_request['arguments']['filters']['state'] = req.query.state;
    if ('pid' in req.query)
        data_request['arguments']['filters']['pid'] = req.query.pid;
    if ('egroup' in req.query)
        data_request['arguments']['filters']['egroup'] = req.query.egroup;
    if ('euser' in req.query)
        data_request['arguments']['filters']['euser'] = req.query.euser;
    if ('fgroup' in req.query)
        data_request['arguments']['filters']['fgroup'] = req.query.fgroup;
    if ('nlwp' in req.query)
        data_request['arguments']['filters']['nlwp'] = req.query.nlwp;
    if ('name' in req.query)
        data_request['arguments']['filters']['name'] = req.query.name;
    if ('pgrp' in req.query)
        data_request['arguments']['filters']['pgrp'] = req.query.pgrp;
    if ('priority' in req.query)
        data_request['arguments']['filters']['priority'] = req.query.priority;
    if ('rgroup' in req.query)
        data_request['arguments']['filters']['rgroup'] = req.query.rgroup;
    if ('ruser' in req.query)
        data_request['arguments']['filters']['ruser'] = req.query.ruser;
    if ('sgroup' in req.query)
        data_request['arguments']['filters']['sgroup'] = req.query.sgroup;
    if ('suser' in req.query)
        data_request['arguments']['filters']['suser'] = req.query.suser;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
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
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {Number} [pid] Filters by pid.
 * @apiParam {String} [protocol] Filters by protocol.
 * @apiParam {String} [local_ip] Filters by local_ip.
 * @apiParam {Number} [local_port] Filters by local_port.
 * @apiParam {String} [remote_ip] Filters by remote_ip.
 * @apiParam {Number} [tx_queue] Filters by tx_queue.
 * @apiParam {String} [state] Filters by state.
 *
 * @apiDescription Returns the agent's ports info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/ports?pretty&sort=-protocol&limit=2"
 *
 */
router.get('/:agent_id/ports', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/ports");

    var data_request = { 'function': '/syscollector/:agent_id/ports', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'protocol': 'alphanumeric_param', 'local_ip': 'alphanumeric_param',
        'local_port': 'numbers', 'remote_ip': 'alphanumeric_param',
        'tx_queue': 'numbers', 'state': 'alphanumeric_param',
        'pid': 'numbers', 'process': 'alphanumeric_param'
    };

    if (!filter.check(req.params, { 'agent_id': 'numbers' }, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('protocol' in req.query)
        data_request['arguments']['filters']['protocol'] = req.query.protocol;
    if ('local_ip' in req.query)
        data_request['arguments']['filters']['local_ip'] = req.query.local_ip;
    if ('local_port' in req.query)
        data_request['arguments']['filters']['local_port'] = req.query.local_port;
    if ('remote_ip' in req.query)
        data_request['arguments']['filters']['remote_ip'] = req.query.remote_ip;
    if ('remote_port' in req.query)
        data_request['arguments']['filters']['remote_port'] = req.query.remote_port;
    if ('tx_queue' in req.query)
        data_request['arguments']['filters']['tx_queue'] = req.query.tx_queue;
    if ('state' in req.query)
        data_request['arguments']['filters']['state'] = req.query.state;
    if ('pid' in req.query)
        data_request['arguments']['filters']['pid'] = req.query.pid;
    if ('process' in req.query)
        data_request['arguments']['filters']['process'] = req.query.process;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /syscollector/:agent_id/netaddr Get network address info of an agent
 * @apiName GetNetaddr_agent
 * @apiGroup Netaddr
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [id] Filters by id.
 * @apiParam {String} [proto] Filters by proto.
 * @apiParam {String} [address] Filters by address.
 * @apiParam {String} [broadcast] Filters by broadcast.
 * @apiParam {String} [netmask] Filters by netmask.
 *
 * @apiDescription Returns the agent's network address info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/netaddr?pretty&limit=2&sort=proto"
 *
 */
router.get('/:agent_id/netaddr', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/netaddr");

    var data_request = { 'function': '/syscollector/:agent_id/netaddr', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'proto': 'alphanumeric_param', 'address': 'alphanumeric_param',
        'broadcast': 'alphanumeric_param', 'netmask': 'alphanumeric_param',
        'id': 'numbers'
    };

    if (!filter.check(req.params, { 'agent_id': 'numbers' }, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('proto' in req.query)
        data_request['arguments']['filters']['proto'] = req.query.proto;
    if ('address' in req.query)
        data_request['arguments']['filters']['address'] = req.query.address;
    if ('broadcast' in req.query)
        data_request['arguments']['filters']['broadcast'] = req.query.broadcast;
    if ('netmask' in req.query)
        data_request['arguments']['filters']['netmask'] = req.query.netmask;
    if ('id' in req.query)
        data_request['arguments']['filters']['id'] = req.query.id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /syscollector/:agent_id/netproto Get network protocol info of an agent
 * @apiName GetNetproto_agent
 * @apiGroup Netproto
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [id] Filters by id.
 * @apiParam {String} [iface] Filters by iface.
 * @apiParam {String} [type] Filters by type.
 * @apiParam {String} [gateway] Filters by gateway.
 * @apiParam {String} [dhcp] Filters by dhcp.
 *
 * @apiDescription Returns the agent's network protocol info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/netproto?pretty&limit=2&sort=type"
 *
 */
router.get('/:agent_id/netproto', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/netproto");

    var data_request = { 'function': '/syscollector/:agent_id/netproto', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'iface': 'alphanumeric_param', 'type': 'alphanumeric_param',
        'gateway': 'alphanumeric_param', 'dhcp': 'alphanumeric_param',
        'id': 'numbers'
    };

    if (!filter.check(req.params, { 'agent_id': 'numbers' }, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('iface' in req.query)
        data_request['arguments']['filters']['iface'] = req.query.iface;
    if ('type' in req.query)
        data_request['arguments']['filters']['type'] = req.query.type;
    if ('gateway' in req.query)
        data_request['arguments']['filters']['gateway'] = req.query.gateway;
    if ('dhcp' in req.query)
        data_request['arguments']['filters']['dhcp'] = req.query.dhcp;
    if ('id' in req.query)
        data_request['arguments']['filters']['id'] = req.query.id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /syscollector/:agent_id/netiface Get network interface info of an agent
 * @apiName GetNetiface_agent
 * @apiGroup Netiface
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [id] Filters by id.
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
 * @apiDescription Returns the agent's network interface info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/netiface?pretty&limit=2&sort=state"
 *
 */
router.get('/:agent_id/netiface', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/netiface");

    var data_request = { 'function': '/syscollector/:agent_id/netiface', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'id': 'numbers', 'name': 'alphanumeric_param',
        'adapter': 'alphanumeric_param', 'type': 'alphanumeric_param',
        'state': 'alphanumeric_param', 'mtu': 'numbers',
        'tx_packets': 'numbers', 'rx_packets': 'numbers', 'tx_bytes': 'numbers',
        'rx_bytes': 'numbers', 'tx_errors': 'numbers',
        'rx_errors': 'numbers', 'tx_dropped': 'numbers',
        'rx_dropped': 'numbers'
    };

    if (!filter.check(req.params, { 'agent_id': 'numbers' }, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('id' in req.query)
        data_request['arguments']['filters']['id'] = req.query.id;
    if ('name' in req.query)
        data_request['arguments']['filters']['name'] = req.query.name;
    if ('adapter' in req.query)
        data_request['arguments']['filters']['adapter'] = req.query.adapter;
    if ('type' in req.query)
        data_request['arguments']['filters']['type'] = req.query.type;
    if ('state' in req.query)
        data_request['arguments']['filters']['state'] = req.query.state;
    if ('mtu' in req.query)
        data_request['arguments']['filters']['mtu'] = req.query.mtu;
    if ('tx_packets' in req.query)
        data_request['arguments']['filters']['tx_packets'] = req.query.tx_packets;
    if ('rx_packets' in req.query)
        data_request['arguments']['filters']['rx_packets'] = req.query.rx_packets;
    if ('tx_bytes' in req.query)
        data_request['arguments']['filters']['tx_bytes'] = req.query.tx_bytes;
    if ('rx_bytes' in req.query)
        data_request['arguments']['filters']['rx_bytes'] = req.query.rx_bytes;
    if ('tx_errors' in req.query)
        data_request['arguments']['filters']['tx_errors'] = req.query.tx_errors;
    if ('rx_errors' in req.query)
        data_request['arguments']['filters']['rx_errors'] = req.query.rx_errors;
    if ('tx_dropped' in req.query)
        data_request['arguments']['filters']['tx_dropped'] = req.query.tx_dropped;
    if ('rx_dropped' in req.query)
        data_request['arguments']['filters']['rx_dropped'] = req.query.rx_dropped;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /syscollector/:agent_id/network Get network interface info of an agent
 * @apiName GetNetwork
 * @apiGroup Network
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [id] Filters by id.
 * @apiParam {String} [scan_id] Filters by scan_id
 * @apiParam {String} [proto] Filters by proto
 * @apiParam {String} [address] Filters by address
 * @apiParam {String} [netmask] Filters by netmask
 * @apiParam {String} [broadcast] Filters by broadcast
 * @apiParam {String} [iface] Filters by iface
 * @apiParam {String} [type] Filters by type
 * @apiParam {String} [gateway] Filters by gateway
 * @apiParam {String} [dhcp] Filters by dhcp
 * @apiParam {String} [scan_time] Filters by scan_time
 * @apiParam {String} [name] Filters by name.
 * @apiParam {String} [adapter] Filters by adapter.
 * @apiParam {String} [state] Filters by state.
 * @apiParam {String} [mtu] Filters by mtu.
 * @apiParam {String} [mac] Filters by mac.
 * @apiParam {String} [tx_packets] Filters by tx_packets.
 * @apiParam {String} [rx_packets] Filters by rx_packets.
 * @apiParam {String} [tx_bytes] Filters by tx_bytes.
 * @apiParam {String} [rx_bytes] Filters by rx_bytes.
 * @apiParam {String} [tx_errors] Filters by tx_errors.
 * @apiParam {String} [rx_errors] Filters by rx_errors.
 * @apiParam {String} [tx_dropped] Filters by tx_dropped.
 * @apiParam {String} [rx_dropped] Filters by rx_dropped.
 *
 * @apiDescription Returns the agent's network interface info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/000/network?pretty&limit=2&sort=state"
 *
 */
router.get('/:agent_id/network', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/:agent_id/network");

    var data_request = { 'function': '/syscollector/:agent_id/network', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'id': 'numbers', 'scan_id': 'numbers', 'proto': 'alphanumeric_param',
        'address': 'alphanumeric_param', 'netmask': 'alphanumeric_param',
        'broadcast': 'alphanumeric_param', 'iface': 'alphanumeric_param',
        'type': 'alphanumeric_param', 'gateway': 'alphanumeric_param',
        'dhcp': 'alphanumeric_param', 'scan_time': 'alphanumeric_param',
        'name': 'alphanumeric_param', 'adapter': 'alphanumeric_param', 'state': 'alphanumeric_param',
        'mtu': 'numbers', 'mac': 'alphanumeric_param', 'tx_packets': 'numbers',
        'rx_packets': 'numbers', 'tx_bytes': 'numbers', 'rx_bytes': 'numbers',
        'tx_errors': 'numbers', 'rx_errors': 'numbers', 'tx_dropped': 'numbers',
        'rx_dropped': 'numbers'
    };

    if (!filter.check(req.params, { 'agent_id': 'numbers' }, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('id' in req.query)
        data_request['arguments']['filters']['id'] = req.query.id;        
    if ('scan_id' in req.query)
        data_request['arguments']['filters']['scan_id'] = req.query.scan_id;   
    if ('proto' in req.query)
        data_request['arguments']['filters']['proto'] = req.query.proto;
    if ('address' in req.query)
        data_request['arguments']['filters']['address'] = req.query.address;
    if ('netmask' in req.query)
        data_request['arguments']['filters']['netmask'] = req.query.netmask;
    if ('broadcast' in req.query)
        data_request['arguments']['filters']['broadcast'] = req.query.broadcast;
    if ('iface' in req.query)
        data_request['arguments']['filters']['iface'] = req.query.iface;    
    if ('gateway' in req.query)
        data_request['arguments']['filters']['gateway'] = req.query.gateway; 
    if ('dhcp' in req.query)
        data_request['arguments']['filters']['dhcp'] = req.query.dhcp;
    if ('scan_time' in req.query)
        data_request['arguments']['filters']['scan_time'] = req.query.scan_time;        
    if ('name' in req.query)
        data_request['arguments']['filters']['name'] = req.query.name;
    if ('adapter' in req.query)
        data_request['arguments']['filters']['adapter'] = req.query.adapter;
    if ('type' in req.query)
        data_request['arguments']['filters']['type'] = req.query.type;
    if ('state' in req.query)
        data_request['arguments']['filters']['state'] = req.query.state;
    if ('mtu' in req.query)
        data_request['arguments']['filters']['mtu'] = req.query.mtu;
    if ('mac' in req.query)
        data_request['arguments']['filters']['mac'] = req.query.mac;  /// this param is not present in the others calls
    if ('tx_packets' in req.query)
        data_request['arguments']['filters']['tx_packets'] = req.query.tx_packets;
    if ('rx_packets' in req.query)
        data_request['arguments']['filters']['rx_packets'] = req.query.rx_packets;
    if ('tx_bytes' in req.query)
        data_request['arguments']['filters']['tx_bytes'] = req.query.tx_bytes;
    if ('rx_bytes' in req.query)
        data_request['arguments']['filters']['rx_bytes'] = req.query.rx_bytes;
    if ('tx_errors' in req.query)
        data_request['arguments']['filters']['tx_errors'] = req.query.tx_errors;
    if ('rx_errors' in req.query)
        data_request['arguments']['filters']['rx_errors'] = req.query.rx_errors;
    if ('tx_dropped' in req.query)
        data_request['arguments']['filters']['tx_dropped'] = req.query.tx_dropped;
    if ('rx_dropped' in req.query)
        data_request['arguments']['filters']['rx_dropped'] = req.query.rx_dropped;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


module.exports = router;
