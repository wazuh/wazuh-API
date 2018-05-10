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
 * @apiGroup Syscollector
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Returns the agent's OS info
 *
 * @apiExample {curl} Example usage*:
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
 * @apiGroup Syscollector
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Returns the agent's hardware info
 *
 * @apiExample {curl} Example usage*:
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
 * @apiGroup Syscollector
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the agent's packages info
 *
 * @apiExample {curl} Example usage*:
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
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('vendor' in req.query)
        data_request['arguments']['filters']['vendor'] = req.query.vendor
    if ('name' in req.query)
        data_request['arguments']['filters']['name'] = req.query.name
    if ('architecture' in req.query)
        data_request['arguments']['filters']['architecture'] = req.query.architecture
    if ('format' in req.query)
        data_request['arguments']['filters']['format'] = req.query.format
    if ('version' in req.query)
        data_request['arguments']['filters']['version'] = req.query.version

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /syscollector/packages Get packages info of all agents
 * @apiName GetPackages
 * @apiGroup Syscollector
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the agent's packages info
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/packages?pretty&sort=-name&limit=2&offset=4"
 *
 */
router.get('/packages', function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/packages");

    var data_request = {'function': '/syscollector/packages', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param',
                   'search':'search_param', 'select':'select_param',
                    'vendor': 'alphanumeric_param', 'name': 'alphanumeric_param',
                    'architecture': 'alphanumeric_param', 'format': 'alphanumeric_param'};


    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters']  = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('vendor' in req.query)
        data_request['arguments']['filters']['vendor'] = req.query.vendor
    if ('name' in req.query)
        data_request['arguments']['filters']['name'] = req.query.name
    if ('architecture' in req.query)
        data_request['arguments']['filters']['architecture'] = req.query.architecture
    if ('format' in req.query)
        data_request['arguments']['filters']['format'] = req.query.format

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /syscollector/os Get os info of all agents
 * @apiName GetOS
 * @apiGroup Syscollector
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the agent's os info
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/os?pretty&sort=-os_name"
 *
 */
router.get('/os', function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/os");

    var data_request = {'function': '/syscollector/os', 'arguments': {}};

    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param',
                   'search':'search_param', 'select':'select_param',
                   'os_name': 'alphanumeric_param', 'architecture': 'alphanumeric_param',
                    'os_version': 'alphanumeric_parenthesis_param','release': 'alphanumeric_param' };


    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters']  = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('architecture' in req.query)
        data_request['arguments']['filters']['architecture'] = req.query.architecture
    if ('os_name' in req.query)
        data_request['arguments']['filters']['os_name'] = req.query.os_name
    if ('os_version' in req.query)
        data_request['arguments']['filters']['os_version'] = req.query.os_version
    if ('release' in req.query)
        data_request['arguments']['filters']['release'] = req.query.release


    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /syscollector/hardware Get hardware info of all agents
 * @apiName GetHardware
 * @apiGroup Syscollector
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the agent's hardware info
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscollector/hardware?pretty&sort=-ram_free"
 *
 */
router.get('/hardware', function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscollector/hardware");

    var data_request = {'function': '/syscollector/hardware', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param',
                   'search':'search_param', 'select':'select_param',
                    'ram_free': 'numbers', 'ram_total': 'numbers', 'cpu_cores': 'numbers', 'cpu_mhz': 'alphanumeric_param',
                    'board_serial': 'alphanumeric_param'};


    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters']  = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('ram_free' in req.query)
        data_request['arguments']['filters']['ram_free'] = req.query.ram_free
    if ('ram_total' in req.query)
        data_request['arguments']['filters']['ram_total'] = req.query.ram_total
    if ('cpu_cores' in req.query)
        data_request['arguments']['filters']['cpu_cores'] = req.query.cpu_cores
    if ('cpu_mhz' in req.query)
        data_request['arguments']['filters']['cpu_mhz'] = req.query.cpu_mhz
    if ('board_serial' in req.query)
        data_request['arguments']['filters']['board_serial'] = req.query.board_serial


    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
