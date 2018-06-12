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
 * @api {get} /ciscat/results Get cis-cat results of all agents
 * @apiName GetCiscatResults
 * @apiGroup RESULTS
 *
 * @apiDescription Returns the cis-cat results
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/ciscat/results?pretty"
 *
 */
router.get('/results', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /ciscat/results");

    var data_request = { 'function': '/ciscat/results', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'vendor': 'alphanumeric_param', 'name': 'alphanumeric_param',
        'architecture': 'alphanumeric_param', 'format': 'alphanumeric_param'
    };

    if (!filter.check(req.query, filters, req, res))
        return;

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

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /ciscat/:agent_id/results Get cis-cat results
 * @apiName GetCiscatResults
 * @apiGroup RESULTS
 *
 * @apiDescription Returns the cis-cat results
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/ciscat/001/results?pretty"
 *
 */
router.get('/:agent_id/results', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /ciscat/:agent_id/results");

    var data_request = { 'function': '/ciscat/:agent_id/results', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'vendor': 'alphanumeric_param', 'name': 'alphanumeric_param',
        'architecture': 'alphanumeric_param', 'format': 'alphanumeric_param'
    };

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['filters'] = {};
    data_request['arguments']['agent_id'] = req.params.agent_id;

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

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;