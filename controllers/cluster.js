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
 * @api {get} /cluster/node Get local node info
 * @apiName GetLocalNodeInfo
 * @apiGroup Nodes
 *
 * @apiDescription Returns the local node info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node?pretty"
 *
 */
router.get('/node', cache(), function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/node");
    req.apicacheGroup = "cluster";

    var data_request = { 'function': '/cluster/node', 'arguments': {} };

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/nodes Get nodes info
 * @apiName GetNodesInfo
 * @apiGroup Nodes
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [type] Filters by node type.
 * *
 * @apiDescription Returns the nodes info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/nodes?pretty"
 *
 */
router.get('/nodes', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/nodes");

    req.apicacheGroup = "cluster";

    var data_request = { 'function': '/cluster/nodes', 'arguments': {} };
    var filters = { 'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'type': 'alphanumeric_param', 'select': 'select_param' }

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('type' in req.query)
        data_request['arguments']['filter_type'] = req.query.type
    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select);

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /cluster/nodes/:node_name Get node info
 * @apiName GetNodeInfo
 * @apiGroup Nodes
 *
 * @apiDescription Returns the node info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/nodes/node01?pretty"
 *
 */
router.get('/nodes/:node_name', cache(), function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/nodes/:node_name");
    req.apicacheGroup = "cluster";

    var data_request = { 'function': '/cluster/nodes/:node_name', 'arguments': {} };
    var filters = {
        'select': 'select_param'
    }

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;
    if (!filter.check(req.params, { 'node_name': 'names' }, req, res))  // Filter with error
        return;

    data_request['arguments']['filter_node'] = req.params.node_name;
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /cluster/healthcheck Show cluster health
 * @apiName GetHealthcheck
 * @apiGroup Info
 *
 * @apiParam {String} [node] Filter information by node name.
 * *
 * @apiDescription Show cluster health
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/healthcheck?pretty"
 *
 */
router.get('/healthcheck', cache(), function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/healthcheck");

    req.apicacheGroup = "cluster";

    var data_request = { 'function': '/cluster/healthcheck', 'arguments': {} };
    var filters = { 'node': 'names' };

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['filter_node'] = req.query.node;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /cluster/status Get info about cluster status
 * @apiName GetClusterstatus
 * @apiGroup Info
 *
 * @apiDescription Returns whether the cluster is enabled or disabled
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/status?pretty"
 *
 */
router.get('/status', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/status");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/status', 'arguments': {}};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/config Get the cluster configuration
 * @apiName GetClusterconfig
 * @apiGroup Configuration
 *
 * @apiDescription Returns the cluster configuration
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/config?pretty"
 *
 */
router.get('/config', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/config");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/config', 'arguments': {}};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/:node_id/status Get node node_id's status
 * @apiName GetManagerStatus
 * @apiGroup Info
 *
 * @apiDescription Returns the status of the manager processes.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node02/status?pretty"
 *
 */
router.get('/:node_id/status', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/status");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/:node_id/status', 'arguments': {}};

    if (!filter.check(req.params, {'node_id':'names'}, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/:node_id/info Get node_id's information
 * @apiName GetManagerInfo
 * @apiGroup Info
 *
 * @apiDescription Returns basic information about manager.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node02/info?pretty"
 *
 */
router.get('/:node_id/info', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/info");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/:node_id/info', 'arguments': {}};

    if (!filter.check(req.params, {'node_id':'names'}, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/:node_id/configuration Get node node_id's configuration
 * @apiName GetManagerConfiguration
 * @apiGroup Configuration
 *
 * @apiParam {String} [section] Indicates the ossec.conf section: global, rules, syscheck, rootcheck, remote, alerts, command, active-response, localfile.
 * @apiParam {String} [field] Indicates a section child, e.g, fields for rule section are: include, decoder_dir, etc.
 *
 * @apiDescription Returns ossec.conf in JSON format.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node02/configuration?section=global&pretty"
 *
 */
router.get('/:node_id/configuration', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/configuration");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/:node_id/configuration', 'arguments': {}};
    var filters = {'section':'names', 'field': 'names', 'node_id': 'names'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    if ('section' in req.query)
        data_request['arguments']['section'] = req.query.section;
    if ('field' in req.query){
        if ('section' in req.query)
            data_request['arguments']['field'] = req.query.field;
        else
            res_h.bad_request(req, res, 604, "Missing field: 'section'");
    }
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/:node_id/stats Get node node_id's stats
 * @apiName GetManagerStatsCluster
 * @apiGroup Stats
 *
 * @apiParam {String} [date] Selects the date for getting the statistical information. Format: YYYYMMDD
 *
 * @apiDescription Returns Wazuh statistical information for the current or specified date.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node02/stats?pretty"
 *
 */
router.get('/:node_id/stats', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/stats");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/:node_id/stats', 'arguments': {}};
    var filters = {'date':'dates', 'node_id': 'names'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    if ('date' in req.query){
        data_request['arguments']['year'] = req.query.date.substring(0, 4);
        data_request['arguments']['month'] = req.query.date.substring(4, 6);
        data_request['arguments']['day'] = req.query.date.substring(6, 8);
    }
    else{
        var moment = require('moment');
        date = moment().format('YYYYMMDD')
        data_request['arguments']['year'] = date.substring(0, 4);
        data_request['arguments']['month'] = date.substring(4, 6);
        data_request['arguments']['day'] = date.substring(6, 8);
    }

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/:node_id/stats/hourly Get node node_id's stats by hour
 * @apiName GetManagerStatsHourlyCluster
 * @apiGroup Stats
 *
 *
 * @apiDescription Returns Wazuh statistical information per hour. Each number in the averages field represents the average of alerts per hour.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node02/stats/hourly?pretty"
 *
 */
router.get('/:node_id/stats/hourly', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/stats/hourly");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/:node_id/stats/hourly', 'arguments': {}};

    if (!filter.check(req.params, {'node_id':'names'}, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/:node_id/stats/weekly Get node node_id's stats by week
 * @apiName GetManagerStatsWeeklyCluster
 * @apiGroup Stats
 *
 *
 * @apiDescription Returns Wazuh statistical information per week. Each number in the hours field represents the average alerts per hour for that specific day.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node02/stats/weekly?pretty"
 *
 */
router.get('/:node_id/stats/weekly', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/stats/weekly");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/:node_id/stats/weekly', 'arguments': {}};

    if (!filter.check(req.params, {'node_id':'names'}, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/:node_id/logs Get ossec.log from a specific node in cluster.
 * @apiName GetManagerLogsCluster
 * @apiGroup Logs
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String="all","error", "warning", "info"} [type_log] Filters by type of log.
 * @apiParam {String} [category] Filters by category of log.
 *
 * @apiDescription Returns the three last months of ossec.log.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node02/logs?offset=0&limit=5&pretty"
 *
 */
router.get('/:node_id/logs', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/logs");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/:node_id/logs', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param',
                   'search':'search_param', 'type_log':'names',
                   'category': 'search_param', 'node_id':'names'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('type_log' in req.query)
        data_request['arguments']['type_log'] = req.query.type_log;
    if ('category' in req.query)
        data_request['arguments']['category'] = req.query.category;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/:node_id/logs/summary Get summary of ossec.log from a specific node in cluster.
 * @apiName GetManagerLogsSummaryCluster
 * @apiGroup Logs
 *
 *
 * @apiDescription Returns a summary of the last three months of the ``ossec.log`` file.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node02/logs/summary?pretty"
 *
 */
router.get('/:node_id/logs/summary', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/logs/summary");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/:node_id/logs/summary', 'arguments': {}};

    if (!filter.check(req.params, {'node_id':'names'}, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


module.exports = router;
