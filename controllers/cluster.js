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
 * @api {get} /cluster/node Get local node info
 * @apiName GetLocalNodeInfo
 * @apiGroup Nodes
 *
 * @apiDescription Returns the local node info.
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
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [type] Filters by node type.
 * @apiParam {String} [q] Query to filter results by. For example q="name=worker-1"
 * 
 * @apiDescription Returns the nodes info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/nodes?pretty"
 *
 */
router.get('/nodes', cache(), function(req, res) {
    param_checks = {}
    query_checks = {'type': 'alphanumeric_param'};

    templates.array_request('/cluster/nodes', req, res, "cluster", param_checks, query_checks);
})


/**
 * @api {get} /cluster/nodes/:node_name Get node info
 * @apiName GetNodeInfo
 * @apiGroup Nodes
 *
 * @apiDescription Returns the node info.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/nodes/master?pretty"
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
 * 
 * @apiDescription Show cluster health.
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
 * @apiDescription Returns whether the cluster is enabled or disabled.
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
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/worker-1/status?pretty"
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
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/worker-1/info?pretty"
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
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/worker-1/configuration?section=global&pretty"
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
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/worker-1/stats?pretty"
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
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/worker-1/stats/hourly?pretty"
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
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/worker-1/stats/weekly?pretty"
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
 * @api {get} /cluster/:node_id/stats/analysisd Get node node_id's analysisd stats
 * @apiName GetManagerStatsAnalysisdCluster
 * @apiGroup Stats
 * 
 * 
 * @apiDescription Returns a summary of the current analysisd stats on the node.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/worker-1/stats/analysisd?pretty"
 *
 */
router.get('/:node_id/stats/analysisd', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/stats/analysisd");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/:node_id/stats/analysisd', 'arguments': {}};

    if (!filter.check(req.params, {'node_id':'names'}, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/:node_id/stats/remoted Get node node_id's remoted stats
 * @apiName GetManagerStatsRemotedCluster
 * @apiGroup Stats
 *
 *
 * @apiDescription Returns a summary of the current remoted stats on the node.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/worker-1/stats/remoted?pretty"
 *
 */
router.get('/:node_id/stats/remoted', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/stats/remoted");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/:node_id/stats/remoted', 'arguments': {}};

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
 * @apiParam {String} [q] Query to filter results by. For example q="level=info"
 *
 * @apiDescription Returns the three last months of ossec.log.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/worker-1/logs?offset=0&limit=5&pretty"
 *
 */
router.get('/:node_id/logs', cache(), function(req, res) {
    param_checks = {'node_id': 'names'};
    query_checks = {'type_log': 'names', 'category': 'search_param'};

    templates.array_request('/cluster/:node_id/logs', req, res, "cluster", param_checks, query_checks);
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
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/worker-1/logs/summary?pretty"
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

/**
 * @api {get} /cluster/:node_id/files Get local file from any cluster node
 * @apiName GetFileCluster
 * @apiGroup Files
 *
 * @apiParam {String} path Relative path of file. This parameter is mandatory.
 * @apiParam {Boolean} validation Validates the content of the file. An error will be returned if file content is not strictly correct. False by default.
 *
 * @apiDescription Returns the content of a local file (rules, decoders and lists).
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/master/files?path=etc/decoders/local_decoder.xml&pretty"
 *
 */
router.get('/:node_id/files', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/files");

    var data_request = {'function': '/cluster/:node_id/files', 'arguments': {}};
    var filters_param = {'node_id': 'names'};
    var filters_query = {'path': 'paths', 'offset': 'numbers', 'limit': 'numbers', 'validation': 'boolean'};

    if (!filter.check(req.params, filters_param, req, res))  // Filter with error (param)
        return;

    if (!filter.check(req.query, filters_query, req, res))  // Filter with error (query)
        return;

    // check path parameter
    var local_paths = false;
    if (req.query.path) {
        if (!filter.check_path(req.query.path, req, res, local_paths)) return;
    } else {
        res_h.bad_request(req, res, 706);
    }

    data_request['arguments']['node_id'] = req.params.node_id;
    data_request['arguments']['path'] = req.query.path;

    if ('validation' in req.query)
        data_request['arguments']['validation'] = req.query.validation == 'true' ? true : false;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {post} /cluster/:node_id/files Update local file at any cluster node
 * @apiName PostUpdateFileCluster
 * @apiGroup Files
 *
 * @apiParam {String} file Input file.
 * @apiParam {String} path Relative path were input file will be placed. This parameter is mandatory.
 * @apiParam {Boolean} overwrite Replaces the existing file. False by default.
 *
 * @apiDescription Upload a local file (rules, decoders and lists) in a cluster node.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X POST -H 'Content-type: application/xml' -d @rules.xml "https://127.0.0.1:55000/cluster/master/files?path=etc/rules/local_rules.xml&pretty"
 *
 */
router.post('/:node_id/files', function(req, res) {
    logger.debug(req.connection.remoteAddress + " POST /cluster/:node_id/files");

    var data_request = {'function': 'POST/cluster/:node_id/files', 'arguments': {}};
    var filters_param = {'node_id': 'names'};
    var filters_query = {'path': 'paths', 'overwrite': 'boolean'};

    if (!filter.check(req.params, filters_param, req, res))  // Filter with error (params)
        return;

    if (!filter.check(req.query, filters_query, req, res))  // Filter with error (query)
        return;

    // check path parameter
    var local_paths = true;
    if (req.query.path) {
        if (!filter.check_path(req.query.path, req, res, local_paths)) return;
    } else {
        res_h.bad_request(req, res, 706);
        return;
    }

    if (req.headers['content-type'] == 'application/octet-stream' || req.headers['content-type'] == 'application/xml') {
        if ((req.headers['content-type'] == 'application/octet-stream' && !filter.check_cdb_list(req.body.toString('utf8'), req, res)) ||
            (req.headers['content-type'] == 'application/xml' && !filter.check_xml(req.body, req, res)))
            return;

        try {
            data_request['arguments']['tmp_file'] = require('../helpers/files').tmp_file_creator(req.body);
        } catch(err) {
            res_h.bad_request(req, res, 702, err);
            return;
        }
    } else {
        res_h.bad_request(req, res, 804, req.headers['content-type']);
        return;
    }


    data_request['arguments']['node_id'] = req.params.node_id;
    data_request['arguments']['path'] = req.query.path;
    data_request['arguments']['content_type'] = req.headers['content-type'];

    // optional parameters
    if ('overwrite' in req.query)
        data_request['arguments']['overwrite'] = req.query.overwrite == 'true' ? true : false;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {delete} /cluster/:node_id/files Delete a remote file in a cluster node
 * @apiName DeleteClusterFiles
 * @apiGroup Files
 *
 * @apiParam {String} path Relative path of file. This parameter is mandatory.
 * 
 * @apiDescription Confirmation message.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/cluster/master/files?path=etc/rules/local_rules.xml&pretty"
 *
 */
router.delete('/:node_id/files', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " DELETE /cluster/:node_id/files");

    var data_request = {'function': 'DELETE/cluster/:node_id/files', 'arguments': {}};
    var filters_query = {'path': 'paths'};
    var filters_param = {'node_id': 'names'};

    if (!filter.check(req.query, filters_query, req, res))  // Filter with error
        return;

    if (!filter.check(req.params, filters_param, req, res))  // Filter with error (params)
        return;

    // check path parameter
    var local_paths = true;
    if (req.query.path) {
        if (!filter.check_path(req.query.path, req, res, local_paths)) return;
    } else {
        res_h.bad_request(req, res, 706);
    }

    data_request['arguments']['path'] = req.query.path;
    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {put} /cluster/restart Restart all nodes in cluster
 * @apiName PutRestartCluster
 * @apiGroup Restart
 *
 * @apiDescription Restarts all nodes in cluster.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/cluster/restart?pretty"
 *
 */
router.put('/restart', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /cluster/restart");

    var data_request = {'function': 'PUT/cluster/restart', 'arguments': {}};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/configuration/validation Check Wazuh configuration in all cluster nodes
 * @apiName GetClusterConfiguration
 * @apiGroup Files
 *
 * @apiDescription Returns if Wazuh configuration is OK.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/configuration/validation?pretty"
 *
 */
router.get('/configuration/validation', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/configuration/validation");

    var data_request = {'function': '/cluster/configuration/validation', 'arguments': {}};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {put} /cluster/:node_id/restart Restart a specific node in cluster
 * @apiName PutRestartClusterNode
 * @apiGroup Restart
 *
 * @apiDescription Restarts a specific node in cluster.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/cluster/worker-1/restart?pretty"
 *
 */
router.put('/:node_id/restart', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /cluster/:node_id/restart");

    var data_request = {'function': 'PUT/cluster/:node_id/restart', 'arguments': {}};

    if (!filter.check(req.params, {'node_id':'names'}, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/:node_id/configuration/validation Check Wazuh configuration in a cluster node
 * @apiName GetClusterNodeConfiguration
 * @apiGroup Files
 *
 * @apiDescription Returns if Wazuh configuration is OK.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/master/configuration/validation?pretty"
 *
 */
router.get('/:node_id/configuration/validation', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/configuration/validation");

    var data_request = {'function': '/cluster/:node_id/configuration/validation', 'arguments': {}};
    var filters_param = {'node_id': 'names'};

    if (!filter.check(req.params, filters_param, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/:node_id/config/:component/:configuration Get active configuration in node node_id
 * @apiName GetClusterNodeActiveConfiguration
 * @apiGroup Configuration
 *
 * @apiParam {String="agent","agentless","analysis","auth","com","csyslog","integrator","logcollector","mail","monitor","request","syscheck","wmodules"} [component] Indicates the wazuh component to check.
 * @apiParam {String="client","buffer","labels","internal","agentless","global","active_response","alerts","command","rules","decoders","internal","auth","active-response","internal","cluster","csyslog","integration","localfile","socket","remote","syscheck","rootcheck","wmodules"} [configuration] Indicates a configuration to check in the component.
 *
 * @apiDescription Returns the requested configuration in JSON format.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/master/config/logcollector/internal?pretty"
 *
 */
router.get('/:node_id/config/:component/:configuration', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/:node_id/config/:component/:configuration");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/:node_id/config/:component/:configuration', 'arguments': {}};
    var filters = {'component':'names', 'configuration': 'names', 'node_id': 'names'};

    if (!filter.check(req.params, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['component'] = req.params.component;
    data_request['arguments']['config'] = req.params.configuration;
    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
