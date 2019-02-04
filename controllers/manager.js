/**
 * Wazuh RESTful API
 * Copyright (C) 2015-2019 Wazuh, Inc. All rights reserved.
 * Wazuh.com
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


var router = require('express').Router();



/**
 * @api {get} /manager/status Get manager status
 * @apiName GetManagerStatus
 * @apiGroup Info
 *
 * @apiDescription Returns the status of the manager processes.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/status?pretty"
 *
 */
router.get('/status', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/status");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/status', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/info Get manager information
 * @apiName GetManagerInfo
 * @apiGroup Info
 *
 * @apiDescription Returns basic information about manager.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/info?pretty"
 *
 */
router.get('/info', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/info");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/info', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/configuration Get manager configuration
 * @apiName GetManagerConfiguration
 * @apiGroup Configuration
 *
 * @apiParam {String} [section] Indicates the ossec.conf section: global, rules, syscheck, rootcheck, remote, alerts, command, active-response, localfile.
 * @apiParam {String} [field] Indicates a section child, e.g, fields for rule section are: include, decoder_dir, etc.
 *
 * @apiDescription Returns ossec.conf in JSON format.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/configuration?section=global&pretty"
 *
 */
router.get('/configuration', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/configuration");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/configuration', 'arguments': {}};
    var filters = {'section':'names', 'field': 'names'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

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
 * @api {get} /manager/stats Get manager stats
 * @apiName GetManagerStats
 * @apiGroup Stats
 *
 * @apiParam {String} [date] Selects the date for getting the statistical information. Format: YYYYMMDD
 *
 * @apiDescription Returns Wazuh statistical information for the current or specified date.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats?pretty"
 *
 */
router.get('/stats', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/stats', 'arguments': {}};
    var filters = {'date':'dates'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

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
 * @api {get} /manager/stats/hourly Get manager stats by hour
 * @apiName GetManagerStatsHourly
 * @apiGroup Stats
 *
 *
 * @apiDescription Returns Wazuh statistical information per hour. Each number in the averages field represents the average of alerts per hour.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats/hourly?pretty"
 *
 */
router.get('/stats/hourly', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats/hourly");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/stats/hourly', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats/weekly Get manager stats by week
 * @apiName GetManagerStatsWeekly
 * @apiGroup Stats
 *
 *
 * @apiDescription Returns Wazuh statistical information per week. Each number in the hours field represents the average alerts per hour for that specific day.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats/weekly?pretty"
 *
 */
router.get('/stats/weekly', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats/weekly");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/stats/weekly', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/logs Get ossec.log
 * @apiName GetManagerLogs
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
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/logs?offset=0&limit=5&pretty"
 *
 */
router.get('/logs', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/logs");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/logs', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'type_log':'names', 'category': 'search_param'};

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
    if ('type_log' in req.query)
        data_request['arguments']['type_log'] = req.query.type_log;
    if ('category' in req.query)
        data_request['arguments']['category'] = req.query.category;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /manager/logs/summary Get summary of ossec.log
 * @apiName GetManagerLogsSummary
 * @apiGroup Logs
 *
 *
 * @apiDescription Returns a summary of the last three months of the ``ossec.log`` file.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/logs/summary?pretty"
 *
 */
router.get('/logs/summary', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/logs/summary");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/logs/summary', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats/analysisd Get analysisd stats
 * @apiName GetAnalysisdStats
 * @apiGroup Stats
 *
 *
 * @apiDescription Returns a summary of the current analysisd stats.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats/analysisd?pretty"
 *
 */
router.get('/stats/analysisd', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats/analysisd");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/stats/analysisd', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats/remoted Get remoted stats
 * @apiName GetRemotedStats
 * @apiGroup Stats
 *
 *
 * @apiDescription Returns a summary of the current remoted stats.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats/remoted?pretty"
 *
 */
router.get('/stats/remoted', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats/remoted");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/stats/remoted', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {put} /manager/restart Restart Wazuh manager
 * @apiName PutRestartManager
 * @apiGroup Restart
 *
 * @apiDescription Restarts Wazuh Manager.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/manager/restart?pretty"
 *
 */
router.put('/restart', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /manager/restart");

    var data_request = {'function': 'PUT/manager/restart', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
