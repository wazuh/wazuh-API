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
 * @api {get} /manager/config/:component/:configuration Get manager active configuration
 * @apiName GetManagerActiveConfiguration
 * @apiGroup Configuration
 *
 * @apiParam {String="agent","agentless","analysis","auth","com","csyslog","integrator","logcollector","mail","monitor","request","syscheck","wmodules"} [component] Indicates the wazuh component to check.
 * @apiParam {String="client","buffer","labels","internal","agentless","global","active_response","alerts","command","rules","decoders","internal","auth","active-response","internal","cluster","csyslog","integration","localfile","socket","remote","syscheck","rootcheck","wmodules"} [configuration] Indicates a configuration to check in the component.
 *
 * @apiDescription Returns the requested configuration in JSON format.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/config/logcollector/internal?pretty"
 *
 */
router.get('/config/:component/:configuration', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/config/:component/:configuration");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/config/:component/:configuration', 'arguments': {}};
    var filters = {'component':'names', 'configuration': 'names'};

    if (!filter.check(req.params, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['component'] = req.params.component;
    data_request['arguments']['config'] = req.params.configuration;

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
 * @apiParam {String} [q] Query to filter results by. For example q="level=info"
 *
 * @apiDescription Returns the three last months of ossec.log.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/logs?offset=0&limit=5&pretty"
 *
 */
router.get('/logs', cache(), function(req, res) {
    param_checks = {}
    query_checks = {'type_log': 'names', 'category': 'search_param'};

    templates.array_request('/manager/logs', req, res, "manager", param_checks, query_checks);
})


/**
 * @api {get} /manager/logs/summary Get summary of ossec.log
 * @apiName GetManagerLogsSummary
 * @apiGroup Logs
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
 * @api {get} /manager/files Get local file
 * @apiName GetFile
 * @apiGroup Files
 *
 * @apiParam {String} path Relative path of file. This parameter is mandatory.
 * @apiParam {Boolean} validation Validates the content of the file. An error will be returned if file content is not strictly correct. False by default.
 *
 * @apiDescription Returns the content of a local file (rules, decoders and lists).
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/files?path=etc/decoders/local_decoder.xml&pretty"
 *
 */
router.get('/files', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/files");

    var data_request = {'function': '/manager/files', 'arguments': {}};
    var filters = {'path': 'paths', 'offset': 'numbers', 'limit': 'numbers', 'validation': 'boolean'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    // check path parameter
    var local_paths = false;
    if (req.query.path) {
        if (!filter.check_path(req.query.path, req, res, local_paths)) return;
    } else {
        res_h.bad_request(req, res, 706);
    }

    data_request['arguments']['path'] = req.query.path;

    if ('validation' in req.query)
        data_request['arguments']['validation'] = req.query.validation == 'true' ? true : false;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {delete} /manager/files Delete a local file
 * @apiName DeleteManagerFiles
 * @apiGroup Files
 *
 * @apiParam {String} path Relative path of file. This parameter is mandatory.
 * 
 * @apiDescription Confirmation message.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/manager/files?path=etc/rules/local_rules.xml&pretty"
 *
 */
router.delete('/files', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " DELETE /manager/files");

    var data_request = {'function': 'DELETE/manager/files', 'arguments': {}};
    var filters = {'path': 'paths'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    // check path parameter
    var local_paths = true;
    if (req.query.path) {
        if (!filter.check_path(req.query.path, req, res, local_paths)) return;
    } else {
        res_h.bad_request(req, res, 706);
    }

    data_request['arguments']['path'] = req.query.path;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {post} /manager/files Update local file
 * @apiName PostUpdateFile
 * @apiGroup Files
 *
 * @apiParam {String} file Input file.
 * @apiParam {String} path Relative path were input file will be placed. This parameter is mandatory.
 * @apiParam {Boolean} overwrite Replaces the existing file. False by default.
 *
 * @apiDescription Upload a local file (rules, decoders and lists).
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X POST -H 'Content-type: application/xml' -d @rules.xml "https://127.0.0.1:55000/manager/files?path=etc/rules/new_rule.xml&pretty"
 *
 */
router.post('/files', function(req, res) {
    logger.debug(req.connection.remoteAddress + " POST /manager/files");

    var data_request = {'function': 'POST/manager/files', 'arguments': {}};
    var filters = {'path': 'paths', 'overwrite': 'boolean'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
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

    data_request['arguments']['path'] = req.query.path;
    data_request['arguments']['content_type'] = req.headers['content-type'];

    // optional parameters
    if ('overwrite' in req.query)
        data_request['arguments']['overwrite'] = req.query.overwrite == 'true' ? true : false;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {put} /manager/restart Restart Wazuh manager
 * @apiName PutRestartManager
 * @apiGroup Restart
 *
 * @apiDescription Restarts Wazuh Manager.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/manager/restart?pretty"
 *
 */
router.put('/restart', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /manager/restart");

    var data_request = {'function': 'PUT/manager/restart', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/configuration/validation Check Wazuh configuration
 * @apiName GetManagerConfiguration
 * @apiGroup Files
 *
 * @apiDescription Returns if Wazuh configuration is OK.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/configuration/validation?pretty"
 *
 */
router.get('/configuration/validation', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/configuration/validation");

    var data_request = {'function': '/manager/configuration/validation', 'arguments': {}};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
