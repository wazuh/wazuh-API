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
 * @api {get} /syscheck/:agent_id Get syscheck files
 * @apiName GetSyscheckAgent
 * @apiGroup Info
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String="added","readded", "modified", "deleted"} [event] Filters files by event.
 * @apiParam {String} [file] Filters file by filename.
 * @apiParam {String="file","registry"} [filetype] Selects type of file.
 * @apiParam {String="yes", "no"} [summary] Returns a summary grouping by filename.
 * @apiParam {String} [md5] Returns the files with the specified md5 hash.
 * @apiParam {String} [sha1] Returns the files with the specified sha1 hash.
 * @apiParam {String} [hash] Returns the files with the specified hash (md5 or sha1).
 *
 * @apiDescription Returns the syscheck files of an agent.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscheck/000?offset=0&limit=2&pretty"
 *
 */
router.get('/:agent_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscheck/:agent_id");

    req.apicacheGroup = "syscheck";

    var data_request = {'function': '/syscheck/:agent_id', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'event':'names', 'file':'paths', 'filetype':'names', 'summary':'names', 'md5':'hashes', 'sha1':'hashes', 'hash':'hashes'};

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
    if ('event' in req.query)
        data_request['arguments']['event'] = req.query.event;
    if ('file' in req.query)
        data_request['arguments']['filename'] = req.query.file;
    if ('filetype' in req.query)
        data_request['arguments']['filetype'] = req.query.filetype;
    if ('summary' in req.query && req.query.summary == "yes")
        data_request['arguments']['summary'] = req.query.summary;
    if ('md5' in req.query)
        data_request['arguments']['md5'] = req.query.md5.toLowerCase();
    if ('sha1' in req.query)
        data_request['arguments']['sha1'] = req.query.sha1.toLowerCase();
    if ('hash' in req.query)
        data_request['arguments']['hash'] = req.query.hash.toLowerCase();


    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /syscheck/:agent_id/last_scan Get last syscheck scan
 * @apiName GetSyscheckAgentLastScan
 * @apiGroup Info
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Return the timestamp of the last syscheck scan.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/syscheck/000/last_scan?pretty"
 *
 */
router.get('/:agent_id/last_scan', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /syscheck/:agent_id/last_scan");

    req.apicacheGroup = "syscheck";

    var data_request = {'function': '/syscheck/:agent_id/last_scan', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {put} /syscheck Run syscheck scan in all agents
 * @apiName PutSyscheck
 * @apiGroup Run
 *
 *
 * @apiDescription Runs syscheck and rootcheck on all agents (Wazuh launches both processes simultaneously).
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/syscheck?pretty"
 *
 */
router.put('/', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /syscheck");

    var data_request = {'function': 'PUT/syscheck', 'arguments': {}};
    data_request['arguments']['all_agents'] = 1;
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {put} /syscheck/:agent_id Run syscheck scan in an agent
 * @apiName PutSyscheckAgentId
 * @apiGroup Run
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Runs syscheck and rootcheck on an agent (Wazuh launches both processes simultaneously).
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/syscheck/000?pretty"
 *
 */
router.put('/:agent_id', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /syscheck/:agent_id");

    var data_request = {'function': 'PUT/syscheck', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {delete} /syscheck Clear syscheck database
 * @apiName DeleteSyscheck
 * @apiGroup Clear
 *
 *
 * @apiDescription Clears the syscheck database for all agents.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/syscheck?pretty"
 *
 */
router.delete('/', function(req, res) {
    logger.debug(req.connection.remoteAddress + " DELETE /syscheck");

    apicache.clear("syscheck");

    var data_request = {'function': 'DELETE/syscheck', 'arguments': {}};
    data_request['arguments']['all_agents'] = 1;
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {delete} /syscheck/:agent_id Clear syscheck database of an agent
 * @apiName DeleteSyscheckAgentId
 * @apiGroup Clear
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Clears the syscheck database for the specified agent.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/syscheck/000?pretty"
 *
 */
router.delete('/:agent_id', function(req, res) {
    logger.debug(req.connection.remoteAddress + " DELETE /syscheck/:agent_id");

    apicache.clear("syscheck");

    var data_request = {'function': 'DELETE/syscheck', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})



module.exports = router;
