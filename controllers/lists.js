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
 * @api {get} /lists Get all lists
 * @apiName GetLists
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [path] Filters by path.
 *
 * @apiDescription Returns the content of all CDB lists.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/lists?pretty&path=etc/lists/audit-keys"
 *
 */
router.get('/', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /lists");

    req.apicacheGroup = "lists";

    var data_request = {'function': '/lists', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param',
        'path': 'paths'};

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
    if ('path' in req.query)
        data_request['arguments']['path'] = req.query.path;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /lists/files Get paths from all lists
 * @apiName GetListPath
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the path from all lists.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/lists/files?pretty"
 *
 */
router.get('/files', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /lists/files");

    req.apicacheGroup = "lists";

    var data_request = {'function': '/lists/files', 'arguments': {}};

    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param'};

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

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
