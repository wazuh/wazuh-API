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
 * @api {get} /decoders Get all decoders
 * @apiName GetDecoders
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [file] Filters by filename.
 * @apiParam {String} [path] Filters by path.
 * @apiParam {String="enabled","disabled", "all"} [status] Filters the decoders by status.
 * @apiParam {String} [q] Query to filter results by. For example q=name=wazuh
 *
 * @apiDescription Returns all decoders included in ossec.conf.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/decoders?pretty&offset=0&limit=2&sort=+file,position"
 *
 */
router.get('/', cache(), function(req, res) {
    param_checks = {}
    query_checks = {'status':'alphanumeric_param', 'path':'paths', 'file':'alphanumeric_param'};

    templates.array_request('/decoders', req, res, "decoders", param_checks, query_checks);
})

/**
 * @api {get} /decoders/files Get all decoders files
 * @apiName GetDecodersFiles
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String="enabled","disabled", "all"} [status] Filters the decoders by status.
 * @apiParam {String} [file] Filters by filename.
 * @apiParam {String} [path] Filters by path.
 * @apiParam {String} [download] Name of the decoder file to download.
 *
 * @apiDescription Returns all decoders files included in ossec.conf.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/decoders/files?pretty&offset=0&limit=10&sort=-path"
 *
 */
router.get('/files', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /decoders/files");

    req.apicacheGroup = "decoders";

    var data_request = {'function': '/decoders/files', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'status':'alphanumeric_param', 'download':'alphanumeric_param', 'path':'paths', 'file':'alphanumeric_param'};

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
    if ('status' in req.query)
        data_request['arguments']['status'] = req.query.status;
    if ('file' in req.query)
        data_request['arguments']['file'] = req.query.file;
    if ('path' in req.query)
        data_request['arguments']['path'] = req.query.path;

    if ('download' in req.query)
        res_h.send_file(req, res, req.query.download, 'decoders');
    else
        execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /decoders/parents Get all parent decoders
 * @apiName GetDecodersParents
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns all parent decoders included in ossec.conf.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/decoders/parents?pretty&offset=0&limit=2&sort=-file"
 *
 */
router.get('/parents', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /decoders/parents");

    req.apicacheGroup = "decoders";

    var data_request = {'function': '/decoders', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param', 'search': 'search_param'};

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

    data_request['arguments']['filters'] = {'parents': 'True'};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /decoders/:decoder_name Get decoders by name
 * @apiName GetDecodersName
 * @apiGroup Info
 *
 * @apiParam {String} decoder_name Decoder name.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the decoders with the specified name.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/decoders/apache-errorlog?pretty"
 *
 */
router.get('/:decoder_name', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /decoders/:decoder_name");

    req.apicacheGroup = "decoders";

    var data_request = {'function': '/decoders', 'arguments': {}};
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

    if (!filter.check(req.params, {'decoder_name':'names'}, req, res))  // Filter with error
        return;

    data_request['arguments']['filters'] = {'name': req.params.decoder_name};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})



module.exports = router;
