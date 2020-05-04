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
 * @api {get} /cache Get cache index
 * @apiName GetCache
 * @apiGroup Info
 *
 *
 * @apiDescription Returns current cache index.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cache?pretty"
 *
 */
router.get('/', function(req, res, next) {
    logger.debug(req.connection.remoteAddress + " GET /cache");
    res_h.send(req, res, { 'error': 0, 'data': apicache.getIndex() });
});

/**
 * @api {get} /cache/config Return cache configuration
 * @apiName GetCacheConfiguration
 * @apiGroup Info
 *
 *
 * @apiDescription Returns cache configuration.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cache/config?pretty"
 *
 */
router.get('/config', function(req, res, next) {
    logger.debug(req.connection.remoteAddress + " GET /cache/config");
    res_h.send(req, res, { 'error': 0, 'data': apicache.options() });
});

/**
  * @api {delete} /cache Delete cache index
  * @apiName DeleteCache
  * @apiGroup Delete
  *
  *
  * @apiDescription Clears entire cache.
  *
  * @apiExample {curl} Example usage:
  *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/cache?pretty"
  *
  */
router.delete('/', function(req, res, next) {
    logger.debug(req.connection.remoteAddress + " DELETE /cache");
    res_h.send(req, res, { 'error': 0, 'data': apicache.clear() });
});

/**
 * @api {delete} /cache/:group Clear group cache
 * @apiName DeleteCacheGroup
 * @apiGroup Delete
 *
 * @apiParam {String} group cache group.
 *
 * @apiDescription Clears cache of the specified group.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/cache/mygroup?pretty"
 *
 */
router.delete('/:group', function(req, res, next) {
    logger.debug(req.connection.remoteAddress + " DELETE /cache/:group");

    if (!filter.check(req.params, {'group':'alphanumeric_param'}, req, res))  // Filter with error
        return;

    res_h.send(req, res, { 'error': 0, 'data': apicache.clear(req.params.group) });
});


module.exports = router;
