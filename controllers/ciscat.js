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
 * @api {get} /ciscat/:agent_id/results Get CIS-CAT results from an agent
 * @apiName GetCiscat_agent
 * @apiGroup Results
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields separated by commas.
 * @apiParam {String} [benchmark] Filters by benchmark.
 * @apiParam {String} [profile] Filters by evaluated profile.
 * @apiParam {Number} [pass] Filters by passed checks.
 * @apiParam {Number} [fail] Filters by failed checks.
 * @apiParam {Number} [error] Filters by encountered errors.
 * @apiParam {Number} [notchecked] Filters by not checked.
 * @apiParam {Number} [unknown] Filters by unknown results.
 * @apiParam {Number} [score] Filters by final score.
 * @apiParam {String} [q] Advanced query filtering.
 *
 * @apiDescription Returns the agent's ciscat results info
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/ciscat/000/results?pretty&sort=-score"
 *
 */
router.get('/:agent_id/results', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /ciscat/:agent_id/results");
    var filters = {'benchmark': 'alphanumeric_param', 'profile': 'alphanumeric_param', 
                   'pass': 'alphanumeric_param', 'fail': 'alphanumeric_param',
                   'error': 'numbers', 'notchecked': 'numbers',
                   'unknown': 'numbers', 'score': 'numbers'
                  };
    templates.array_request("/ciscat/:agent_id/results", req, res, "ciscat", {'agent_id': 'numbers'}, filters);
});

module.exports = router;
