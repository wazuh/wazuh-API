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
 * @api {get} /sca/:agent_id Get security configuration assessment (SCA) database
 * @apiName GetSCAAgent
 * @apiGroup Info
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {String} [name] Filters by policy name.
 * @apiParam {String} [description] Filters by policy description
 * @apiParam {String} [references] Filters by references
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [q] Query to filter results by. This is specially useful to filter by total checks passed, failed or total score (fields pass, fail, score).
 *
 * @apiDescription Returns the sca database of an agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/sca/000?q=pass>2;score<150&pretty&limit=2"
 *
 */
router.get('/:agent_id', cache(), function(req, res) {
    query_checks = {'name':'alphanumeric_param', 'description': 'alphanumeric_param', 'references': 'encoded_uri'};
    templates.array_request("/sca/:agent_id", req, res, "sca", {'agent_id': 'numbers'}, query_checks);
})


/**
 * @api {get} /sca/:agent_id/checks/:policy_id Get security configuration assessment (SCA) checks database
 * @apiName GetSCAAgentChecks
 * @apiGroup Info
 *
 * @apiParam {Number} [agent_id] Agent ID.
 * @apiParam {String} [policy_id] Filters by policy id
 * @apiParam {String} [title] Filters by title
 * @apiParam {String} [description] Filters by policy description
 * @apiParam {String} [rationale] Filters by rationale
 * @apiParam {String} [remediation] Filters by remediation
 * @apiParam {String} [file] Filters by file
 * @apiParam {String} [process] Filters by process
 * @apiParam {String} [directory] Filters by directory
 * @apiParam {String} [registry] Filters by registry
 * @apiParam {String} [references] Filters by references
 * @apiParam {String} [result] Filters by result
 * @apiParam {String} [condition] Filters by condition
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the sca checks of an agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/sca/000/checks/unix_audit?limit=1&pretty"
 *
 */
router.get('/:agent_id/checks/:policy_id', cache(), function(req, res) {
    query_checks = {'title': 'alphanumeric_param', 'description': 'alphanumeric_param',
        'rationale': 'alphanumeric_param', 'remediation': 'alphanumeric_param',
        'file': 'paths', 'process': 'alphanumeric_param', 'directory': 'paths',
        'registry': 'alphanumeric_param', 'references': 'encoded_uri',
        'result': 'alphanumeric_param', 'condition': 'alphanumeric_param'
    };
    templates.array_request("/sca/:agent_id/checks/:policy_id", req, res,
               "sca",
               {'agent_id': 'numbers', 'policy_id': 'alphanumeric_param'}, query_checks);
})

module.exports = router;
