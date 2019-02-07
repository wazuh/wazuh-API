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
 * @api {get} /configuration_assessment/:agent_id Get configuration_assessment database
 * @apiName GetPMAgent
 * @apiGroup Info
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {String} [name] Filters by policy name.
 * @apiParam {String} [description] Filters by policy description
 * @apiParam {String} [references] Filters by references
 * @apiParam {String} [hash] Filters by hash
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [q] Query to filter results by. This is specially useful to filter by total checks passed, failed or total score (fields pass, fail, score).
 *
 * @apiDescription Returns the configuration_assessment database of an agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/configuration_assessment/000?offset=0&limit=2&q=pass>30;score<100&pretty"
 *
 */
router.get('/:agent_id', cache(), function(req, res) {
    query_checks = {'name':'alphanumeric_param', 'description':'alphanumeric_param', 'references':'alphanumeric_param', 'hash':'alphanumeric_param'};
    templates.array_request("/configuration_assessment/:agent_id", req, res, "configuration_assessment", {'agent_id':'numbers'}, query_checks);
})


/**
 * @api {get} /configuration_assessment/:agent_id/checks/:id Get configuration_assessment checks database
 * @apiName GetPMAgentChecks
 * @apiGroup Info
 *
 * @apiParam {Number} [agent_id] Agent ID.
 * @apiParam {Number} [scan_id] Filters by scan id
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
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the configuration_assessment checks of an agent
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/configuration_assessment/000/checks/1907428094?name=&pretty"
 *
 */
router.get('/:agent_id/checks/:scan_id', cache(), function(req, res) {
    query_checks = {'title': 'alphanumeric_param', 'description': 'alphanumeric_param',
        'rationale': 'alphanumeric_param', 'remediation': 'alphanumeric_param', 'file': 'paths', 'process': 'alphanumeric_param', 'directory': 'paths',
        'registry': 'alphanumeric_param', 'references': 'alphanumeric_param', 'result': 'alphanumeric_param'
    };
    templates.array_request("/configuration_assessment/:agent_id/checks/:scan_id", req, res,
               "configuration_assessment",
               {'agent_id': 'numbers', 'scan_id': 'alphanumeric_param'}, query_checks);
})

module.exports = router;
