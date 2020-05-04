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
 * @api {get} /rules Get all rules
 * @apiName GetRules
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String="enabled","disabled", "all"} [status] Filters the rules by status.
 * @apiParam {String} [group] Filters the rules by group.
 * @apiParam {Range} [level] Filters the rules by level. level=2 or level=2-5.
 * @apiParam {String} [path] Filters the rules by path.
 * @apiParam {String} [file] Filters the rules by file name.
 * @apiParam {String} [pci] Filters the rules by pci requirement.
 * @apiParam {String} [gdpr] Filters the rules by gdpr requirement.
 * @apiParam {String} [hipaa] Filters the rules by hipaa requirement.
 * @apiParam {String} [nist-800-53] Filters the rules by nist-800-53 requirement.
 * @apiParam {String} [gpg13] Filters the rules by gpg13 requirement.
 * @apiParam {String} [mitre] Filters the rules by mitre requirement.
 * @apiParam {String} [tsc] Filters the rules by tsc requirement.
 * @apiParam {String} [q] Query to filter results by. For example q=id=89055
 *
 * @apiDescription Returns all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules?offset=0&limit=2&pretty"
 *
 */
router.get('/', cache(), function(req, res) {
    param_checks = {}
    query_checks = {'status':'alphanumeric_param', 'group':'alphanumeric_param',
        'level':'ranges', 'path':'paths', 'file':'alphanumeric_param', 'pci':'alphanumeric_param',
        'gdpr': 'alphanumeric_param', 'hipaa': 'alphanumeric_param',
        'nist-800-53': 'alphanumeric_param', 'gpg13': 'alphanumeric_param', 'tsc': 'alphanumeric_param',
        'mitre': 'alphanumeric_param'};

    templates.array_request('/rules', req, res, "rules", param_checks, query_checks);
})

/**
 * @api {get} /rules/groups Get rule groups
 * @apiName GetRulesGroups
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the groups of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/groups?offset=0&limit=10&pretty"
 *
 */
router.get('/groups', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rules/groups");

    req.apicacheGroup = "rules";

    var data_request = {'function': '/rules/groups', 'arguments': {}};
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

/**
 * @api {get} /rules/pci Get rule pci requirements
 * @apiName GetRulesPci
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the PCI requirements of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/pci?offset=0&limit=10&pretty"
 *
 */
router.get('/pci', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rules/pci");

    req.apicacheGroup = "rules";

    var data_request = {'function': '/rules/pci', 'arguments': {}};
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


/**
 * @api {get} /rules/gpg13 Get rule gpg13 requirements
 * @apiName GetRulesGpg13
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the GPG13 requirements of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/gpg13?offset=0&limit=10&pretty"
 *
 */
router.get('/gpg13', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rules/gpg13");

    req.apicacheGroup = "rules";

    var data_request = {'function': '/rules/gpg13', 'arguments': {}};
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


/**
 * @api {get} /rules/gdpr Get rule gdpr requirements
 * @apiName GetRulesGdpr
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the GDPR requirements of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/gdpr?offset=0&limit=10&pretty"
 *
 */
router.get('/gdpr', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rules/gdpr");

    req.apicacheGroup = "rules";

    var data_request = {'function': '/rules/gdpr', 'arguments': {}};
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


/**
 * @api {get} /rules/hipaa Get rule hipaa requirements
 * @apiName GetRulesHipaa
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the HIPAA requirements of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/hipaa?offset=0&limit=10&pretty"
 *
 */
router.get('/hipaa', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rules/hipaa");

    req.apicacheGroup = "rules";

    var data_request = {'function': '/rules/hipaa', 'arguments': {}};
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


/**
 * @api {get} /rules/nist-800-53 Get rule nist-800-53 requirements
 * @apiName GetRulesNist-800-53
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the NIST-800-53 requirements of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/nist-800-53?offset=0&limit=10&pretty"
 *
 */
router.get('/nist-800-53', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rules/nist-800-53");

    req.apicacheGroup = "rules";

    var data_request = {'function': '/rules/nist-800-53', 'arguments': {}};
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

/**
 * @api {get} /rules/tsc Get rule TSC requirements
 * @apiName GetRulesTSC
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the TSC requirements of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/tsc?offset=0&limit=10&pretty"
 *
 */
router.get('/tsc', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rules/tsc");

    req.apicacheGroup = "rules";

    var data_request = {'function': '/rules/tsc', 'arguments': {}};
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

/**
 * @api {get} /rules/mitre Get rule mitre requirements
 * @apiName GetRulesMitre
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the Mitre requirements of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/Mitre?offset=0&limit=2&pretty"
 *
 */
router.get('/mitre', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rules/mitre");

    req.apicacheGroup = "rules";

    var data_request = {'function': '/rules/mitre', 'arguments': {}};
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


/**
 * @api {get} /rules/files Get files of rules
 * @apiName GetRulesFiles
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String="enabled","disabled", "all"} [status] Filters files by status.
 * @apiParam {String} [path] Filters the rules by path.
 * @apiParam {String} [file] Filters the rules by filefile.
 * @apiParam {String} [download] Downloads the file
 *
 * @apiDescription Returns the files of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/files?offset=0&limit=10&pretty"
 *
 */
router.get('/files', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rules/files");

    req.apicacheGroup = "rules";

    var data_request = {'function': '/rules/files', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'status':'alphanumeric_param', 'download':'alphanumeric_param','path':'paths', 'file':'alphanumeric_param'};

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
    if ('path' in req.query)
        data_request['arguments']['path'] = req.query.path;
    if ('file' in req.query)
        data_request['arguments']['file'] = req.query.file;

    if ('download' in req.query)
        res_h.send_file(req, res, req.query.download, 'rules');
    else
        execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /rules/:rule_id Get rules by id
 * @apiName GetRulesId
 * @apiGroup Info
 *
 * @apiParam {Number} id rule.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the rules with the specified id.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/1002?pretty"
 *
 */
router.get('/:rule_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /rules/:rule_id");

    req.apicacheGroup = "rules";

    var data_request = {'function': '/rules', 'arguments': {}};
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

    if (!filter.check(req.params, {'rule_id': 'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['filters'] = {'id': req.params.rule_id};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})



module.exports = router;
