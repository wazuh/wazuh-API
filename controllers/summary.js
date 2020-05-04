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
 * @api {get} /summary/agents Get a full summary of agents
 * @apiName GetSummaryAgents
 * @apiGroup Info
 *
 * @apiDescription Returns a dictionary with a full summary of agents.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/summary/agents?pretty"
 *
 */
router.get('/agents', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /summary/agents");

    req.apicacheGroup = "summary";

    var data_request = {'function': '/summary/agents', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
