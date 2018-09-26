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
 * @api {put} /active-response/:agent_id Run an AR command in the agent
 * @apiName PutARAgentIdCommand
 * @apiGroup Command
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {String} command Command.
 * @apiParam {Boolean} Custom Custom.
 * @apiParam {Arguments} Arguments Command arguments.
 *
 * @apiDescription Runs an Active Response command on a specified agent
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X PUT -d '{"command":"restart-ossec0", "arguments": ["-", "null", "(from_the_server)", "(no_rule_id)"]}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/active-response/001?pretty"
 */
router.put('/:agent_id', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /active-response/:agent_id");

    var data_request = {'function': '/PUT/active-response/:agent_id', 'arguments': {}};

    // ToDo: Add argments
    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['command'] = req.body.command;
    data_request['arguments']['custom'] = req.body.custom;
    data_request['arguments']['arguments'] = req.body.arguments;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})



module.exports = router;
