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


errors = require('../helpers/errors');
filter = require('../helpers/filters');
execute = require('../helpers/execute');
templates = require('../helpers/request_templates');
apicache  = require('apicache');
cache     = apicache.middleware;
wazuh_control = api_path + "/models/wazuh-api.py";

var router = require('express').Router();
var os = require("os");

// Cache options
if (config.cache_enabled.toLowerCase() == "yes"){
    if (config.cache_debug.toLowerCase() == "yes")
        cache_debug = true;
    else
        cache_debug = false;
    cache_opt = { debug: cache_debug, defaultDuration: parseInt(config.cache_time)};
}
else
    cache_opt = { enabled: false };

apicache.options(cache_opt);

// Content-type
router.post("*", function(req, res, next) {
    var content_type = req.get('Content-Type');

    if (!content_type || !(content_type == 'application/json' || content_type == 'application/x-www-form-urlencoded'
        || content_type == 'application/xml' || content_type == 'application/octet-stream')){
        logger.debug(req.connection.remoteAddress + " POST " + req.path);
        res_h.bad_request(req, res, "607");
    }
    else
        next();
});

// All requests
router.all("*", function(req, res, next) {
    var go_next = true;
    logger.set_user(req.user);

    if (req.query){
        // Pretty
        if ("pretty" in req.query){
            req['pretty'] = true;
            delete req.query["pretty"];
        } else {
            req['pretty'] = false;
        }
        // wait for
        if ("wait_for_complete" in req.query) {
            // Disable timeout in the current API call
            execute.set_disable_timeout(true);
            delete req.query["wait_for_complete"];
        }
    }

    if (go_next)
        next();
});

// Controllers
router.use('/agents', require('./agents'));
router.use('/manager', require('./manager'));
router.use('/syscheck', require('./syscheck'));
router.use('/rootcheck', require('./rootcheck'));
router.use('/configuration_assessment', require('./configuration_assessment'));
router.use('/rules', require('./rules'));
router.use('/decoders', require('./decoders'));
router.use('/cache', require('./cache'));
router.use('/cluster', require('./cluster'));
router.use('/syscollector', require('./syscollector'));
router.use('/ciscat', require('./ciscat'));
router.use('/active-response', require('./active_response'));
router.use('/lists', require('./lists'));

if (config.experimental_features){
    router.use('/experimental', require('./experimental'));
}

// Index
router.get('/',function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /");
    data = { 'msg': "Welcome to Wazuh HIDS API", 'api_version': "v" + info_package.version, 'hostname': os.hostname(), 'timestamp': new Date().toString()}
    json_res = {'error': 0, 'data': data};
    res_h.send(req, res, json_res);
});

// Version
router.get('/version',function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /version");

    json_res = {'error': 0, 'data': "v" + info_package.version};

    res_h.send(req, res, json_res);
});

// ALWAYS Keep this as the last route
router.all('*',function(req, res) {
    logger.debug(req.connection.remoteAddress + " " + req.method + " " + req.path);
    json_res = { 'error': 603, 'message': errors.description(603)};
    res_h.send(req, res, json_res, 404);
});


// Router Errors
router.use(function(err, req, res, next){
    logger.log("Internal Error");
    if(err.stack)
        logger.log(err.stack);
    logger.log("Exiting...");

    res_h.send(req, res, { error: 3 }, 500)
});


module.exports = router
