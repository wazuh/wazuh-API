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

var errors = require('../helpers/errors');
var logger = require('../helpers/logger');
var conf   = require('../configuration/config');
var fileSystem = require('fs');

exports.send = function(req, res, json_r, status){

    if (typeof status == 'undefined')
        status = 200;

    // Validate json and status
    if (json_r != null && json_r.error != null && (json_r.data != null || json_r.message != null) && status >= 100 && status <= 600){

        // Calculate status
        if (json_r.error >= 1 && json_r.error <= 9)
            status = 500;

    }
    else{
        json_r = {"error": 3, "message": errors.description(3)}; // Internal Error
        status = 500;
    }

    // Logging
    var log_msg = "[" + req.connection.remoteAddress + "] " + req.method + " " + req.baseUrl + req.url + " - " + status + " - error: '" + json_r.error + "'.";
    logger.log(log_msg);

    if (status != 200)
        logger.debug("Response: " + JSON.stringify(json_r) + " HTTP Status: " + status);

    // Send
    if (!res.headersSent){
        if (req['pretty'])
            res.status(status).send(JSON.stringify( json_r, null, 3) + "\n");
        else
            res.status(status).json(json_r);
    }
}

exports.bad_request = function(req, res, internal_error, extra_msg){
    var msg = errors.description(internal_error);

    if (extra_msg)
        msg = msg + ". " + extra_msg;

    json_res = {'error': internal_error, 'message': msg};

    this.send(req, res, json_res, 400);
}

exports.unauthorized_request = function(req, res, internal_error, extra_msg){
    var msg = errors.description(internal_error);

    if (extra_msg)
        msg = msg + ". " + extra_msg;

    json_res = {'error': internal_error, 'message': msg};

    this.send(req, res, json_res, 401);
}

exports.send_file = function(req, res, file_name, type){

    if (type == 'zip') {
        var real_filename = conf.ossec_path + file_name.data;
        var send_aux = this.send;

        try {
            var stat = fileSystem.statSync(real_filename);

            res.writeHead(200, {
            'Content-Type': 'text/xml',
            'Content-Length': stat.size
            });

            var readStream = fileSystem.createReadStream(real_filename);
            readStream
                .on('close', function(err) {
                    // remove .zip file once it has been sent
                    fileSystem.unlink(real_filename);
                });

            readStream.pipe(res)

            // Logging
            var log_msg = "[" + req.connection.remoteAddress + "] " + req.method + " " + req.baseUrl + req.url + " - 200 - error: '0'.";
            logger.log(log_msg);
        } catch (e) {
            json_res = {'error': 3, 'message': errors.description(3)};
            send_aux(req, res, json_res, 500);
            return;
        }

    }else{

        var data_request = {'function': '/' + type +'/files', 'arguments': {'file': file_name}};

        var send_aux = this.send;
        execute.exec(python_bin, [wazuh_control], data_request, function (data) {
            try {
                try {
                    var filepath = data.data.items[0].path + "/" + file_name;
                } catch (e) {
                    json_res = {'error': 700, 'message': errors.description(700) + ": " + file_name};
                    send_aux(req, res, json_res, 404);
                    return;
                }
                var stat = fileSystem.statSync(conf.ossec_path + '/' + filepath);

                res.writeHead(200, {
                'Content-Type': 'text/xml',
                'Content-Length': stat.size
                });

                var readStream = fileSystem.createReadStream(conf.ossec_path + '/' + filepath);

                readStream.pipe(res)

                // Logging
                var log_msg = "[" + req.connection.remoteAddress + "] " + req.method + " " + req.baseUrl + req.url + " - 200 - error: '0'.";
                logger.log(log_msg);
            } catch (e) {
                if (e.code === 'ENOENT') {
                    json_res = {'error': 700, 'message': errors.description(700) + ": " + filepath};
                    send_aux(req, res, json_res, 404);
                    return;
                } else {
                    json_res = {'error': 3, 'message': errors.description(3)};
                    send_aux(req, res, json_res, 500);
                    return;
                }
            }
        });
    }
}
