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

var logger = require('../helpers/logger');
var errors = require('../helpers/errors');
var timeout = 240; // seconds
var disable_timeout = false;

/**
 * Exec command.
 * It returns (callback) always a JSON.
 * Input
 *   Error: {'error': !=0, 'message': 'Error description'}
 *   OK: {'error': 0, 'data' = 'cmd output'}
 * Output
 *   Error: {'error': !=0, 'message': 'Error description'}
 *   OK: {'error': 0, 'data' = 'cmd output'}
 */
exports.exec = function(cmd, args, stdin, callback) {
    const child_process  = require('child_process');

    if (stdin != null)
        stdin['ossec_path'] = config.ossec_path;

    // log
    stdin['arguments']['wait_for_complete'] = disable_timeout;
    var full_cmd = "CMD - Command: " + cmd + " args:" + args.join(' ') + " stdin:" + JSON.stringify(stdin);
    logger.debug(full_cmd);

    const child = child_process.spawn(cmd, args);

    var output = [];
    var error = false;
    var close = false;
    var tout = false;

    if (!disable_timeout) {
        setTimeout(function(){
            logger.debug("Sending SIGTERM to " + full_cmd);
            child.kill('SIGTERM');
            tout = true;
        }, timeout*1000);
    } else {
        logger.log("Timeout has been disabled in this API call.");
    }

    // Delay to prevent write stdin when the pipe is closed.
    setTimeout(function(){
        if (!close){
            child.stdin.setEncoding('utf-8');
            child.stdin.write(JSON.stringify(stdin) +"\n");
        }
    }, 50);

    child.stdout.on('data', (chunk) => {
        output.push(chunk)
        //logger.debug("Chunk: " + Buffer.byteLength(chunk, 'utf8') + " bytes");
    });

    child.on('error', function(err) {
        // Reset disable timeout
        disable_timeout = false;
        logger.error("CMD - Error executing command: " + err);
        error = true;
        callback({"error": 1, "message": errors.description(1)});  // Error executing internal command
    });

    child.on('close', (code) => {
        // Reset disable timeout
        disable_timeout = false;
        logger.debug("CMD - Exit code: " + code);
        close = true;
        if (!error){
            var json_result = {};

            if (code != 0){  // Exit code must be 0
                if (tout)
                    json_result = {"error": 1, "message": errors.description(1) + ". Timeout exceeded (" + timeout + "s)."};  // Error executing internal command
                else
                    json_result = {"error": 1, "message": errors.description(1) + ". Exit code: " + code};  // Error executing internal command
            }
            else{
                var json_cmd = {}
                // Check JSON
                var stdout = output.join('');
                logger.debug("CMD - STDOUT:\n---\n" + stdout + "\n---");
                logger.debug("CMD - STDOUT: " + Buffer.byteLength(stdout, 'utf8') + " bytes");
                json_cmd = tryParseJSON(stdout)

                if (!json_cmd){
                    logger.debug("CMD - STDOUT NOT JSON");
                    json_result = {"error": 2, "message": errors.description(2)}; // OUTPUT Not JSON
                }
                else{
                    // Check JSON content
                    if ( json_cmd.hasOwnProperty('error') && ( json_cmd.hasOwnProperty('message') || json_cmd.hasOwnProperty('data') ) ){

                        json_result.error = json_cmd.error;

                        if ( json_cmd.hasOwnProperty('data') )
                            json_result.data = json_cmd.data;

                        if ( json_cmd.hasOwnProperty('message') ){
                            logger.error(json_cmd.message);
                            if ( json_result.error === 1000)
                                json_result.message = "Internal error";
                            else{
                                if (typeof json_cmd.message === 'string')
                                    json_result.message = json_cmd.message.split(":", 1)[0];
                            }
                            
			}
                    }
                    else{
                        json_result = {"error": 1, "message": errors.description(1) + ". Wrong keys"}; // JSON Wrong keys
                        logger.error("CMD - Wrong keys: " + Object.keys(json_cmd));
                    }
                }
            }
            callback(json_result);
        }
    });

}

exports.set_disable_timeout = function(new_value) {
    disable_timeout = new_value;
}

function tryParseJSON (jsonString){
    try {
        var o = JSON.parse(jsonString);

        if (o && typeof o === "object" && o !== null) {
            return o;
        }
    }
    catch (e) { }

    return false;
};
