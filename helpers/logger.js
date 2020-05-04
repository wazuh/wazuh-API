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

var moment = require('moment');
var fs = require('fs');
var path = require('path');
var rfs = require('rotating-file-stream');

var tag = "WazuhAPI";
var absolute_path_log = config.log_path;
var file_log = path.basename(config.log_path);
var path_log = path.dirname(config.log_path);
var foreground = false;
var ossec_uid = 0;
var ossec_gid = 0;

// get ossec uid and gid

var uidNumber = require("uid-number");
uidNumber("ossec", "ossec", function(er, uid, gid) {
    ossec_uid = gid;
    ossec_gid = uid;
});

var LEVEL_DISABLED = 0;
var LEVEL_INFO = 1;
var LEVEL_WARNING = 2;
var LEVEL_ERROR = 3;
var LEVEL_DEBUG = 4;
var user = "";

var logger_level = LEVEL_INFO;
switch (config.logs.toLowerCase()) {
    case "info":
        logger_level = LEVEL_INFO;
        break;
    case "warning":
        logger_level = LEVEL_WARNING;
        break;
    case "error":
        logger_level = LEVEL_ERROR;
        break;
    case "debug":
        logger_level = LEVEL_DEBUG;
        break;
    case "disabled":
        logger_level = LEVEL_DISABLED;
        break;
    default:
        logger_level = LEVEL_INFO;
}

exports.set_user = function(req_user) {
    user = req_user;
}

exports.set_foreground = function() {
    foreground = true;
}

function header(){
    return tag + " " + moment().format('YYYY-MM-DD HH:mm:ss') + " " + user + ": ";
}

function write_log(msg) {
    if (foreground)
        console.log(msg);
    fs.appendFile(absolute_path_log, msg + "\n", { 'mode': 0o640 }, function (err) {
        if (err) {
            return console.error(err);
        }
    });
}

exports.log = function (message) {
    if (logger_level >= LEVEL_INFO)
        write_log(header() + message);
}

exports.warning = function (message) {
    if (logger_level >= LEVEL_WARNING)
        write_log(header() + message);
}

exports.error = function (message) {
    if (logger_level >= LEVEL_ERROR)
        write_log(header() + message);
}

exports.debug = function (message) {
    if (logger_level >= LEVEL_DEBUG)
        write_log(header() + message);
}

function pad(num) {
    return (num > 9 ? "" : "0") + num;
}

function generator(time, index) {
    if (!time)
        return path_log + "/" + file_log;

    var month = moment.monthsShort(time.getMonth());
    var day = pad(time.getDate());
    var year = pad(time.getFullYear());

    return path_log + "/api/" + year + "/" + month + "/api-" + day + "-" + index + ".gz";
}

var stream = rfs(generator, {
    interval: '1d',
    compress: true,
    rotationTime: true,
    mode: 0o640,
});

stream.on('rotated', function(filename) {
    try {
        // rotation job completed with success producing given filename
        // setting correct permissions for generated files
        logger.log("Rotated: " + filename);
        fs.chmodSync(filename, 0o640);
        fs.chmodSync(path.dirname(filename), 0o750);
        fs.chmodSync(path.dirname(path.dirname(filename)), 0o750);

        // if the API is running as root, set the user of the created files to ossec
        if (!config.drop_privileges) {
            fs.chownSync(filename, ossec_uid, ossec_gid);
            fs.chownSync(path.dirname(filename), ossec_uid, ossec_gid);
            fs.chownSync(path.dirname(path.dirname(filename)), ossec_uid, ossec_gid);
            fs.chownSync(absolute_path_log, ossec_uid, ossec_gid);
        }

    // Prevents from crashing the service if the above instructions fail
    } catch (error) {
        try {
            logger.error(error.message || error);
        } catch (err) {
            console.log(err.message || err)
        }
    }
});
