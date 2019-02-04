/**
 * Wazuh API RESTful
 * Copyright (C) 2015-2019 Wazuh, Inc.  All rights reserved.
 * Wazuh.com
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

if (process.getuid() !== 0){
    console.log('A root user is required to start the API.');
    process.exit(1);
}

/********************************************/
/* Root actions
/********************************************/
try {
    var auth = require("http-auth");
} catch (e) {
    console.log("Dependencies not found. Try 'npm install' in /var/ossec/api. Exiting...");
    process.exit(1);
}

const check = require('./helpers/check');

//  Get configuration
config = require('./configuration/config');
if (check.configuration_file() < 0) {
    setTimeout(function(){ process.exit(1); }, 500);
    return;
}

//  Get credentials
if (config.basic_auth.toLowerCase() == "yes"){
    var auth_secure = auth.basic({
        realm: "OSSEC API",
        file: __dirname + "/configuration/auth/user"
    });
}

//  Get Certs
var options = {};

var fs = require('fs');
if (config.https.toLowerCase() == "yes"){
    var api_route = config.ossec_path + '/api/';
    var option_paths = {};

    // Cert and key
    option_paths.key = config.https_key || 'configuration/ssl/server.key';
    if (option_paths.key.charAt(0) != '/'){
        option_paths.key = api_route + option_paths.key;
    }

    option_paths.cert = config.https_cert  || 'configuration/ssl/server.crt';
    if (option_paths.cert.charAt(0) != '/'){
        option_paths.cert = api_route + option_paths.cert;
    }

    options.key = fs.readFileSync(option_paths.key);
    options.cert = fs.readFileSync(option_paths.cert);

    // CA
    var use_ca = config.https_use_ca || 'no';
    if (use_ca.toLowerCase() == "yes"){
        option_paths.ca = config.https_ca || 'configuration/ssl/ca.crt';
        if (option_paths.ca.charAt(0) != '/'){
            option_paths.ca = api_route + option_paths.ca;
        }

        options.ca = fs.readFileSync(option_paths.ca);
    }
    if (config.secureProtocol && config.secureProtocol != "") options.secureProtocol = config.secureProtocol;
    if (config.ciphers && config.ciphers != "") options.ciphers = config.ciphers;
    if (config.honorCipherOrder) options.honorCipherOrder = config.honorCipherOrder;
    if (config.secureOptions) options.secureOptions = config.secureOptions;
}


/********************************************/
/* Drop privileges
/********************************************/
if (config.drop_privileges || config.drop_privileges == undefined) {
    try {
        process.setgid('ossec');
        process.setuid('ossec');
    } catch(err) {
        console.log('Drop privileges failed: ' + err.message);
        process.exit(1);
    }
}

/********************************************/
/* Modules, vars and global vars
/********************************************/
try {
    var express = require('express');
    var bodyParser = require('body-parser');
    var cors = require('cors')
    var moment = require('moment');
    res_h = require('./helpers/response_handler');
    logger = require('./helpers/logger');
} catch (e) {
    console.log("Dependencies not found. Try 'npm install' in /var/ossec/api. Exiting...");
    process.exit(1);
}

api_path = __dirname;
python_bin = config.ossec_path + '/python/bin/python3';

/********************************************/
/* Config APP
/********************************************/
info_package = require('./package.json');
var version_mmp = info_package.version.split('.'); // major.minor.patch
var current_mm_version = version_mmp[0] + '.' + version_mmp[1]; // major.minor

if (process.argv.length == 3 && process.argv[2] == "-f")
    logger.set_foreground();

if (check.wazuh(logger) < 0) {
    setTimeout(function(){ process.exit(1); }, 500);
    return;
}

var port = process.env.PORT || config.port;

if (config.host != "0.0.0.0")
    var host = config.host;

var app = express();

// CORS
if (config.cors.toLowerCase() == "yes"){
    app.use(cors());
}

// Basic authentication
if (config.basic_auth.toLowerCase() == "yes"){
    app.use(auth.connect(auth_secure));

    auth_secure.on('fail', (result, req) => {
        logger.set_user(result.user);
        var log_msg = "[" + req.connection.remoteAddress + "] " + "User: \"" + result.user + "\" - Authentication failed.";
        logger.log(log_msg);
    });

    auth_secure.on('error', (error, req) => {
        logger.set_user("");
        var log_msg = "[" + req.connection.remoteAddress + "] Authentication error: " + error.code + " - " + error.message;
        logger.log(log_msg);
    });
}

// temporary
if (config.ld_library_path) {
    logger.warning("LD library path configuration is deprecated.");
}
if (config.python) {
    logger.warning("Python configuration is deprecated. Using " + python_bin);
}


// Body
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.text({type:"application/xml", limit:"1mb"}));
app.use(bodyParser.raw({type:"application/octet-stream", limit:"1mb"}));


/**
 * Check Wazuh app version
 * Using: Header: "wazuh-app-version: X.Y.Z"
 */
app.use(function(req, res, next) {
    var go_next = true;
    var app_version_header = req.get('wazuh-app-version');
    var regex_version = /^\d+\.\d+\.\d+$/i;

    if (typeof app_version_header != 'undefined'){
        if (!regex_version.test(app_version_header)){
            go_next = false;
            res_h.bad_request(req, res, "801");
        }
        else{
            var app_version_mmp = app_version_header.split('.'); // major.minor.patch
            var app_mm_version = app_version_mmp[0] + '.' + app_version_mmp[1]; // major.minor

            if (app_mm_version != current_mm_version){
                go_next = false;
                res_h.bad_request(req, res, "802", "Expected version '" + current_mm_version + ".x', and found '" + app_mm_version + ".x'.");
            }
        }
    }

    if (go_next)
        next();
});

// Controllers
app.use("/", require('./controllers'));

// APP Errors
app.use (function (err, req, res, next){

    if ( err == "Error: invalid json" ){
        logger.debug(req.connection.remoteAddress + " " + req.method + " " + req.path);
        res_h.bad_request(req, res, "607");
    }
    else if ('status' in err && err.status == 400){
        var msg = "";
        if ('body' in err)
            msg = "Body is not correct.";
        res_h.bad_request(req, res, "614", msg);
    }
    else if (err == "PayloadTooLargeError: request entity too large"){
        res_h.bad_request(req, res, "701");
    }
    else{
        logger.log("Internal Error");
        if(err.stack)
            logger.log(err.stack);
        logger.log("Exiting...");
        setTimeout(function(){ process.exit(1); }, 500);
    }
});

/********************************************/
/* Create server
/********************************************/
if (config.https.toLowerCase() == "yes"){
    var https = require('https');
    var server = https.createServer(options, app).listen(port, host, function(){
        logger.log("Listening on: https://" + server.address().address + ":" + port);
    });
}
else{
    var http = require('http');
    var server = http.createServer(app).listen(port, host, function(){
        logger.log("Listening on: http://" + server.address().address + ":" + port);
    });
}

/********************************************/
/* Event handler
/********************************************/
process.on('uncaughtException', function(err) {

    if (err.errno == "EADDRINUSE")
        logger.log("Error: Address in use (port " + port + "): Close the program using that port or change the port.")
    else {
      logger.log("Internal Error: uncaughtException");
      if(err.stack)
          logger.log(err.stack);
    }

    logger.log("Exiting...");
    setTimeout(function(){ process.exit(1); }, 500);
});

process.on('SIGTERM', function() {
    logger.log("Exiting... (SIGTERM)");
    setTimeout(function(){ process.exit(1); }, 500);
});

process.on('SIGINT', function() {
    logger.log("Exiting... (SIGINT)");
    setTimeout(function(){ process.exit(1); }, 500);
});
