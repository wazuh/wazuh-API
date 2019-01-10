/**
 * API RESTful for OSSEC
 * Copyright (C) 2015-2019 Wazuh, Inc.All rights reserved.
 * Wazuh.com
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

var fs = require('fs');
var moment = require('moment');

/*
    Creates a temporary file with a random name containing file_contents.
    Returns the file name
*/
exports.tmp_file_creator = function(file_contents) {
    random_file_name = config.ossec_path + '/tmp/api_group_conf_' + moment().unix() + '_' + Math.floor(Math.random() * Math.floor(1000)).toString();

    fs.writeFileSync(random_file_name, file_contents, (err) => {
        if (err) {
            throw err; 
        }
    });

    return random_file_name;
}