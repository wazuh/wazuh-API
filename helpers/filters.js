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

var res_h = require('../helpers/response_handler');
var validator = require('../helpers/input_validation');
var errors = require('../helpers/errors');

/*
 * query = req.query, req.params
 * filters = {'filter1':'type', 'filter2':'type'}
 * res = response
 *
 * Return:
 *  True, if matched filter
 *  False: Error in filter. Also, it sends a response!*
*/
exports.check = function (query, filters, req, res){
    var query_aux = (JSON.parse(JSON.stringify(query)));  // Clone query

    for(var field in filters){
        if (field in query){
            var type = filters[field]
            if(!validator[type](query[field])){ // Bad type
                var erro_code = errors.description(type);
                res_h.bad_request(req, res, erro_code, " Field: " + field);
                return false;
            }
            delete query_aux[field];
        }
    }

    // No extra fields
    if (Object.keys(query_aux).length != 0){
      res_h.bad_request(req, res, 604, filters_to_string(filters));
      return false; //Error: Allowed fields
    }

    return true; // Filter OK
}

exports.check_xml = function(xml_string, req, res) {
    var parser = require('fast-xml-parser');
    var is_valid = parser.validate(xml_string);
    if (is_valid === true) {
        return true;
    } else {
        res_h.bad_request(req, res, 703, is_valid.err.msg);
        return false;
    };
}

exports.check_path = function(path, req, res) {
    if (path.includes('./') || path.includes('../')) {
        res_h.bad_request(req, res, 704);
        return false
    }

    if (path == 'etc/ossec.conf') {
        return true
    }

    re = new RegExp(/((^etc\/rules\/|^etc\/decoders\/)[A-Za-z_\-\/]+\.{1}xml|(^etc\/lists\/)[A-Za-z_\-\.\/]+)/)
    if (!re.test(path)) {
        res_h.bad_request(req, res, 704);
        return false
    }

    return true
}

exports.check_cdb_list = function(cdb_list, req, res) {
    // for each line
    re = new RegExp(/^#?[\d\w\s-]+:{1}(#?[\d\w\s-]+|)/)
    var cdb_list_splitted = cdb_list.split('\n')
    for (i=0; i<cdb_list_splitted.length-1; i++) {
        if (!re.test(cdb_list_splitted[i])) {
            var line_error = 'Line ' + (i+1) + ': ' + cdb_list_splitted[i]
            res_h.bad_request(req, res, 705, line_error);
            return false
        }
    }
    return true
}

/*
 * filters = "-field1,field2"
 * Return:
 * sort_param = {"fields":["field1", "field1"], "order": "desc"}
*/
exports.sort_param_to_json = function (sort_param){
    var sort = {"fields": [], "order": "asc"};

    var all_fields = sort_param;
    if (sort_param[0] == '-'){
        sort["order"] = "desc";
        all_fields = sort_param.substring(1);
    }
    else if (sort_param[0] == '+' || sort_param[0] == ' '){  // +  is translated as a space
        sort["order"] = "asc";
        all_fields = sort_param.substring(1);
    }

    // Remove first character (- or +) and split by comma
    var fields = all_fields.split(',');

    if (fields[0].length != 0)
        for(var i = 0; i < fields.length; i++)
            sort["fields"].push(fields[i].trim());

    return sort
}

/*
 * filters = word. "word1 word2". !word. !"word1 word2"
 * Return:
 * search_param = {'value': 'search_text', 'negation':0}
*/
exports.search_param_to_json = function (search_param){
    var search = {"value": "", "negation": 0};

    var value = search_param;

    if (search_param[0] == '!'){
        search["negation"] = 1;
        value = search_param.substring(1);
    }

    if (value[0] == '"' && value[value.length - 1] == '"')
        search["value"] = value.substring(1, value.length - 1);
    else
        search["value"] = value.trim()

    return search
}

/*
 * filters = "field1,field2"
 * Return:
 * select_param = {"fields":["field1", "field1"]}
*/
exports.select_param_to_json = function (select_param){
    var select = {"fields": []};

    if (typeof select_param == 'string') {
        select_param.split(',').map(function(x) {
            select['fields'].push(x);
        });
    } else {
        select['fields'] = select_param;
    }

    return select
}

filters_to_string = function (filters){
    var output = "Allowed filters: [";
    for(var field in filters)
        output += " " + field + " ";
    output += "]  ";
    return output;
}
