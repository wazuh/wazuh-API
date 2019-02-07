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
function input_val (val, regex) {
    if (typeof val != 'undefined')
        return regex.test(val);
    else
        return false;
}

exports.numbers = function(n) {
    return input_val(n, /^\d+$/);
}

exports.array_numbers = function(n) {
    return input_val(n, /^\d+(,\d+)*$/);
}

exports.names = function(name) {
    return input_val(name, /^[a-zA-Z0-9_\-\.]+$/);
}

exports.array_names = function(names) {
    return input_val(names, /^[a-zA-Z0-9_\-\.]+(,[a-zA-Z0-9_\-\.]+)*$/);
}

exports.paths = function(path) {
    return input_val(path, /^[a-zA-Z0-9\-\_\.\\\/:]+$/);
}

exports.dates = function(date) {
    return input_val(date, /^\d{8}$/);
}

exports.ips = function(ip) {
    return input_val(ip, /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2])){0,1}$|^any$|^ANY$/);
}

exports.alphanumeric_param = function(param) {
    return input_val(param, /^[a-zA-Z0-9_,\-\.\+\s\:]+$/);
}

exports.sort_param = function(param) {
    return input_val(param, /^[a-zA-Z0-9_\-\,\s\+\.]+$/); // + is translated as \s
}

exports.search_param = function(param) {
    return input_val(param, /^[^;\|&\^*>]+$/);
}

exports.select_param = function(param) {
    return input_val(param, /^[a-zA-Z0-9_\,\.]+$/);
}

exports.ranges = function(range) {
    return input_val(range, /^[0-9]+$|^[0-9]{1,2}\-[0-9]{1,2}$/);
}

exports.hashes = function(hash) {
    return input_val(hash, /^[0-9a-fA-F]{32}(?:[0-9a-fA-F]{8})?$|(?:[0-9a-fA-F]{32})?$/); // md5, sha1 or sha256
}

exports.ossec_key = function(key) {
    return input_val(key, /^[a-zA-Z0-9]+$/);
}

// [n_days]d[n_hours]h[n_minutes]m[n_seconds]s
exports.timeframe_type = function(timeframe) {
    return input_val(timeframe, /^(\d{1,}[d|h|m|s]?){1}$/);
}

exports.empty_boolean = function(b) {
    return input_val(b, /^$|(^true|false$)/);
}

exports.yes_no_boolean = function(b) {
    return input_val(b, /^yes$|^no$/);
}

exports.boolean = function(b) {
    return input_val(b, /^true|false$/);
}

exports.query_param = function(q) {
    return input_val(q, /[\w \d]+/);
}

exports.format = function(q) {
    return input_val(q,/^xml|json$/)
}