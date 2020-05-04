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

var errors = {};

// 1 - 9 Internal Errors
errors['1'] = "Error executing internal command";
errors['2'] = "Command output not in JSON";
errors['3'] = "Internal error";

// Auth
errors['100'] = "Unauthorized request. Cluster privileges required";

// 600 - 699 Requests
errors['600'] = "Param not valid. Integer expected";  // Integer
errors['numbers'] = 600;
errors['601'] = "Param not valid. Valid characters: a-z, A-Z, 0-9, ., _, -, %";  // Names
errors['names'] = 601;
errors['603'] = "The requested URL was not found on this server";  // Default error
errors['604'] = "Filter error";  // Filter
errors['605'] = "Param not valid. Date format: YYYYMMDD";  // Date
errors['dates'] = 605;
errors['606'] = "Param not valid. IP invalid";  // IP
errors['ips'] = 606;  // IP
errors['607'] = "Invalid content-type. POST requests should be 'application/json', 'application/x-www-form-urlencoded', 'application/xml' or 'application/octet-stream'";  //
errors['608'] = "Param not valid. Path invalid. Valid characters: a-z, A-Z, 0-9, ., _, -, :, /, \\";  // Paths
errors['paths'] = 608;
errors['609'] = "Param not valid. Valid characters: a-z, A-Z, 0-9, ., _, -, +";  // Alphanumeric params
errors['alphanumeric_param'] = 609;
errors['610'] = "Param not valid. Valid characters: number or interval separated by '-'";  // range
errors['ranges'] = 610;
errors['611'] = "Param not valid. Valid characters: a-z, A-Z, 0-9, _, -, +, ,";  // sort
errors['sort_param'] = 611;
errors['612'] = "Param not valid. Invalid characters: ; & | * ^ >";  // search
errors['search_param'] = 612;
errors['613'] = "Param not valid. Valid values: md5/sha1/sha256 hash";  // hashes
errors['hashes'] = 613;
errors['614'] = "Invalid request"
errors['615'] = "Param not valid. Valid characters: a-z A-Z 0-9";  // keys
errors['ossec_key'] = 615;
errors['616'] = "Param not valid. Valid values: array of numbers";
errors['array_numbers'] = 616;
errors['timeframe_type'] = 617;
errors['617'] = "Param not valid. Valid characters: [0-9]d|[0-9]h|[0-9]m|[0-9]s|0-9";
errors['boolean'] = 618;
errors['618'] = "Param not valid. Valid values: true or false";
errors['619'] = "Param not valid. Valid characters: a-z A-Z 0-9 space . , _";  // select
errors['select_param'] = 619;
errors['yes_no_boolean'] = 620;
errors['620'] = "Param not valid. Valid values: yes or no";
errors['array_names'] = 621;
errors['621'] = "Invalid character in parameters";
errors['query_param'] = 622;
errors['622'] = 'Param not valid. Review queries documentation: https://documentation.wazuh.com/current/user-manual/api/queries.html'
errors['empty_boolean'] = 623;
errors['623'] = 'Param not valid. Valid values: true,false or empty(true)';
errors['700'] = "File not found";
errors['701'] = "Size of XML file is too long";
errors['702'] = "Could not write XML temporary file";
errors['703'] = "Invalid XML file";
errors['704'] = "Invalid path";
errors['705'] = "Invalid CDB list. Format for CDB list is 'key:value'";
errors['706'] = "'path' parameter is mandatory";

// Headers
errors['800'] = "Error adding agent due to header 'x-forwarded-for' is not present";
errors['801'] = "Wrong format for 'wazuh-app-version' header. Expected format: 'X.Y.Z'";
errors['802'] = "Invalid 'wazuh-app-version' header";
errors['803'] = "Wazuh API is only available for master nodes";
errors['804'] = "Invalid content-type for this request. Content-type should be 'application/xml' or 'application/octet-stream'";

exports.description = function(n){
    if (n in errors)
        return errors[n];
    else
        return "Undefined error.";
}
