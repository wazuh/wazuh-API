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


var router = require('express').Router();


/**
 * @api {get} /vulndetector Get data from 'VULNERABILITIES' table (cve.db)
 * @apiName GetVuln
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [file] Filters file by filename.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {string} [q] Advanced query filtering
 *
 * @apiDescription Returns information from Vulnerability Detector database.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/vulndetector?offset=3&limit=4&pretty"
 *
 */
router.get('/', cache(), function(req, res) {
    templates.array_request("/vulndetector", req, res, "vulndetector");
})


/**
 * @api {get} /vulndetector/info Get data from 'VULNERABILITIES_INFO' table (cve.db)
 * @apiName GetVulnInfo
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [file] Filters file by filename.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {string} [q] Advanced query filtering
 *
 * @apiDescription Returns information from Vulnerability Detector database.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/vulndetector/info?offset=0&limit=2&pretty"
 *
 */
router.get('/info', cache(), function(req, res) {
    templates.array_request("/vulndetector/info", req, res, "vulndetector");
})


module.exports = router;