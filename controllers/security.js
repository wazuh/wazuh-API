/**
 * API RESTful for OSSEC
 * Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
 * Wazuh.com
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


var router = require('express').Router();
var users = require('../helpers/users');



/**
 * @api {get} /security/user/authenticate Authenticate user
 * @apiName AuthenticateUser
 * @apiGroup usersentication
 *
 * @apiDescription Assigns and returns a token for the specified user. Also, returns information about user roles, and token.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/security/user/authenticate?pretty"
 *
 */
router.get('/user/authenticate', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET/security/user/authenticate");
    var user_name = users.current_user_name;

    var token = users.get_token(user_name);
    var data_request = { 'function': '/security/user/authenticate', 'arguments': {} };
    data_request['url'] = req.originalUrl;
    data_request['arguments']['user_name'] = user_name;

    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {
        if (python_response.error == 0 && python_response.data) {
            var response = {
                data: {
                    token: token, username: user_name,
                    token_expires_in: config.token_expiration_time, roles: python_response.data.roles,
                    totalRoles: python_response.data.totalRoles
                }, error: 0
            };
            res_h.send(req, res, response, "200");
        } else {
            res_h.send(req, res, python_response);
        }
    });
});


/**
 * @api {put} /security/user Update current user
 * @apiName UpdateCurrentUser
 * @apiGroup UpdateUser
 *
 * @apiParam {Boolean} enabled To enable or disable the user.
 * 
 * @apiDescription Updates the current user information. Fields that can be updated: enabled, password.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X PUT -H "Content-Type:application/json" -d '{"enabled":true}' "https://127.0.0.1:55000/security/user?pretty"
 *
 */
router.put('/user', function (req, res) {
    logger.debug(req.connection.remoteAddress + " PUT/security/user");
    var user_name = users.current_user_name;
    var data_request = { 'function': 'PUT/security/user', 'arguments': { 'only_verify_privileges': true } };
    data_request['url'] = req.originalUrl;
    var filters = { 'enabled': 'boolean', 'password': 'names' };

    if (!filter.check(req.body, filters, req, res))  // Filter with error
        return;

    var user_data = { enabled: req.body.enabled, name: user_name, password: req.body.password };

    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {
        if (python_response.error == 0 && python_response.data) {
            users.update_user(user_data, function (err) {
                var response = {
                    data: {
                        user: {
                            name: user_data.name,
                            enabled: user_data.enabled,
                        },
                        updated: !err
                    }, error: 0
                };
                res_h.send(req, res, response);
            });
        } else {
            res_h.send(req, res, python_response);
        }
    });

});


/**
 * @api {put} /security/users/:user_name Update selected user
 * @apiName UpdateUser
 * @apiGroup UpdateUser
 *
 * @apiParam {String} user_name Name of the selected user.
 * @apiParam {Boolean} enabled To enable or disable the user.
 * 
 * @apiDescription Updates user information for a specific user. Fields that can be updated: enabled, password.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X PUT -H "Content-Type:application/json" -d '{"enabled":true}' "https://127.0.0.1:55000/security/user/foo?pretty"
 *
 */
router.put('/users/:user_name', function (req, res) {
    logger.debug(req.connection.remoteAddress + " PUT/security/users/:user_name");
    var data_request = { 'function': 'PUT/security/users/:user_name', 'arguments': { 'only_verify_privileges': true } };
    data_request['url'] = req.originalUrl;
    var filters = { 'enabled': 'boolean', 'password': 'names'};

    if (!filter.check(req.body, filters, req, res))  // Filter with error
        return;

    if (!filter.check(req.params, { 'user_name': 'names' }, req, res))  // Filter with error
        return;
        
    var user_data = { enabled: req.body.enabled, name: req.params.user_name, password: req.body.password};

    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {
        if (python_response.error == 0 && python_response.data) {
            users.update_user(user_data, function (err, result) {
                if (!err){
                    var response = {
                        data: {
                            user: {
                                name: user_data.name,
                                enabled: user_data.enabled,
                            },
                            updated: !err
                        }, error: 0
                    };
                    res_h.send(req, res, response);
                } else {
                    res_h.bad_request(req, res, "620");
                }
            });
        } else {
            res_h.send(req, res, python_response);
        }
    });

});


/**
 * @api {post} /security/user/register Register new API user
 * @apiName Resgistration
 * @apiGroup Registration
 *
 * @apiParam {String} username User name.
 * @apiParam {String} password User password.
 * 
 * @apiDescription Register a new API user. 
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X POST -H "Content-Type:application/json" -d '{"username":"foo2", "password":"bar2"}' "https://127.0.0.1:55000/security/user/register?pretty"
 *
 */
router.post('/users/register', function (req, res) {
    logger.debug(req.connection.remoteAddress + " POST/security/users/register");
    var data_request = { 'function': 'POST/security/users/register', 'arguments': { 'only_verify_privileges': true } };
    data_request['url'] = req.originalUrl;
    var user_data = { name: req.body.name, password: req.body.password };

    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {
        if (python_response.error == 0 && python_response.data) {
            users.register_user(user_data, function (err) {
                var response = {
                    data: {
                        user: user_data.name,
                        registered: !err
                    }, error: 0
                };
                res_h.send(req, res, response);
            });
        } else {
            res_h.send(req, res, python_response);
        }
    });

});


/**
 * @api {get} /security/users/:user_name Returns information about specific user.
 * @apiName GetCurrentUser
 * @apiGroup GetUser
 *
 * @apiParam {String} user_name Name of the selected user.
 * 
 * @apiDescription Returns information about specific user. Fields that returns: enabled, user_name, roles.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/security/user?pretty"
 *
 */
router.get('/users/:user_name', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET/security/users/:user_name");
    var data_request = { 'function': '/security/users/:user_name', 'arguments': {} };
    data_request['url'] = req.originalUrl;

    if (!filter.check(req.params, { 'user_name': 'names' }, req, res))  // Filter with error
        return;
    var user_name = req.params.user_name
    data_request['arguments']['user_name'] = user_name;

    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {
        if (python_response.error == 0 && python_response.data) {
            users.get_user(user_name, function (err, result) {
                if (!err){
                    var response = {
                        data: {
                            user_name: result.name,
                            enabled: !!parseInt(result.enabled),
                            reserved: !!parseInt(result.reserved),
                            roles: python_response.data.roles,
                            groups: python_response.data.groups
                        }, error: 0
                    };
                    res_h.send(req, res, response);
                } else {
                    res_h.bad_request(req, res, "620");
                }
            });
        } else {
            res_h.send(req, res, python_response);
        }
    });

});



/**
 * @api {get} /security/user Returns information about current user.
 * @apiName GetCurrentUser
 * @apiGroup GetUser
 *
 * @apiDescription Returns information about current user. Fields that returns: enabled, user_name, roles.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/security/user?pretty"
 *
 */
router.get('/user', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET/users");
    var user_name = users.current_user_name;
    var data_request = { 'function': '/security/user', 'arguments': {} };
    data_request['url'] = req.originalUrl;
    data_request['arguments']['user_name'] = user_name;

    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {

        if (python_response.error == 0 && python_response.data) {
            users.get_user(user_name, function (err, result) {
                if (!err){
                    var response = {
                        data: {
                            name: user_name, 
                            enabled: !!parseInt(result.enabled),
                            reserved: !!parseInt(result.reserved),
                            roles: python_response.data.roles,
                            groups: python_response.data.groups,
                            privileges: python_response.data.privileges
                        }, error: 0
                    };
                    res_h.send(req, res, response);
                } else {
                    res_h.bad_request(req, res, "620");
                }
            });
        } else {
            res_h.send(req, res, python_response);
        }
    });

});


/**
 * @api {delete} /security/users Get all API users
 * @apiName GetUsers
 * @apiGroup GetUsers
 *
 * @apiDescription Returns all API users.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/security/users?pretty"
 *
 */
router.get('/users', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /security/users");

    var data_request = { 'function': '/security/users', 'arguments': {} };
    data_request['url'] = req.originalUrl

    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {
        if (python_response.error == 0 && python_response.data) {
            users.get_all_users(function (err, result) {
                if (!err){
                    result.forEach(function (user) {
                        user.enabled = !!parseInt(user.enabled);
                        user.reserved = !!parseInt(user.reserved);
                        user.roles = python_response.data[user.name].roles,
                        user.groups = python_response.data[user.name].groups,
                        user.privileges = python_response.data[user.name].privileges
                    });
                    var response = {
                        data: {
                            items: result, totalItems: result.length}
                        , error: 0
                    };
                    res_h.send(req, res, response);
                } else {
                    res_h.bad_request(req, res, "4");
                }
            });
        } else {
            res_h.send(req, res, python_response);
        }
    });
})



/**
 * @api {get} /security/user/:user_name/privileges Returns the privileges of a specific user
 * @apiName GetUserPrivileges
 * @apiGroup Privileges
 *
 * @apiParam {String} user_name Name of the selected user.
 * 
 * @apiDescription Returns the privileges of a specific user.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/security/user/foo/privileges?pretty"
 *
 */
router.get('/users/:user_name/privileges', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET/security/users/:user_name/privileges");
    var data_request = { 'function': '/security/users/:user_name/privileges', 'arguments': {} };
    data_request['url'] = req.originalUrl;

    if (!filter.check(req.params, { 'user_name': 'names' }, req, res))  // Filter with error
        return;
    user_name = req.params.user_name;
    data_request['arguments']['user_name'] = user_name;

    users.exists_user(user_name, function (err, result) {
        if (!err) {
            execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
        } else {
            res_h.bad_request(req, res, "620");
        }
    });

});



/**
 * @api {get} /security/user/:user_name/groups Returns the groups of a specific user
 * @apiName GetUserGroups
 * @apiGroup Groups
 *
 * @apiParam {String} user_name Name of the selected user.
 * 
 * @apiDescription Returns the groups of a specific user.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/security/user/foo/groups?pretty"
 *
 */
router.get('/users/:user_name/groups', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET/security/users/:user_name/groups");
    var data_request = { 'function': '/security/users/:user_name/groups', 'arguments': {} };
    data_request['url'] = req.originalUrl;

    if (!filter.check(req.params, { 'user_name': 'names' }, req, res))  // Filter with error
        return;
    user_name = req.params.user_name;
    data_request['arguments']['user_name'] = user_name;

    users.exists_user(user_name, function (err, result) {
        if (!err) {
            execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
        } else {
            res_h.bad_request(req, res, "620");
        }
    });

});


/**
 * @api {get} /security/user/:user_name/roles Returns the roles of a specific user
 * @apiName GetUserRoles
 * @apiGroup Roles
 *
 * @apiParam {String} user_name Name of the selected user.
 * 
 * @apiDescription Returns the roles of a specific user.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/security/user/foo/roles?pretty"
 *
 */
router.get('/users/:user_name/roles', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET/security/users/:user_name/roles");
    var data_request = { 'function': '/security/users/:user_name/roles', 'arguments': {} };
    data_request['url'] = req.originalUrl;

    if (!filter.check(req.params, { 'user_name': 'names' }, req, res))  // Filter with error
        return;
    user_name = req.params.user_name;
    data_request['arguments']['user_name'] = user_name;

    users.exists_user(user_name, function (err, result) {
        if (!err) {
            execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
        } else {
            res_h.bad_request(req, res, "620");
        }
    });
});


/**
 * @api {get} /security/user/roles Returns the roles of the current user
 * @apiName GetCurrentUserRoles
 * @apiGroup Roles
 *
 * @apiDescription Returns the roles of the current user.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/security/user/roles?pretty"
 *
 */
router.get('/user/roles', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET/security/user/roles");
    var data_request = { 'function': '/security/user/roles', 'arguments': {} };
    data_request['url'] = req.originalUrl;
    data_request['arguments']['user_name'] = users.current_user_name;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
});


/**
 * @api {get} /security/user/privileges Returns the privileges of the current user
 * @apiName GetCurrentUserPrivileges
 * @apiGroup Privileges
 *
 * @apiDescription Returns the privileges of the current user.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/security/user/privileges?pretty"
 *
 */
router.get('/user/privileges', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET/security/user/privileges");
    var data_request = { 'function': '/security/user/privileges', 'arguments': {} };
    data_request['url'] = req.originalUrl;
    data_request['arguments']['user_name'] = users.current_user_name;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
});


/**
 * @api {get} /security/user/groups Returns the privileges of the current user
 * @apiName GetCurrentUserGroups
 * @apiGroup Groups
 *
 * @apiDescription Returns the groups of the current user.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/security/user/groups?pretty"
 *
 */
router.get('/user/groups', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET/security/user/groups");
    var data_request = { 'function': '/security/user/groups', 'arguments': {} };
    data_request['url'] = req.originalUrl;
    data_request['arguments']['user_name'] = users.current_user_name;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
});


/**
 * @api {get} /security/roles_mapping Returns all roles
 * @apiName GetAllRoles
 * @apiGroup Roles
 *
 * @apiDescription Returns roles mapping. Resources, methods, and exceptions for all roles.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/security/roles?pretty"
 *
 */
router.get('/roles_mapping', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET/security/roles_mapping");
    var data_request = { 'function': '/security/roles_mapping', 'arguments': {} };
    data_request['url'] = req.originalUrl;
    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {res_h.send(req, res, python_response)});
});


/**
 * @api {get} /security/groups Returns all groups
 * @apiName GetAllGroups
 * @apiGroup Groups
 *
 * @apiDescription Returns all existing groups in the API.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/security/groups?pretty"
 *
 */
router.get('/groups', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET/security/groups");
    var data_request = { 'function': '/security/groups', 'arguments': {} };
    data_request['url'] = req.originalUrl;
    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) { res_h.send(req, res, python_response) });
});


/**
 * @api {delete} /security/users/:user_name Delete an API user
 * @apiName DeleteUser
 * @apiGroup Delete
 *
 * @apiParam {String} user_name Name of the selected user.
 *
 * @apiDescription Removes a specific API user.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/security/users/foo2?pretty"
 *
 */
router.delete('/users/:user_name', function (req, res) {
    logger.debug(req.connection.remoteAddress + " DELETE/security/users/:user_name");

    var data_request = { 'function': 'DELETE/security/users/:user_name', 'arguments': { 'only_verify_privileges': true } };

    if (!filter.check(req.body, { 'user_name': 'names' }, req, res))  // Filter with error
        return;

    var user_name = req.params.user_name;
    data_request['url'] = req.originalUrl

    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {
        if (python_response.error == 0 && python_response.data) {
            users.delete_user(user_name, function (err) {
                var response = {
                    data: {
                        user: user_name,
                        deleted: !err
                    }, error: 0
                };
                res_h.send(req, res, response);
            });
        } else {
            res_h.send(req, res, python_response);
        }
    });
    
})



module.exports = router;
