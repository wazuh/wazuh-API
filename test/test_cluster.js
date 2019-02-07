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

var should = require('should');
var assert = require('assert');
var request = require('supertest');
var glob = require('glob');
var common = require('./common.js');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

var path_rules = 'etc/rules/test_rules.xml'
var path_decoders = 'etc/decoders/test_decoder.xml'
var path_lists = 'etc/lists/test_list'

describe('Cluster', function () {


    describe('GET/cluster/nodes', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/cluster/nodes")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['name', 'ip', 'version', 'type']);
                    done();
                });
        });

        it('Pagination', function (done) {
            request(common.url)
                .get("/cluster/nodes?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['name', 'ip', 'version', 'type']);
                    done();
                });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/cluster/nodes?limit=0")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1406);
                done();
            });
        });

        it('Sort', function (done) {
            request(common.url)
                .get("/cluster/nodes?sort=-name")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['name', 'ip', 'version', 'type']);
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/cluster/nodes?search=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['name', 'ip', 'version', 'type']);
                    done();
                });
        });

        it('Filters: type', function (done) {
            request(common.url)
                .get("/cluster/nodes?type=master")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['name', 'ip', 'version', 'type']);
                    res.body.data.items[0].type.should.be.equal('master');
                    done();
                });
        });

        it('Filters: invalid type', function (done) {
            request(common.url)
                .get("/cluster/nodes?type=wrong_type")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(1728);
                    res.body.message.should.be.instanceof(String)
                    done();
                });
        });

        it('Select', function (done) {
            request(common.url)
                .get("/cluster/nodes?select=name,version")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['name', 'version']);
                    done();
                });
        });

        it('Select 2', function (done) {
            request(common.url)
                .get("/cluster/nodes?select=type")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['type']);
                    done();
                });
        });

        it('Wrong select', function (done) {
            request(common.url)
                .get("/cluster/nodes?select=wrong_field")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(1724);
                    res.body.message.should.be.instanceof(String)
                    done();
                });
        });


    });  // GET/cluster/nodes

    describe('GET/cluster/:node_id/stats', function () {

        var expected_name = "";
        before(function (done) {
            request(common.url)
                .get("/cluster/nodes/")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    expected_name = res.body.data.items[0].name;
                    done();
                });
        });

        it('Cluster stats', function (done) {
            request(common.url)
                .get("/cluster/" + expected_name + "/stats")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    done();
                });
        });

        it('Unexisting node stats', function (done) {
            request(common.url)
                .get("/cluster/unexisting_node/stats")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(3022);
                    res.body.message.should.be.instanceof(String)
                    done();
                });
        });

        it('Analysisd stats', function (done) {
            request(common.url)
                .get("/cluster/:node_id/stats/analysisd")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['archives_queue_size', 'events_dropped',
                                                          'rule_matching_queue_usage', 'alerts_queue_size',
                                                          'event_queue_usage', 'events_edps', 'hostinfo_events_decoded',
                                                          'syscollector_events_decoded', 'rootcheck_edps', 'events_processed',
                                                          'firewall_queue_usage', 'alerts_queue_usage', 'firewall_queue_size',
                                                          'alerts_written', 'firewall_written', 'syscheck_queue_size',
                                                          'events_received', 'rootcheck_queue_usage', 'rootcheck_events_decoded',
                                                          'rootcheck_queue_size', 'syscheck_edps', 'fts_written',
                                                          'syscheck_queue_usage', 'other_events_edps', 'statistical_queue_usage',
                                                          'hostinfo_edps', 'hostinfo_queue_usage', 'syscheck_events_decoded',
                                                          'syscollector_queue_usage', 'archives_queue_usage', 'statistical_queue_size',
                                                          'total_events_decoded', 'hostinfo_queue_size', 'syscollector_queue_size',
                                                          'rule_matching_queue_size', 'other_events_decoded', 'event_queue_size',
                                                          'syscollector_edps']);
                    done();
                });
        });

        it('Remoted stats', function (done) {
            request(common.url)
                .get("/cluster/:node_id/stats/remoted")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    
                    res.body.data.should.have.properties(['discarded_count', 'msg_sent', 'queue_size',
                                                          'ctrl_msg_count', 'evt_count', 'tcp_sessions',
                                                          'total_queue_size']);
                    done();
                });
        });


    });  // GET/cluster/stats


    describe('GET/cluster/nodes/:node_name', function () {

        var expected_name = "";
        before(function (done) {
            request(common.url)
                .get("/cluster/nodes/")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    expected_name = res.body.data.items[0].name;
                    done();
                });
        });

        it('Request', function (done) {
            request(common.url)
                .get("/cluster/nodes/" + expected_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['name', 'ip', 'version', 'type']);
                    done();
                });
        });

        it('Request wrong name', function (done) {
            request(common.url)
                .get("/cluster/nodes/wrong_name")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(1730);
                    res.body.message.should.be.instanceof(String)
                    done();
                });
        });

    });  // GET/cluster/nodes/:node_name


    describe('GET/cluster/status', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/cluster/status")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['running', 'enabled']);

                    res.body.data.running.should.be.instanceof(String);
                    res.body.data.enabled.should.be.instanceof(String);
                    res.body.data.running.should.be.equal("yes");
                    res.body.data.enabled.should.be.equal("yes");
                    done();
                });
        });

    });  // GET/cluster/status


    describe('GET/cluster/config', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/cluster/config")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['disabled', 'hidden', 'name', 'node_name', 'bind_addr', 'node_type', 'key', 'nodes', 'port']);
                    done();
                });
        });

    });  // GET/cluster/config


    describe('GET/cluster/healthcheck', function () {

        var expected_name_master = "";
        var expected_name_worker = "";
        before(function (done) {
            request(common.url)
                .get("/cluster/nodes/")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    expected_name_master = res.body.data.items[1].name;
                    expected_name_worker = res.body.data.items[0].name;
                    done();
                });
        });

        it('Request', function (done) {
            request(common.url)
                .get("/cluster/healthcheck")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['nodes', 'n_connected_nodes']);

                    res.body.data.n_connected_nodes.should.be.above(1)

                    res.body.data.nodes.should.have.properties([expected_name_worker, expected_name_master]);

                    // master
                    res.body.data.nodes[expected_name_master].should.have.properties(['info']);
                    res.body.data.nodes[expected_name_master].info.should.have.properties(['ip', 'version', 'type', 'name', 'n_active_agents']);
                    res.body.data.nodes[expected_name_master].info.n_active_agents.should.be.instanceof(Number)
                    res.body.data.nodes[expected_name_master].info.name.should.be.equal(expected_name_master);
                    res.body.data.nodes[expected_name_master].info.type.should.be.equal('master');


                    // worker
                    res.body.data.nodes[expected_name_worker].should.have.properties(['info', 'status']);

                    res.body.data.nodes[expected_name_worker].info.should.have.properties(['ip', 'version', 'type', 'name', 'n_active_agents']);
                    res.body.data.nodes[expected_name_worker].info.n_active_agents.should.be.instanceof(Number)
                    res.body.data.nodes[expected_name_worker].info.name.should.be.equal(expected_name_worker);
                    res.body.data.nodes[expected_name_worker].info.type.should.be.equal('worker');

                    res.body.data.nodes[expected_name_worker].status.should.have.properties(['last_sync_agentinfo', 'sync_integrity_free', 'last_sync_agentgroups', 'last_sync_integrity', 'sync_agentinfo_free', 'sync_extravalid_free']);

                    res.body.data.nodes[expected_name_worker].status.last_sync_agentinfo.should.have.properties(['date_start_master', 'date_end_master', 'total_agentinfo']);
                    res.body.data.nodes[expected_name_worker].status.last_sync_agentinfo.total_agentinfo.should.be.instanceof(Number);

                    res.body.data.nodes[expected_name_worker].status.sync_integrity_free.should.be.instanceof(Boolean);

                    res.body.data.nodes[expected_name_worker].status.last_sync_agentgroups.should.have.properties(['date_end_master', 'date_start_master', 'total_agentgroups']);
                    res.body.data.nodes[expected_name_worker].status.last_sync_agentgroups.total_agentgroups.should.be.instanceof(Number);

                    res.body.data.nodes[expected_name_worker].status.sync_agentinfo_free.should.be.instanceof(Boolean);
                    res.body.data.nodes[expected_name_worker].status.sync_extravalid_free.should.be.instanceof(Boolean);

                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.should.have.properties(['total_files', 'date_end_master', 'date_start_master']);
                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.total_files.should.have.properties(['shared', 'missing', 'extra_valid', 'extra']);
                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.total_files.shared.should.be.instanceof(Number);
                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.total_files.missing.should.be.instanceof(Number);
                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.total_files.extra_valid.should.be.instanceof(Number);
                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.total_files.extra.should.be.instanceof(Number);

                    done();
                });
        });


        it('Filter: node name', function (done) {
            request(common.url)
                .get("/cluster/healthcheck?node=" + expected_name_worker)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['nodes', 'n_connected_nodes']);

                    res.body.data.n_connected_nodes.should.be.above(1)

                    res.body.data.nodes.should.have.properties([expected_name_worker]);


                    // worker
                    res.body.data.nodes[expected_name_worker].should.have.properties(['info', 'status']);

                    res.body.data.nodes[expected_name_worker].info.should.have.properties(['ip', 'version', 'type', 'name', 'n_active_agents']);
                    res.body.data.nodes[expected_name_worker].info.n_active_agents.should.be.instanceof(Number)
                    res.body.data.nodes[expected_name_worker].info.name.should.be.equal(expected_name_worker);
                    res.body.data.nodes[expected_name_worker].info.type.should.be.equal('worker');

                    res.body.data.nodes[expected_name_worker].status.should.have.properties(['last_sync_agentinfo', 'sync_integrity_free', 'last_sync_agentgroups', 'last_sync_integrity', 'sync_agentinfo_free', 'sync_extravalid_free']);

                    res.body.data.nodes[expected_name_worker].status.last_sync_agentinfo.should.have.properties(['date_start_master', 'date_end_master', 'total_agentinfo']);
                    res.body.data.nodes[expected_name_worker].status.last_sync_agentinfo.total_agentinfo.should.be.instanceof(Number);

                    res.body.data.nodes[expected_name_worker].status.sync_integrity_free.should.be.instanceof(Boolean);

                    res.body.data.nodes[expected_name_worker].status.last_sync_agentgroups.should.have.properties(['date_end_master', 'date_start_master', 'total_agentgroups']);
                    res.body.data.nodes[expected_name_worker].status.last_sync_agentgroups.total_agentgroups.should.be.instanceof(Number);

                    res.body.data.nodes[expected_name_worker].status.sync_agentinfo_free.should.be.instanceof(Boolean);
                    res.body.data.nodes[expected_name_worker].status.sync_extravalid_free.should.be.instanceof(Boolean);

                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.should.have.properties(['total_files', 'date_end_master', 'date_start_master']);
                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.total_files.should.have.properties(['shared', 'missing', 'extra_valid', 'extra']);
                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.total_files.shared.should.be.instanceof(Number);
                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.total_files.missing.should.be.instanceof(Number);
                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.total_files.extra_valid.should.be.instanceof(Number);
                    res.body.data.nodes[expected_name_worker].status.last_sync_integrity.total_files.extra.should.be.instanceof(Number);

                    done();
                });
        });

    });  // GET/cluster/healthcheck

    describe('POST/cluster/:node_id/files', function() {

        it('Upload rules', function(done) {
            request(common.url)
            .post("/cluster/node01/files?path=" + path_rules)
            .set("Content-Type", "application/xml")
            .send("<!-- Local rules -->\n  <!-- Modify it at your will. -->\n  <!-- Example -->\n  <group name=\"local,\">\n    <!--   NEW RULE    -->\n    <rule id=\"100001111\" level=\"5\">\n      <if_sid>5716</if_sid>\n      <srcip>1.1.1.1</srcip>\n      <description>sshd: authentication failed from IP 1.1.1.1.</description>\n      <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>\n    </rule>\n  </group>\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) throw err;
                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.string;

                done();
              });
        });

        it('Upload decoder', function(done) {
            request(common.url)
            .post("/cluster/node01/files?path=" + path_decoders)
            .set("Content-Type", "application/xml")
            .send("<!-- NEW Local Decoders -->\n  <!-- Modify it at your will. -->\n  <decoder name=\"local_decoder_example\">\n    <program_name>NEW DECODER</program_name>\n  </decoder>\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) throw err;
                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.string;

                done();
              });
        });

        it('Upload list', function(done) {
            request(common.url)
            .post("/cluster/node01/files?path=" + path_lists)
            .set("Content-Type", "application/octet-stream")
            .send("test-wazuh-w:write\ntest-wazuh-r:read\ntest-wazuh-a:attribute\ntest-wazuh-x:execute\ntest-wazuh-c:command\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) throw err;

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.string;

                done();
              });
        });

        it('Upload malformed rules', function(done) {
            request(common.url)
            .post("/cluster/node01/files?path=" + path_rules)
            .set("Content-Type", "application/xml")
            .send("<!--   NEW RULE    -->\n    <rule id=\"100001111\" level=\"5\">\n      <if_sid>5716</if_sid>\n      <srcip>1.1.1.1</srcip>\n      <description>sshd: authentication failed from IP 1.1.1.1.</description>\n      <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>\n    </rule>\n  </group>\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err, res) {
                if (err) throw err;

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(703);
                res.body.message.should.be.an.string;

                done();
              });
        });

        it('Upload rules to unexisting node', function(done) {
            request(common.url)
            .post("/cluster/TESTNODE001/files?path=" + path_rules)
            .set("Content-Type", "application/xml")
            .send("<!-- Local rules -->\n  <!-- Modify it at your will. -->\n  <!-- Example -->\n  <group name=\"local,\">\n    <!--   NEW RULE    -->\n    <rule id=\"100001111\" level=\"5\">\n      <if_sid>5716</if_sid>\n      <srcip>1.1.1.1</srcip>\n      <description>sshd: authentication failed from IP 1.1.1.1.</description>\n      <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>\n    </rule>\n  </group>\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) throw err;

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(3022);
                res.body.message.should.be.an.string;

                done();
              });
        });


        it('Upload malformed decoder', function(done) {
            request(common.url)
            .post("/cluster/node01/files?path=" + path_decoders)
            .set("Content-Type", "application/xml")
            .send("<!-- NEW Local Decoders -->\n  <!-- Modify it at your will. -->\n  <decoder name=\"local_decoder_example\">\n    <program_name>NEW <DECODER</program_name>\n  </decoder>\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err, res) {
                if (err) throw err;

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(703);
                res.body.message.should.be.an.string;

                done();
              });
        });

        it('Upload decoder to unexisting node', function(done) {
            request(common.url)
            .post("/cluster/TESTNODE001/files?path=" + path_decoders)
            .set("Content-Type", "application/xml")
            .send("<!-- NEW Local Decoders -->\n  <!-- Modify it at your will. -->\n  <decoder name=\"local_decoder_example\">\n    <program_name>NEW DECODER</program_name>\n  </decoder>\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) throw err;

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(3022);
                res.body.message.should.be.an.string;

                done();
              });
        });

        it('Upload malformed list', function(done) {
            request(common.url)
            .post("/cluster/node01/files?path=" + path_lists)
            .set("Content-Type", "application/octet-stream")
            .send("test&%-wazuh-w:write\ntest-wazuh-r:read\ntest-wazuh-a:attribute\ntest-wazuh-x:execute\ntest-wazuh-c:command\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err, res) {
                if (err) throw err;

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(705);
                res.body.message.should.be.an.string;

                done();
              });
        });

        it('Upload list to unexisting node', function(done) {
            request(common.url)
            .post("/cluster/TESTNODE001/files?path=" + path_lists)
            .set("Content-Type", "application/octet-stream")
            .send("test-wazuh-w:write\ntest-wazuh-r:read\ntest-wazuh-a:attribute\ntest-wazuh-x:execute\ntest-wazuh-c:command\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) throw err;

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(3022);
                res.body.message.should.be.an.string;

                done();
              });
        });

    });  // POST/cluster/:node_id/files

    describe('/cluster/:node_id/files', function() {

        after(function(done) {
            var config = require('../configuration/config')
            var path = require('path')
            var fs = require('fs')

            // delete test files
            fs.unlinkSync(path.join(config.ossec_path, path_rules));
            fs.unlinkSync(path.join(config.ossec_path, path_decoders));
            fs.unlinkSync(path.join(config.ossec_path, path_lists));

            done();
        });

        it('Request rules', function(done) {
            request(common.url)
            .get("/cluster/node01/files?path=etc/rules/test_rules.xml")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.string;

                done();
            });
        });

        it('Request decoders', function(done) {
            request(common.url)
            .get("/cluster/node01/files?path=etc/decoders/test_decoder.xml")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.string;

                done();
            });
        });

        it('Request lists', function(done) {
            request(common.url)
            .get("/cluster/node01/files?path=etc/lists/test_list")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.string;

                done();
            });
        });

        it('Request wrong path 1', function(done) {
            request(common.url)
            .get("/cluster/node01/files?path=etc/internal_options.conf")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(704);

                done();
            });
        });

        it('Request wrong path 2', function(done) {
            request(common.url)
            .get("/cluster/node01/files?path=../tmp")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(704);

                done();
            });
        });

        it('Request wrong path 3', function(done) {
            request(common.url)
            .get("/cluster/node01/files?path=./framework/wazuh/agent.py")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(704);

                done();
            });
        });

        it('Request unexisting file', function(done) {
            request(common.url)
            .get("/cluster/node01/files?path=etc/rules/wrong_file.xml")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1005);

                done();
            });
        });

        it('Request file from unexisting node', function(done) {
            request(common.url)
            .get("/cluster/TESTNODE001/files?path=etc/rules/test_rules.xml")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(3022);

                done();
            });
        });

    });  // GET/cluster/:node_id/files


}); // Cluster
