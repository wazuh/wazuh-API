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
var path_ossec_conf = 'etc/ossec.conf'
var ossec_conf_content_master = null
var ossec_conf_content_worker = null

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

    }); // GET/cluster/nodes/:node_name


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

    }); // GET/cluster/status


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

    }); // GET/cluster/config


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

                    res.body.data.n_connected_nodes.should.be.above(0)

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

                    res.body.data.n_connected_nodes.should.be.above(0)

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

    }); // GET/cluster/healthcheck


    describe('POST/cluster/:node_id/files', function() {

        // save master ossec.conf
        before(function (done) {
            request(common.url)
                .get("/cluster/master/files?path=" + path_ossec_conf)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.string;

                    ossec_conf_content_master = res.body.data

                    done();
                });
        });

        // save worker ossec.conf
        before(function (done) {
            request(common.url)
            .get("/cluster/worker-1/files?path=" + path_ossec_conf)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.string;

                    ossec_conf_content_worker = res.body.data

                    done();
                });
        });

        it('Upload ossec.conf (master)', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send(ossec_conf_content_master)
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

        it('Upload ossec.conf (worker)', function(done) {
            request(common.url)
            .post("/cluster/worker-1/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send(ossec_conf_content_worker)
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

        it('Upload rules', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_rules)
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
            .post("/cluster/master/files?path=" + path_decoders)
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
            .post("/cluster/master/files?path=" + path_lists)
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

        it('Upload corrupted ossec.conf (master)', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send("<!--  Wazuh - Manager -->\n  <ossec_config>\n    <global>\n      <jsonout_output><<<<yes</jsonout_output>\n      <alerts_log>yes</alerts_log>\n      <logall>no</logall>\n      <logall_json>no</logall_json>\n      <email_notification>no</email_notification>\n      <smtp_server>smtp.example.wazuh.com</smtp_server>\n      <email_from>ossecm@example.wazuh.com</email_from>\n      <email_to>recipient@example.wazuh.com</email_to>\n      <email_maxperhour>12</email_maxperhour>\n      <email_log_source>alerts.log</email_log_source>\n      <queue_size>131072</queue_size>\n    </global>\n  </ossec_config>\n")
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

        it('Upload corrupted ossec.conf (worker)', function(done) {
            request(common.url)
            .post("/cluster/worker-1/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send("<!--  Wazuh - Manager -->\n  <ossec_config>\n    <global>\n      <jsonout_output><<<<yes</jsonout_output>\n      <alerts_log>yes</alerts_log>\n      <logall>no</logall>\n      <logall_json>no</logall_json>\n      <email_notification>no</email_notification>\n      <smtp_server>smtp.example.wazuh.com</smtp_server>\n      <email_from>ossecm@example.wazuh.com</email_from>\n      <email_to>recipient@example.wazuh.com</email_to>\n      <email_maxperhour>12</email_maxperhour>\n      <email_log_source>alerts.log</email_log_source>\n      <queue_size>131072</queue_size>\n    </global>\n  </ossec_config>\n")
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

        it('Upload malformed rules', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_rules)
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
            .post("/cluster/master/files?path=" + path_decoders)
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
            .post("/cluster/master/files?path=" + path_lists)
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


    describe('GET/cluster/:node_id/files', function() {

        it('Request ossec.conf (master)', function (done) {
            request(common.url)
                .get("/cluster/master/files?path=" + path_ossec_conf)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.string;
                    res.body.data.should.equal(ossec_conf_content_master)

                    done();
                });
        });

        it('Request ossec.conf (worker)', function (done) {
            request(common.url)
                .get("/cluster/worker-1/files?path=" + path_ossec_conf)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.string;
                    res.body.data.should.equal(ossec_conf_content_worker)

                    done();
                });
        });

        it('Request rules', function (done) {
            request(common.url)
                .get("/cluster/master/files?path=" + path_rules)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.string;

                    done();
                });
        });

        it('Request decoders', function(done) {
            request(common.url)
            .get("/cluster/master/files?path=" + path_decoders)
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
            .get("/cluster/master/files?path=" + path_lists)
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
            .get("/cluster/master/files?path=etc/internal_options.conf")
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
            .get("/cluster/master/files?path=../tmp")
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
            .get("/cluster/master/files?path=./framework/wazuh/agent.py")
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
            .get("/cluster/master/files?path=etc/rules/wrong_file.xml")
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


    describe('GET/cluster/:node_id/configuration/validation (manager and worker OK)', function() {

        it('Request validation (master)', function (done) {
            request(common.url)
                .get("/cluster/master/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['status']);
                    res.body.data.status.should.equal('OK');

                    done();
                });
        });

        it('Request validation (worker)', function (done) {
            request(common.url)
                .get("/cluster/worker-1/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['status']);
                    res.body.data.status.should.equal('OK');

                    done();
                });
        });

        it('Request validation (all nodes)', function (done) {
            request(common.url)
                .get("/cluster/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);

                    res.body.data.should.have.properties(['status']);
                    res.body.data.status.should.equal('OK');

                    done();
                });
        });

    });  // GET/cluster/:node_id/configuration/validation (manager and worker OK)


    describe('GET/cluster/:node_id/configuration/validation (manager KO, worker OK)', function() {

        // upload corrupted ossec.conf in master (semantic)
        before(function (done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send("<!--  Wazuh - Manager -->\n  <ossec_config>\n    <global>\n      <jsonout_output>WRONG_VALUE</jsonout_output>\n      <alerts_log>yes</alerts_log>\n      <logall>no</logall>\n      <logall_json>no</logall_json>\n      <email_notification>no</email_notification>\n      <smtp_server>smtp.example.wazuh.com</smtp_server>\n      <email_from>ossecm@example.wazuh.com</email_from>\n      <email_to>recipient@example.wazuh.com</email_to>\n      <email_maxperhour>12</email_maxperhour>\n      <email_log_source>alerts.log</email_log_source>\n      <queue_size>131072</queue_size>\n    </global>\n <cluster>\n      <name>wazuh</name>\n      <node_name>master</node_name>\n      <node_type>master</node_type>\n      <key>XXXX</key>\n      <port>1516</port>\n      <bind_addr>192.168.122.111</bind_addr>\n      <nodes>\n        <node>192.168.122.111</node>\n      </nodes>\n      <hidden>no</hidden>\n      <disabled>no</disabled>\n    </cluster>\n  </ossec_config>\n")
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

        // restore ossec.conf (master)
        after(function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send(ossec_conf_content_master)
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

        it('Request validation (master)', function (done) {
            request(common.url)
                .get("/cluster/master/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['status', 'details']);
                    res.body.data.status.should.equal('KO');
                    res.body.data.details.should.be.instanceof(Array);

                    done();
                });
        });

        it('Request validation (worker)', function (done) {
            request(common.url)
                .get("/cluster/worker-1/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.error.should.equal(0);

                    res.body.data.should.have.properties(['status']);
                    res.body.data.status.should.equal('OK');

                    done();
                });
        });

        it('Request validation (all nodes)', function (done) {
            request(common.url)
                .get("/cluster/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['status', 'details']);
                    res.body.data.status.should.equal('KO');
                    res.body.data.details.should.be.instanceof(Array);


                    done();
                });
        });

    });  // GET/cluster/:node_id/configuration/validation (manager KO, worker KO)


    describe('GET/cluster/:node_id/configuration/validation (manager OK, worker KO)', function() {

        // upload corrupted ossec.conf in worker (semantic)
        before(function (done) {
            request(common.url)
            .post("/cluster/worker-1/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send("<!--  Wazuh - Manager -->\n  <ossec_config>\n    <global>\n      <jsonout_output>WRONG_VALUE</jsonout_output>\n      <alerts_log>yes</alerts_log>\n      <logall>no</logall>\n      <logall_json>no</logall_json>\n      <email_notification>no</email_notification>\n      <smtp_server>smtp.example.wazuh.com</smtp_server>\n      <email_from>ossecm@example.wazuh.com</email_from>\n      <email_to>recipient@example.wazuh.com</email_to>\n      <email_maxperhour>12</email_maxperhour>\n      <email_log_source>alerts.log</email_log_source>\n      <queue_size>131072</queue_size>\n    </global>\n  </ossec_config>\n")
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

        // restore ossec.conf (worker)
        after(function(done) {
            request(common.url)
            .post("/cluster/worker-1/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send(ossec_conf_content_worker)
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

        it('Request validation (master)', function (done) {
            request(common.url)
                .get("/cluster/master/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['status']);
                    res.body.data.status.should.equal('OK');

                    done();
                });
        });

        it('Request validation (worker)', function (done) {
            request(common.url)
                .get("/cluster/worker-1/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.error.should.equal(0);

                    res.body.data.should.have.properties(['status', 'details']);
                    res.body.data.status.should.equal('KO');
                    res.body.data.details.should.be.instanceof(Array);

                    done();
                });
        });


        it('Request validation (all nodes)', function (done) {
            request(common.url)
                .get("/cluster/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);

                    res.body.data.should.have.properties(['status', 'details']);
                    res.body.data.status.should.equal('KO');
                    res.body.data.details.should.be.instanceof(Array);

                    done();
                });
        });

    });  // GET/cluster/:node_id/configuration/validation (manager OK, worker KO)


    describe('GET/cluster/:node_id/configuration/validation (manager and worker KO)', function() {

        // upload corrupted ossec.conf in master (semantic)
        before(function (done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send("<!--  Wazuh - Manager -->\n  <ossec_config>\n    <global>\n      <jsonout_output>WRONG_VALUE</jsonout_output>\n      <alerts_log>yes</alerts_log>\n      <logall>no</logall>\n      <logall_json>no</logall_json>\n      <email_notification>no</email_notification>\n      <smtp_server>smtp.example.wazuh.com</smtp_server>\n      <email_from>ossecm@example.wazuh.com</email_from>\n      <email_to>recipient@example.wazuh.com</email_to>\n      <email_maxperhour>12</email_maxperhour>\n      <email_log_source>alerts.log</email_log_source>\n      <queue_size>131072</queue_size>\n    </global>\n <cluster>\n      <name>wazuh</name>\n      <node_name>master</node_name>\n      <node_type>master</node_type>\n      <key>XXXXX</key>\n      <port>1516</port>\n      <bind_addr>192.168.122.111</bind_addr>\n      <nodes>\n        <node>192.168.122.111</node>\n      </nodes>\n      <hidden>no</hidden>\n      <disabled>no</disabled>\n    </cluster>\n  </ossec_config>\n")
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

        // upload corrupted ossec.conf in worker (semantic)
        before(function (done) {
            request(common.url)
            .post("/cluster/worker-1/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send("<!--  Wazuh - Manager -->\n  <ossec_config>\n    <global>\n      <jsonout_output>WRONG_VALUE</jsonout_output>\n      <alerts_log>yes</alerts_log>\n      <logall>no</logall>\n      <logall_json>no</logall_json>\n      <email_notification>no</email_notification>\n      <smtp_server>smtp.example.wazuh.com</smtp_server>\n      <email_from>ossecm@example.wazuh.com</email_from>\n      <email_to>recipient@example.wazuh.com</email_to>\n      <email_maxperhour>12</email_maxperhour>\n      <email_log_source>alerts.log</email_log_source>\n      <queue_size>131072</queue_size>\n    </global>\n  </ossec_config>\n")
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

        // restore ossec.conf (master)
        after(function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send(ossec_conf_content_master)
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

        // restore ossec.conf (worker)
        after(function(done) {
            request(common.url)
            .post("/cluster/worker-1/files?path=" + path_ossec_conf)
            .set("Content-Type", "application/xml")
            .send(ossec_conf_content_worker)
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

        it('Request validation (master)', function (done) {
            request(common.url)
                .get("/cluster/worker-1/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['status', 'details']);
                    res.body.data.status.should.equal('KO');
                    res.body.data.details.should.be.instanceof(Array);

                    done();
                });
        });

        it('Request validation (worker)', function (done) {
            request(common.url)
                .get("/cluster/worker-1/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['status', 'details']);
                    res.body.data.status.should.equal('KO');
                    res.body.data.details.should.be.instanceof(Array);

                    done();
                });
        });

        it('Request validation (all nodes)', function (done) {
            request(common.url)
                .get("/cluster/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['status', 'details']);
                    res.body.data.status.should.equal('KO');
                    res.body.data.details.should.be.instanceof(Array);

                    done();
                });
        });

    });  // GET/cluster/:node_id/configuration/validation (manager and worker KO)

    describe('DELETE/cluster/:node_id/files', function() {

        // upload a file in worker
        before(function (done) {
            request(common.url)
            .post("/cluster/worker-1/files?path=" + path_rules)
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

        it('Delete rules (master)', function(done) {
            request(common.url)
            .delete("/cluster/master/files?path=" + path_rules)
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

        it('Delete decoders (master)', function(done) {
            request(common.url)
            .delete("/cluster/master/files?path=" + path_decoders)
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

        it('Delete CDB list (master)', function(done) {
            request(common.url)
            .delete("/cluster/master/files?path=" + path_lists)
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

        it('Delete rules (worker)', function(done) {
            request(common.url)
            .delete("/cluster/worker-1/files?path=" + path_rules)
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

    });  // DELETE/manager/files

    describe('PUT/cluster/:node_id/restart', function() {

        it('Request (worker)', function(done) {
            request(common.url)
            .put("/cluster/worker-1/restart")
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


        it('Request (master)', function(done) {
            request(common.url)
            .put("/cluster/master/restart")
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
    });  // PUT/cluster/:node_id/restart


}); // Cluster
