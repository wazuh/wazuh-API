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

        it('Filters: query 1', function (done) {
            request(common.url)
                .get("/cluster/nodes?q=name~worker&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['name', 'ip', 'version', 'type']);
                    res.body.data.items[0].type.should.be.equal('worker');
                    res.body.data.totalItems.should.equal(2)
                    done();
                });
        });

        it('Filters: query 2', function (done) {
            request(common.url)
            request(common.url)
            .get("/cluster/nodes?q=name=worker-1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type", /json/)
            .expect(200)
            .end(function (err, res) {
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['items', 'totalItems']);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(['name', 'ip', 'version', 'type']);
                res.body.data.items[0].type.should.be.equal('worker');
                res.body.data.items[0].name.should.be.equal('worker-1');
                res.body.data.totalItems.should.equal(1)
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

        it('Analysisd stats (master)', function (done) {
            request(common.url)
                .get("/cluster/master/stats/analysisd")
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

        it('Analysisd stats (worker-1)', function (done) {
            request(common.url)
                .get("/cluster/worker-1/stats/analysisd")
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

        it('Analysisd stats (worker-2)', function (done) {
            request(common.url)
                .get("/cluster/worker-2/stats/analysisd")
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

        it('Remoted stats (master)', function (done) {
            request(common.url)
                .get("/cluster/master/stats/remoted")
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

        it('Remoted stats (worker-1)', function (done) {
            request(common.url)
                .get("/cluster/worker-1/stats/remoted")
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

        it('Remoted stats (worker-2)', function (done) {
            request(common.url)
                .get("/cluster/worker-2/stats/remoted")
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


    describe('GET/cluster/:node_id/logs', function () {

        it('Request (master)', function (done) {
            request(common.url)
            .get("/cluster/master/logs")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.totalItems.should.be.instanceof(Number);
                    res.body.data.items[0].should.have.properties(['timestamp', 'tag', 'level', 'description']);

                    done();
                });
        });

        it('Request (worker-1)', function (done) {
            request(common.url)
            .get("/cluster/worker-1/logs")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.totalItems.should.be.instanceof(Number);
                    res.body.data.items[0].should.have.properties(['timestamp', 'tag', 'level', 'description']);

                    done();
                });
        });

        it('Request (worker-2)', function (done) {
            request(common.url)
            .get("/cluster/worker-2/logs")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.totalItems.should.be.instanceof(Number);
                    res.body.data.items[0].should.have.properties(['timestamp', 'tag', 'level', 'description']);

                    done();
                });
        });

        it('Pagination', function (done) {
            request(common.url)
            .get("/cluster/master/logs?offset=1&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.totalItems.should.be.instanceof(Number);
                    res.body.data.items[0].should.have.properties(['timestamp', 'tag', 'level', 'description']);

                    done();
                });
        });

        it('Sort', function (done) {
            request(common.url)
            .get("/cluster/master/logs?sort=timestamp")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.totalItems.should.be.instanceof(Number);
                    res.body.data.items[0].should.have.properties(['timestamp', 'tag', 'level', 'description']);

                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
            .get("/cluster/master/logs?search=analysisd&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.totalItems.should.be.instanceof(Number);
                    res.body.data.items[0].should.have.properties(['timestamp', 'tag', 'level', 'description']);
                    res.body.data.items[0].tag.should.be.equal('ossec-analysisd');

                    done();
                });
        });

        it('Filters: type_log', function (done) {
            request(common.url)
            .get("/cluster/master/logs?type_log=info&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.totalItems.should.be.instanceof(Number);
                    res.body.data.items[0].should.have.properties(['timestamp', 'tag', 'level', 'description']);
                    res.body.data.items[0].level.should.be.equal('info');

                    done();
                });
        });

        it('Filters: category', function (done) {
            request(common.url)
            .get("/cluster/master/logs?category=ossec-execd&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.totalItems.should.be.instanceof(Number);
                    res.body.data.items[0].should.have.properties(['timestamp', 'tag', 'level', 'description']);
                    res.body.data.items[0].tag.should.be.equal('ossec-execd');

                    done();
                });
        });

        it('Filters: query 1', function (done) {
            request(common.url)
            .get("/cluster/master/logs?q=tag=ossec-analysisd;level=info&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.totalItems.should.be.instanceof(Number);
                    res.body.data.items[0].should.have.properties(['timestamp', 'tag', 'level', 'description']);
                    res.body.data.items[0].tag.should.be.equal('ossec-analysisd');
                    res.body.data.items[0].level.should.be.equal('info');

                    done();
                });
        });

        it('Filters: query 2', function (done) {
            request(common.url)
            .get("/cluster/master/logs?q=tag=ossec-analysisd;level=info&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.totalItems.should.be.instanceof(Number);
                    res.body.data.items[0].should.have.properties(['timestamp', 'tag', 'level', 'description']);
                    res.body.data.items[0].tag.should.be.equal('ossec-analysisd');
                    res.body.data.items[0].level.should.be.equal('info');

                    done();
                });
        });

        it('Filters: query 3', function (done) {
            request(common.url)
            .get("/cluster/master/logs?q=tag~ossec;level=info&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.totalItems.should.be.instanceof(Number);
                    res.body.data.items[0].should.have.properties(['timestamp', 'tag', 'level', 'description']);
                    res.body.data.items[0].tag.should.startWith('ossec');
                    res.body.data.items[0].level.should.be.equal('info');

                    done();
                });
        });

        it('Filters: wrong query', function (done) {
            request(common.url)
            .get("/cluster/master/logs?q=ossec")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(622);

                    done();
                });
        });

    });  // GET/cluster/:node_id/logs


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
                    expected_name_master = res.body.data.items[0].name;
                    expected_name_worker = res.body.data.items[1].name;
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
            .post("/cluster/master/files?path=" + path_ossec_conf + "&overwrite=true")
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
            .post("/cluster/worker-1/files?path=" + path_ossec_conf + "&overwrite=true")
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

        it('Upload new rules', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_rules + "&overwrite=true")
            .set("Content-Type", "application/xml")
            .send("<!-- Local rules -->\n  <!-- Modify it at your will. -->\n  <!-- Example -->\n  <group name=\"local,\">\n    <!--   NEW RULE    -->\n    <rule id=\"111111\" level=\"5\">\n      <if_sid>5716</if_sid>\n      <srcip>1.1.1.1</srcip>\n      <description>sshd: authentication failed from IP 1.1.1.1.</description>\n      <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>\n    </rule>\n  </group>\n")
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

        it('Upload rules (overwrite=true)', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_rules + "&overwrite=true")
            .set("Content-Type", "application/xml")
            .send("<!-- Local rules -->\n  <!-- Modify it at your will. -->\n  <!-- Example -->\n  <group name=\"local,\">\n    <!--   NEW RULE    -->\n    <rule id=\"111111\" level=\"5\">\n      <if_sid>5716</if_sid>\n      <srcip>1.1.1.1</srcip>\n      <description>sshd: authentication failed from IP 1.1.1.1.</description>\n      <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>\n    </rule>\n  </group>\n")
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

        it('Upload rules (overwrite=false)', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_rules + "&overwrite=false")
            .set("Content-Type", "application/xml")
            .send("<!-- Local rules -->\n  <!-- Modify it at your will. -->\n  <!-- Example -->\n  <group name=\"local,\">\n    <!--   NEW RULE    -->\n    <rule id=\"111111\" level=\"5\">\n      <if_sid>5716</if_sid>\n      <srcip>1.1.1.1</srcip>\n      <description>sshd: authentication failed from IP 1.1.1.1.</description>\n      <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>\n    </rule>\n  </group>\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) throw err;
                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1905);
                res.body.message.should.be.an.string;

                done();
              });
        });

        it('Upload new decoder', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_decoders + "&overwrite=true")
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

        it('Upload decoder (overwrite=true)', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_decoders + "&overwrite=true")
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

        it('Upload decoder (without overwrite parameter)', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_decoders)
            .set("Content-Type", "application/xml")
            .send("<!-- NEW Local Decoders -->\n  <!-- Modify it at your will. -->\n  <decoder name=\"local_decoder_example\">\n    <program_name>NEW DECODER</program_name>\n  </decoder>\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) throw err;
                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1905);
                res.body.message.should.be.an.string;

                done();
              });
        });

        it('Upload new list', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_lists + "&overwrite=true")
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

        it('Upload list (overwrite=true)', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_lists + "&overwrite=true")
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

        it('Upload list (overwrite=false)', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_lists + "&overwrite=false")
            .set("Content-Type", "application/octet-stream")
            .send("test-wazuh-w:write\ntest-wazuh-r:read\ntest-wazuh-a:attribute\ntest-wazuh-x:execute\ntest-wazuh-c:command\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) throw err;

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1905);
                res.body.message.should.be.an.string;

                done();
              });
        });

        it('Upload corrupted ossec.conf (master)', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=" + path_ossec_conf + "&overwrite=true")
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
            .post("/cluster/worker-1/files?path=" + path_ossec_conf + "&overwrite=true")
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
            .post("/cluster/master/files?path=" + path_rules + "&overwrite=true")
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
            .post("/cluster/master/files?path=" + path_decoders + "&overwrite=true")
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
            .post("/cluster/master/files?path=" + path_lists + "&overwrite=true")
            .set("Content-Type", "application/octet-stream")
            .send(":write\ntest-wazuh-r:read\ntest-wazuh-a:attribute\ntest-wazuh-x:execute\ntest-wazuh-c:command\n")
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

        it('Upload list with empty path', function(done) {
            request(common.url)
            .post("/cluster/master/files")
            .set("Content-Type", "application/octet-stream")
            .send("test&%-wazuh-w:write\ntest-wazuh-r:read\ntest-wazuh-a:attribute\ntest-wazuh-x:execute\ntest-wazuh-c:command\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err, res) {
                if (err) throw err;

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(706);
                res.body.message.should.be.an.string;

                done();
              });
        });

        it('Upload a file with a wrong content type', function(done) {
            request(common.url)
            .post("/cluster/master/files?path=etc/lists/new-list")
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send("test&%-wazuh-w:write\ntest-wazuh-r:read\ntest-wazuh-a:attribute\ntest-wazuh-x:execute\ntest-wazuh-c:command\n")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err, res) {
                if (err) throw err;

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(804);
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

        it('Request rules (local)', function (done) {
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

        it('Request rules (global)', function (done) {
            request(common.url)
                .get("/cluster/master/files?path=ruleset/rules/0095-sshd_rules.xml")
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

        it('Request decoders (local)', function(done) {
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

        it('Request decoders (global)', function(done) {
            request(common.url)
            .get("/cluster/master/files?path=ruleset/decoders/0025-apache_decoders.xml")
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

        it('Request file with empty path', function(done) {
            request(common.url)
            .get("/cluster/master/files")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(706);
                res.body.message.should.be.an.string;

                done();
            });
        });

        it('Request file with validation parameter (true)', function(done) {
            request(common.url)
            .get("/cluster/master/files?path=" + path_lists + "&validation=true")
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
            .post("/cluster/master/files?path=" + path_ossec_conf + "&overwrite=true")
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
            .post("/cluster/master/files?path=" + path_ossec_conf + "&overwrite=true")
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
            .post("/cluster/worker-1/files?path=" + path_ossec_conf + "&overwrite=true")
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
            .post("/cluster/worker-1/files?path=" + path_ossec_conf + "&overwrite=true")
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
            .post("/cluster/master/files?path=" + path_ossec_conf + "&overwrite=true")
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
            .post("/cluster/worker-1/files?path=" + path_ossec_conf + "&overwrite=true")
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
            .post("/cluster/master/files?path=" + path_ossec_conf + "&overwrite=true")
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
            .post("/cluster/worker-1/files?path=" + path_ossec_conf + "&overwrite=true")
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

        it('Delete file with empty path', function(done) {
            request(common.url)
            .delete("/cluster/master/files")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(706);
                res.body.message.should.be.an.string;

                done();
            });
        });

    });  // DELETE/cluster/master/files

    describe('GET/cluster/master/config/:component/:configuration', function () {

		// agentless
		it('Request-Agentless-Agentless', function(done) {
            request(common.url)
            .get("/cluster/master/config/agentless/agentless")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('agentless'); // returns an array
                res.body.data.agentless[0].should.have.properties(['state', 'host',
                'frequency', 'arguments', 'type', 'port']);

                res.body.error.should.equal(0);
                done();
            });
        });

        // analysis
		it('Request-Analysis-Global', function(done) {
            request(common.url)
            .get("/cluster/worker-1/config/analysis/global")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['global']);
                res.body.data.global.should.have.properties(['email_notification', 'max_output_size',
                'alerts_log', 'zeromq_output', 'host_information', 'jsonout_output', 'rotate_interval',
                'rootkit_detection', 'integrity_checking', 'memory_size', 'logall', 'prelude_output',
                'stats', 'white_list', 'logall_json']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Analysis-Active-response', function(done) {
            request(common.url)
            .get("/cluster/master/config/analysis/active_response")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                // res.body.data.should.have.properties(['active_response']); // empty list

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Analysis-Alerts', function(done) {
            request(common.url)
            .get("/cluster/worker-1/config/analysis/alerts")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['alerts']);
                res.body.data.alerts.should.have.properties(['email_alert_level', 'log_alert_level']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Analysis-Command', function(done) {
            request(common.url)
            .get("/cluster/master/config/analysis/command")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('command');
                res.body.data.command[0].should.have.properties(['executable', 'timeout_allowed',
                'name', 'expect']);
                res.body.data.command[1].should.have.properties(['executable', 'timeout_allowed',
                'name']);
                res.body.data.command[2].should.have.properties(['executable', 'timeout_allowed',
                'name', 'expect']);
                res.body.data.command[3].should.have.properties(['executable', 'timeout_allowed',
                'name', 'expect']);
                res.body.data.command[4].should.have.properties(['executable', 'timeout_allowed',
                'name', 'expect']);
                res.body.data.command[5].should.have.properties(['executable', 'timeout_allowed',
                'name', 'expect']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Analysis-Internal', function(done) {
            request(common.url)
            .get("/cluster/worker-1/config/analysis/internal")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('internal');
                res.body.data.internal.should.have.properties(['analysisd']);
                res.body.data.internal.analysisd.should.have.properties(['label_cache_maxage',
                'stats_percent_diff', 'show_hidden_labels', 'decoder_order_size',
                'min_rotate_interval', 'stats_mindiff', 'log_fw', 'rlimit_nofile', 'fts_list_size',
                'debug', 'fts_min_size_for_str', 'default_timeframe', 'stats_maxdiff']);

                res.body.error.should.equal(0);
                done();
            });
        });

        // auth
		it('Request-Auth-Auth', function(done) {
            request(common.url)
            .get("/cluster/master/config/auth/auth")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('auth');
                res.body.data.auth.should.have.properties(['purge', 'ssl_auto_negotiate', 'ciphers',
                'force_insert', 'ssl_verify_host', 'limit_maxagents', 'force_time',
                'ssl_manager_key', 'disabled', 'ssl_manager_cert', 'use_source_ip',
                'use_password', 'port']);

                res.body.error.should.equal(0);
                done();
            });
        });

        // com
		it('Request-Com-Active-response', function(done) {
            request(common.url)
            .get("/cluster/worker-1/config/com/active-response")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['active-response']);
                res.body.data['active-response'].should.have.properties(['disabled', 'ca_verification']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Com-Internal', function(done) {
            request(common.url)
            .get("/cluster/master/config/com/internal")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['internal']);
                res.body.data.internal.should.have.properties(['execd']);
                res.body.data.internal.execd.should.have.properties(['request_timeout', 'max_restart_lock']);

                res.body.error.should.equal(0);
                done();
            });
        });

        // csyslog
		it('Request-Csyslog-Csyslog', function(done) {
            request(common.url)
            .get("/cluster/master/config/csyslog/csyslog")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['syslog_output']);
                res.body.data['syslog_output'][0].should.have.properties(['format',
                'level', 'use_fqdn', 'port', 'server']);

                res.body.error.should.equal(0);
                done();
            });
        });

        // integrator
		it('Request-Integrator-Integration', function(done) {
            request(common.url)
            .get("/cluster/master/config/integrator/integration")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('integration');
                res.body.data.integration[0].should.have.properties(['alert_format', 'hook_url',
                'group', 'name', 'level']);

                res.body.error.should.equal(0);
                done();
            });
        });

        // logcollector  // fails without any motive
		it('Request-Logcollector-Localfile', function(done) {
            request(common.url)
            .get("/cluster/worker-1/config/logcollector/localfile")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('localfile');

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Logcollector-Socket', function(done) {
            request(common.url)
            .get("/cluster/master/config/logcollector/socket")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                // res.body.should.have.properties(['error', 'data']); // data property is empty
                // res.body.data.should.have.properties(['socket']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Logcollector-Internal', function(done) {
            request(common.url)
            .get("/cluster/worker-1/config/logcollector/internal")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('internal');
                res.body.data.internal.should.have.properties('logcollector');
				res.body.data.internal.logcollector.should.have.properties(['open_attempts', 'input_threads',
                'vcheck_files', 'max_files', 'sock_fail_time', 'queue_size', 'max_lines', 'remote_commands',
                'loop_timeout', 'debug', 'open_attempts']);

                res.body.error.should.equal(0);
                done();
            });
        });

        // mail
		it('Request-Mail-Global', function(done) {
            request(common.url)
            .get("/cluster/master/config/mail/global")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('global');
                res.body.data.global.should.have.properties(['email_maxperhour', 'email_to',
                'email_from', 'smtp_server']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Mail-Alerts', function(done) {
            request(common.url)
            .get("/cluster/master/config/mail/alerts")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                // res.body.should.have.properties(['error', 'data']); // data property is empty

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Mail-Internal', function(done) {
            request(common.url)
            .get("/cluster/master/config/mail/internal")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('internal');
                res.body.data.internal.should.have.properties('mail');
                res.body.data.internal.mail.should.have.properties(['strict_checking',
                'grouping']);

                res.body.error.should.equal(0);
                done();
            });
        });

        // monitor
		it('Request-Monitor-Internal', function(done) {
            request(common.url)
            .get("/cluster/worker-1/config/monitor/internal")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('monitord');

                res.body.error.should.equal(0);
                done();
            });
        });

        // request
		it('Request-Request-Remote', function(done) {
            request(common.url)
            .get("/cluster/master/config/request/remote")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('remote');

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Request-Internal', function(done) {
            request(common.url)
            .get("/cluster/worker-1/config/request/internal")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('internal');
                res.body.data.internal.should.have.properties('remoted');
                res.body.data.internal.remoted.should.have.properties(['request_timeout', 'pass_empty_keyfile',
                'recv_timeout', 'request_rto_sec', 'request_rto_msec', 'response_timeout', 'sender_pool', 'recv_counter_flush',
                'request_pool', 'comp_average_printout', 'shared_reload', 'merge_shared', 'rlimit_nofile',
                'verify_msg_id', 'max_attempts']);

                res.body.error.should.equal(0);
                done();
            });
        });

        // syscheck
		it('Request-Syscheck-Syscheck', function(done) {
            request(common.url)
            .get("/cluster/master/config/syscheck/syscheck")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['syscheck']);
                res.body.data.syscheck.should.have.properties(['ignore', 'skip_nfs', 'directories',
                'scan_on_start', 'disabled', 'frequency', 'whodata', 'nodiff']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Syscheck-Rootcheck', function(done) {
            request(common.url)
            .get("/cluster/master/config/syscheck/rootcheck")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['rootcheck']);
                res.body.data.rootcheck.should.have.properties(['check_unixaudit', 'check_sys', 'rootkit_trojans',
                'skip_nfs', 'check_if', 'check_pids', 'check_dev', 'check_ports', 'disabled', 'rootkit_files',
                // 'frequency', 'scanall', 'check_trojans', 'base_directory', 'check_files', 'system_audit']); // base directory value is empty, this cause an error, system_audit is optional
                'frequency', 'scanall', 'check_trojans', 'check_files']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Request-Syscheck-Internal', function(done) {
            request(common.url)
            .get("/cluster/master/config/syscheck/internal")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['internal']);
                res.body.data.internal.should.have.properties(['syscheck', 'rootcheck']);

                res.body.error.should.equal(0);
                done();
            });
        });

        // wmodules
		it('Request-Wmodules-Wmodules', function(done) {
            request(common.url)
            .get("/cluster/master/config/wmodules/wmodules")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['wmodules']);

                res.body.error.should.equal(0);

                // get the name of the modules
                var modules = []
                for (i in res.body.data.wmodules) {
                    modules.push(Object.keys(res.body.data.wmodules[i])[0])
                }

                // list of modules which should be present in the request
                module_list = ['cis-cat', 'database', 'open-scap', 'osquery', 'sca', 'syscollector', 'vulnerability-detector', 'wazuh_control', 'wazuh_download']

                // check modules
                should((JSON.stringify(module_list.sort()))).be.eql(JSON.stringify(modules.sort()))

                done();
            });
        });

    }); // GET/cluster/master/config/:component/:configuration

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
