/**
 * API RESTful for OSSEC
 * Copyright (C) 2015-2019 Wazuh, Inc. All rights reserved.
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
var common = require('./common.js');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

var path_rules = 'etc/rules/test_rules.xml'
var path_decoders = 'etc/decoders/test_decoder.xml'
var path_lists = 'etc/lists/test_list'
var path_ossec_conf = 'etc/ossec.conf'
var ossec_conf_content = null

describe('Manager', function() {

    describe('GET/manager/status', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/status")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);

                res.body.data.should.have.properties(['ossec-agentlessd', 'ossec-analysisd', 'ossec-authd', 'ossec-csyslogd', 'ossec-dbd', 'ossec-monitord',
                                                      'ossec-execd', 'ossec-integratord', 'ossec-logcollector', 'ossec-maild', 'ossec-remoted',
                                                      'ossec-reportd', 'ossec-syscheckd', 'wazuh-clusterd', 'wazuh-modulesd', 'wazuh-db']);
                done();
            });
        });

    });  // GET/manager/status

    describe('GET/manager/info', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/info")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['path', 'compilation_date', 'version', 'type']);
                done();
            });
        });

    });  // GET/manager/info

    describe('GET/manager/configuration', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/configuration")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['global', 'ruleset', 'syscheck', 'rootcheck', 'remote', 'localfile']);
                done();
            });
        });

        it('Filters: Missing field section', function(done) {
            request(common.url)
            .get("/manager/configuration?field=hi")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                res.body.message.should.be.an.string;
                done();
            });
        });

        it('Filters: Section', function(done) {
            request(common.url)
            .get("/manager/configuration?section=ruleset")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['decoder_dir', 'rule_dir', 'rule_exclude', 'list']);
                res.body.data.rule_dir.should.be.instanceof(Array)
                done();
            });
        });

        it('Errors: Invalid Section', function(done) {
            request(common.url)
            .get("/manager/configuration?section=rulesa")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1102);
                res.body.message.should.be.an.string;
                done();
            });
        });

        it('Filters: Section - field', function(done) {
            request(common.url)
            .get("/manager/configuration?section=ruleset&field=rule_dir")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.be.instanceof(Array)
                done();
            });
        });

        it('Errors: Invalid field', function(done) {
            request(common.url)
            .get("/manager/configuration?section=ruleset&field=includedd")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1103);
                res.body.message.should.be.an.string;
                done();
            });
        });

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .get("/manager/configuration?random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                done();
            });
        });

        it('Filters: Invalid filter - Extra field', function(done) {
            request(common.url)
            .get("/manager/configuration?section=ruleset&field=rule_dir&random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                done();
            });
        });

    });  // GET/manager/configuration

    describe('GET/manager/stats', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/stats")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: date', function(done) {
            var moment = require('moment');
            date = moment().format('YYYYMMDD')

            request(common.url)
            .get("/manager/stats?date=" + date)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: Invalid date', function(done) {
            request(common.url)
            .get("/manager/stats?date=2016/07/07")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(605);
                res.body.message.should.be.an.string;
                done();
            });
        });

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .get("/manager/stats?random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                done();
            });
        });

        it('Filters: Invalid filter - Extra field', function(done) {
            request(common.url)
            .get("/manager/stats?date=20160707&random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                done();
            });
        });

    });  // GET/manager/stats

    describe('GET/manager/stats/hourly', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/stats/hourly")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['averages', 'interactions']);
                done();
            });
        });

    });  // GET/manager/stats/hourly

    describe('GET/manager/stats/weekly', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/stats/weekly")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                done();
            });
        });

    });  // GET/manager/stats/weekly

    describe('GET/manager/stats/analysisd', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/stats/analysisd")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;

                res.body.data.should.have.properties(['archives_queue_size',
                'events_dropped', 'alerts_queue_size', 'rule_matching_queue_usage',
                'events_processed', 'event_queue_usage', 'events_edps',
                'hostinfo_events_decoded', 'syscollector_events_decoded',
                'rootcheck_edps', 'firewall_queue_usage', 'alerts_queue_usage',
                'firewall_queue_size', 'alerts_written', 'firewall_written',
                'syscheck_queue_size', 'events_received', 'rootcheck_queue_usage',
                'rootcheck_events_decoded', 'rootcheck_queue_size', 'syscheck_edps',
                'fts_written', 'syscheck_queue_usage', 'other_events_edps',
                'statistical_queue_usage', 'hostinfo_edps', 'hostinfo_queue_usage',
                'syscheck_events_decoded', 'syscheck_events_decoded', 'archives_queue_usage',
                'statistical_queue_size', 'total_events_decoded', 'hostinfo_queue_size',
                'syscollector_queue_size', 'rule_matching_queue_size',
                'other_events_decoded', 'event_queue_size', 'syscollector_edps']);
                done();
            });
        });

    });  // GET/manager/stats/analysisd

    describe('GET/manager/stats/remoted', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/stats/remoted")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['discarded_count',
                'msg_sent', 'queue_size', 'ctrl_msg_count', 'evt_count',
                'tcp_sessions', 'total_queue_size']);
                done();
            });
        });

    });  // GET/manager/stats/remoted

    describe('GET/manager/logs', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/logs")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Pagination', function(done) {
            request(common.url)
            .get("/manager/logs?offset=0&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                done();
            });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/manager/logs?limit=0")
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

        it('Sort', function(done) {
            request(common.url)
            .get("/manager/logs?sort=+")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('SortField', function(done) {
            request(common.url)
            .get("/manager/logs?sort=+level")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Search', function(done) {
            request(common.url)
            .get("/manager/logs?search=info")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: type_log', function(done) {
            request(common.url)
            .get("/manager/logs?type_log=info")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: category', function(done) {
            request(common.url)
            .get("/manager/logs?category=ossec-monitord")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: type_log and category', function(done) {
            request(common.url)
            .get("/manager/logs?type_log=info&category=ossec-analysisd")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .get("/manager/logs?random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                done();
            });
        });

        it('Filters: Invalid filter - Extra field', function(done) {
            request(common.url)
            .get("/manager/logs?category=all&random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                done();
            });
        });

        it('Filters: query 1', function (done) {
            request(common.url)
            .get("/manager/logs?q=tag=ossec-analysisd;level=info&limit=1")
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
            .get("/manager/logs?q=tag=ossec-execd;level=info&limit=1")
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
                    res.body.data.items[0].level.should.be.equal('info');

                    done();
                });
        });

        it('Filters: query 3', function (done) {
            request(common.url)
            .get("/manager/logs?q=tag~ossec;level=error&limit=1")
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
                    res.body.data.items[0].level.should.be.equal('error');

                    done();
                });
        });

        it('Filters: wrong query', function (done) {
            request(common.url)
            .get("/manager/logs?q=ossec-analysisd")
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

    });  // GET/manager/logs

    describe('GET/manager/logs/summary', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/manager/logs/summary")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;

                res.body.data.should.have.properties(['ossec-monitord']);
                res.body.data['ossec-monitord'].should.have.properties(['info', 'all', 'error']);

                done();
            });
        });

    });  // GET/manager/logs/summary

    describe('POST/manager/files', function() {

        // save ossec.conf
        before(function (done) {
            request(common.url)
                .get("/manager/files?path=" + path_ossec_conf)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.string;

                    ossec_conf_content = res.body.data

                    done();
                });
        });

        it('Upload ossec.conf', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_ossec_conf + "&overwrite=true")
            .set("Content-Type", "application/xml")
            .send(ossec_conf_content)
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

        it('Upload ossec.conf (overwrite=false)', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_ossec_conf + "&overwrite=false")
            .set("Content-Type", "application/xml")
            .send(ossec_conf_content)
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

        it('Upload rules (new rule)', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_rules + '&overwrite=true')
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
            .post("/manager/files?path=" + path_rules + '&overwrite=true')
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
            .post("/manager/files?path=" + path_rules + '&overwrite=false')
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

        it('Upload decoder (overwrite=true)', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_decoders + "&overwrite=true")
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
            .post("/manager/files?path=" + path_decoders)
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

        it('Upload list (overwrite=true)', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_lists + "&overwrite=true")
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

        it('Upload list (without overwrite parameter)', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_lists)
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

        it('Upload malformed rule', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_rules + "&overwrite=true")
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

        it('Upload malformed decoder', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_decoders + "&overwrite=true")
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

        it('Upload malformed list', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_lists + "&overwrite=true")
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

        it('Upload list with empty path', function(done) {
            request(common.url)
            .post("/manager/files")
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
            .post("/manager/files?path=" + path_lists)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send("test-wazuh-w:write\ntest-wazuh-r:read\ntest-wazuh-a:attribute\ntest-wazuh-x:execute\ntest-wazuh-c:command\n")
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

    });  // POST/manager/files

    describe('GET/manager/files', function() {

        it('Request ossec.conf', function (done) {
            request(common.url)
                .get("/manager/files?path=" + path_ossec_conf)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.string;
                    res.body.data.should.equal(ossec_conf_content)

                    done();
                });
        });

        it('Request rules (local)', function(done) {
            request(common.url)
            .get("/manager/files?path=" + path_rules)
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

        it('Request rules (global)', function(done) {
            request(common.url)
            .get("/manager/files?path=ruleset/rules/0350-amazon_rules.xml")
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

        it('Request decoders (local)', function(done) {
            request(common.url)
            .get("/manager/files?path=" + path_decoders)
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
            .get("/manager/files?path=ruleset/decoders/0005-wazuh_decoders.xml")
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
            .get("/manager/files?path=" + path_lists)
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
            .get("/manager/files?path=etc/internal_options.conf")
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
            .get("/manager/files?path=../tmp")
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
            .get("/manager/files?path=./framework/wazuh/agent.py")
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
            .get("/manager/files?path=etc/rules/wrong_file.xml")
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

        it('Request file with empty path', function(done) {
            request(common.url)
            .get("/manager/files")
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
            .get("/manager/files?path=" + path_lists + "&validation=true")
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

    });  // GET/manager/files

    describe('DELETE/manager/files', function() {

        it('Delete rules', function(done) {
            request(common.url)
            .delete("/manager/files?path=" + path_rules)
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

        it('Delete decoders', function(done) {
            request(common.url)
            .delete("/manager/files?path=" + path_decoders)
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

        it('Delete CDB list', function(done) {
            request(common.url)
            .delete("/manager/files?path=" + path_lists)
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
            .delete("/manager/files")
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

    });  // DELETE/manager/files

    describe('GET/manager/configuration/validation (OK)', function() {

        it('Request validation ', function (done) {
            request(common.url)
                .get("/manager/configuration/validation")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.status.should.equal('OK');

                    done();
                });
        });

    });  // GET/manager/configuration/validation (OK)

    describe('GET/manager/configuration/validation (KO)', function() {

        // upload corrupted ossec.conf
        before(function (done) {
            request(common.url)
            .post("/manager/files?path=" + path_ossec_conf + "&overwrite=true")
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

                setTimeout(function(){
                    done();
                }, 1000)

            });
        });

        // restore ossec.conf
        after(function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_ossec_conf + "&overwrite=true")
            .set("Content-Type", "application/xml")
            .send(ossec_conf_content)
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

        it('Request validation', function (done) {
            request(common.url)
                .get("/manager/configuration/validation")
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

    });  // GET/manager/configuration/validation (KO)

    describe('GET/manager/config/:component/:configuration', function () {

		// agentless
		it('Request-Agentless-Agentless', function(done) {
            request(common.url)
            .get("/manager/config/agentless/agentless")
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
            .get("/manager/config/analysis/global")
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
            .get("/manager/config/analysis/active_response")
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
            .get("/manager/config/analysis/alerts")
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
            .get("/manager/config/analysis/command")
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
            .get("/manager/config/analysis/internal")
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
            .get("/manager/config/auth/auth")
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
            .get("/manager/config/com/active-response")
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
            .get("/manager/config/com/internal")
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
            .get("/manager/config/csyslog/csyslog")
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
            .get("/manager/config/integrator/integration")
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
            .get("/manager/config/logcollector/localfile")
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
            .get("/manager/config/logcollector/socket")
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
            .get("/manager/config/logcollector/internal")
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
            .get("/manager/config/mail/global")
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
            .get("/manager/config/mail/alerts")
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
            .get("/manager/config/mail/internal")
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
            .get("/manager/config/monitor/internal")
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
            .get("/manager/config/request/remote")
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
            .get("/manager/config/request/internal")
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
            .get("/manager/config/syscheck/syscheck")
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
            .get("/manager/config/syscheck/rootcheck")
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
            .get("/manager/config/syscheck/internal")
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
            .get("/manager/config/wmodules/wmodules")
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
                module_list = ['cis-cat', 'database', 'open-scap', 'osquery', 'sca', 'syscollector', 'vulnerability-detector', 'wazuh_download']

                // check modules
                should((JSON.stringify(module_list.sort()))).be.eql(JSON.stringify(modules.sort()))

                done();
            });
        });


    }); // GET/manager/config/:component/:configuration

    describe('PUT/manager/restart', function() {

        it('Request', function(done) {
            request(common.url)
            .put("/manager/restart")
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

    });  // PUT/manager/restart

});  // Manager
