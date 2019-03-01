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

                res.body.data.should.have.properties(['wazuh-modulesd', 'ossec-authd', 'ossec-monitord', 'ossec-logcollector', 'ossec-execd', 'ossec-remoted', 'ossec-syscheckd', 'ossec-analysisd', 'ossec-maild']);
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

        // upload rule file for testing overwrite parameter
        before(function (done) {
            request(common.url)
                .get("/manager/files?path=" + overwrite_rule)
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
            .post("/manager/files?path=" + path_ossec_conf)
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

        it('Upload rules (new rule)', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_rules)
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

        it('Upload rules (overwrite parameter = true)', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_rules + '&overwrite=true')
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

        it('Upload rules (overwrite parameter = false)', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_rules + '&overwrite=False')
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
            .post("/manager/files?path=" + path_decoders)
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
            .post("/manager/files?path=" + path_lists)
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

        it('Upload malformed rule', function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_rules)
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
            .post("/manager/files?path=" + path_decoders)
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
            .post("/manager/files?path=" + path_lists)
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

        it('Request rules', function(done) {
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

        it('Request decoders', function(done) {
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

    });  // GET/manager/files

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
            .post("/manager/files?path=" + path_ossec_conf)
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

        // restore ossec.conf
        after(function(done) {
            request(common.url)
            .post("/manager/files?path=" + path_ossec_conf)
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

    });  // DELETE/manager/files

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
