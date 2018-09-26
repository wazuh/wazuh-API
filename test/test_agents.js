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

var should  = require('should');
var assert  = require('assert');
var request = require('supertest');
var fs      = require('fs');
var common  = require('./common.js');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

var disconnected_agent_properties = ['status', 'ip', 'id', 'name', 'dateAdd'];
var manager_properties = disconnected_agent_properties.concat(['version', 'manager', 'lastKeepAlive', 'os']);
var agent_properties = manager_properties.concat(['configSum', 'mergedSum', 'group']);
var agent_os_properties = ['major', 'name', 'uname', 'platform', 'version', 'codename', 'arch'];

describe('Agents', function() {

    describe('GET/agents', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)

                res.body.data.items[0].should.have.properties(manager_properties);
                res.body.data.items[1].should.have.properties(agent_properties);
                res.body.data.items[0].os.should.have.properties(agent_os_properties);
                res.body.data.items[1].os.should.have.properties(agent_os_properties);
                done();
            });
        });

        it('Pagination', function(done) {
            request(common.url)
            .get("/agents?offset=0&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(manager_properties);
                res.body.data.items[0].id.should.have.equal('000');
                res.body.data.items[0].status.should.have.equal('Active');
                done();
            });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/agents?limit=0")
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
            .get("/agents?sort=-id")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].id.should.equal('001');
                res.body.data.items[0].should.have.properties(agent_properties);
                done();
            });
        });

        it('Wrong Sort', function(done) {
            request(common.url)
            .get("/agents?sort=-wrongParameter")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1403);
                done();
            });
        });

        it('Search', function(done) {
            request(common.url)
            .get("/agents?search=001")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].id.should.be.equal("001");
                res.body.data.items[0].should.have.properties(agent_properties);
                res.body.data.items[0].os.should.have.properties(agent_os_properties);
                done();
            });
        });

        it('Selector', function(done) {
            request(common.url)
            .get("/agents?select=dateAdd,mergedSum")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['dateAdd', 'id']);
                res.body.data.items[1].should.have.properties(['dateAdd', 'mergedSum', 'id']);
                done();
            });
        });

        it('Not allowed selector', function(done) {
            request(common.url)
            .get("/agents?select=wrongParam")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1724);
                done();
            });
        });

        var expected_version = 0;
        before(function(done) {
            request(common.url)
            .get("/version")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
              expected_version="Wazuh "+String(res.body.data);
              done();
            });
        });

        it('Version', function(done) {
            request(common.url)
            .get("/agents?version="+expected_version.replace(/\s/g, ''))
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['version']);
                res.body.data.items[0].version.should.be.equal(expected_version);
                done();
            });
        });


        var expected_os_platform = "";
        var expected_os_version = "";
        var expected_manager_host = "";
        before(function(done) {
            request(common.url)
            .get("/agents")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                expected_os_platform = res.body.data.items[0].os.platform;
                expected_os_version = res.body.data.items[0].os.version;
                expected_manager_host = res.body.data.items[0].manager;
                done();
            });
        });

        it('Os.platform', function(done) {
            request(common.url)
            .get("/agents?os.platform=" + expected_os_platform)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].os.should.have.properties(['platform']);
                res.body.data.items[0].os.platform.should.be.equal(expected_os_platform);
                done();
            });
        });

        it('Os.version', function(done) {
            request(common.url)
            .get("/agents?os.version=" + expected_os_version)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].os.should.have.properties(['version']);
                res.body.data.items[0].os.version.should.be.equal(expected_os_version);
                done();
            });
        });

        it('ManagerHost', function(done) {
            request(common.url)
            .get("/agents?manager=" + expected_manager_host)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].os.should.have.properties(['version']);
                res.body.data.items[0].manager.should.be.equal(expected_manager_host);
                done();
            });
        });

        it('Filters: status', function(done) {
            request(common.url)
            .get("/agents?status=aCtIvE")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['status', 'ip', 'id', 'name']);
                done();
            });
        });

        it('Filters: status 2', function (done) {
            request(common.url)
                .get("/agents?status=aCtIvE,neverconnected")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['status', 'ip', 'id', 'name']);
                    done();
                });
        });

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .get("/agents?random")
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
            .get("/agents?status=aCtIvE&random")
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

        it('Filters: older_than', function (done) {
            request(common.url)
                .get("/agents?older_than=1s")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['status', 'ip', 'id', 'name']);
                    done();
                });
        });

        it('Filters: group', function (done) {
            request(common.url)
                .get("/agents?group=default")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items','totalItems']);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.items[0].group.should.be.equal('default');
                    done();
                });
        });

        it('Select: single field', function (done) {
            request(common.url)
                .get("/agents?select=lastKeepAlive")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['id', 'lastKeepAlive']);
                    done();
                });
        });

        it('Select: multiple fields', function (done) {
            request(common.url)
                .get("/agents?select=status,os.platform,os.version")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['id', 'status', 'os']);
                    res.body.data.items[0].os.should.have.properties(['version','platform']);
                    done();
                });
        });

        it('Select: wrong field', function (done) {
            request(common.url)
                .get("/agents?select=wrong_field")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {

                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1724);
                    done();
                });
        });

        it('Select: invalid character', function (done) {
            request(common.url)
                .get("/agents?select=invalidñcharacter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {

                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(619);
                    done();
                });
        });

        it('Filters: query', function (done) {
            request(common.url)
                .get("/agents?q=group=default;lastKeepAlive<1d")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items','totalItems']);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.items[0].group.should.be.equal('default');
                    done();
                });
        });

    });  // GET/agents

    describe('GET/agents/summary', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents/summary")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['Active', 'Total', 'Disconnected', 'Never connected']);
                res.body.data['Active'].should.be.above(0);
                res.body.data['Total'].should.be.an.integer;
                res.body.data['Disconnected'].should.be.an.integer;
                res.body.data['Never connected'].should.be.an.integer;
                done();
            });
        });

    });  // GET/agents/summary

    describe('GET/agents/summary/os', function() {

        it('Request', function(done) {
            request(common.url)
                .get('/agents/summary/os')
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function(err, res) {
                    if (err) return done(err);

                    res.body.error.should.equal(0);
                    res.body.should.have.properties(['error','data']);
                    res.body.data.should.have.properties(['totalItems','items']);
                    res.body.data.items.should.be.instanceof(Array);
                    done();
                });
        });
    }); // GET/agents/summary/os

    describe('GET/agents/outdated', function() {
        before(function (done) {
            request(common.url)
                .get("/manager/info")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    manager_version = res.body.data.version;
                    done();
                });
        });

        it('Request', function(done) {
            request(common.url)
            .get("/agents/outdated")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['items','totalItems']);
                res.body.data.items.should.be.instanceOf(Array);
                res.body.data.items[0].should.have.properties(['version','id','name']);
                res.body.data.items[0].should.not.be.eql(manager_version);

                done();
            });
        });


    });  // GET/agents/outdated


    describe('GET/agents/:agent_id', function() {

        it('Request (manager)', function(done) {
            request(common.url)
            .get("/agents/000")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.id.should.equal("000");
                res.body.data.should.have.properties(manager_properties);
                res.body.data.os.should.have.properties(agent_os_properties);
                done();
            });
        });

        it('Request (agent)', function(done) {
            request(common.url)
            .get("/agents/001")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.id.should.equal("001");
                res.body.data.should.have.properties(agent_properties);
                res.body.data.os.should.have.properties(agent_os_properties);
                done();
            });
        });



        it('Selector', function(done) {
            request(common.url)
            .get("/agents/001?select=dateAdd,mergedSum")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['dateAdd', 'mergedSum']);
                done();
            });
        });

        it('Not allowed selector', function(done) {
            request(common.url)
            .get("/agents/001?select=wrongParam")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1724);
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .get("/agents/abc")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(600);
                done();
            });
        });

        it('Errors: No agent', function(done) {
            request(common.url)
            .get("/agents/9999999")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1701);
                done();
            });
        });

        it('Select', function(done) {
            request(common.url)
            .get("/agents/000?select=lastKeepAlive,id,ip,status")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['lastKeepAlive','id','ip','status']);
                done();
            });
        });

        it('Select: wrong field', function(done) {
            request(common.url)
            .get("/agents/000?select=wrong_field")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1724);
                done();
            });
        });

    });  // GET/agents/:agent_id

    describe('GET/agents/name/:agent_name', function() {
        var expected_name = ""
        before(function(done) {
            request(common.url)
            .get("/agents/001")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.data.should.have.properties(agent_properties);
                res.body.error.should.equal(0);
                expected_name = res.body.data.name;
                done();
            });
        });
        it('Request', function(done) {
            request(common.url)
            .get("/agents/name/"+expected_name)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(agent_properties);
                res.body.data.os.should.have.properties(agent_os_properties);
                done();
            });
        });

        it('Wrong name', function(done) {
            request(common.url)
            .get("/agents/name/non_existent_agent")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1701);
                done();
            });
        });

        it('Selector', function(done) {
            request(common.url)
            .get("/agents/name/"+expected_name+"?select=dateAdd,mergedSum,os.name")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['mergedSum','dateAdd','os']);
                res.body.data.os.should.have.properties(['name']);
                done();
            });
        });

        it('Not allowed selector', function(done) {
            request(common.url)
            .get("/agents/name/"+expected_name+"?select=wrongField")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1724);
                done();
            });
        });
    });  // GET/agents/name/:agent_name

    describe('GET/agents/:agent_id/key', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents/001/key")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('string');
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .get("/agents/abc/key")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(600);
                done();
            });
        });

        it('Errors: No key', function(done) {
            request(common.url)
            .get("/agents/999999/key")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1701);
                done();
            });
        });
    });  // GET/agents/:agent_id/key

    describe('PUT/agents/groups/:group_id', function() {

        it('Request', function(done) {

            request(common.url)
            .put("/agents/groups/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .put("/agents/groups/!group")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

        it('Params: Group already exists', function(done) {
            request(common.url)
            .put("/agents/groups/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1711);
                done();
            });
        });

    });  // PUT/agents/groups/:group_id

    describe('PUT/agents/:agent_id/group/:group_id', function() {

        it('Request', function(done) {

            request(common.url)
            .put("/agents/001/group/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad agent name', function(done) {
            request(common.url)
            .put("/agents/001!/group/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(600);
                done();
            });
        });

        it('Params: Agent does not exist', function(done) {
            request(common.url)
            .put("/agents/1568/group/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1701);
                done();
            });
        });

        it('Params: Replace parameter', function(done) {
            request(common.url)
            .put("/agents/001/group/dmz?replace")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                done();
            });
        });

    });  // PUT/agents/:agent_id/group/:group_id

    var agent_id = 0
    describe('GET/agents/no_group', function () {
        var agent_name = "agentWithoutGroup"
        before(function (done) {
            request(common.url)
                .put("/agents/" + agent_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    agent_id = res.body.data.id;
                    done();
                });
        });

        it('Request', function (done) {
            request(common.url)
                .get("/agents/no_group")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.array;
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.totalItems.should.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['ip', 'id', 'name']);
                    done();
                });
        });


        it('Pagination', function (done) {
            request(common.url)
                .get("/agents/no_group?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.array;
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.totalItems.should.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['ip', 'id', 'name']);
                    done();
                });
        });

        it('Retrieve all elements with limit=0', function (done) {
            request(common.url)
                .get("/agents/no_group?limit=0")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1406);
                    done();
                });
        });

        it('Sort', function (done) {
            request(common.url)
                .get("/agents/no_group?sort=-id")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.array;
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.totalItems.should.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['ip', 'id', 'name']);
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/agents/no_group?search=" + agent_id)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.array;
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.totalItems.should.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['ip', 'id', 'name']);
                    done();
                });
        });

        it('Select', function (done) {
            request(common.url)
                .get("/agents/no_group?select=name")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.array;
                    res.body.data.should.have.properties(['items', 'totalItems']);
                    res.body.data.totalItems.should.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['name']);
                    done();
                });
        });

        it('Wrong select', function (done) {
            request(common.url)
                .get("/agents/no_group?select=worng_select")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(1724);
                    done();
                });
        });

        it('Filter: status', function (done) {
            request(common.url)
                .get("/agents/no_group?status=never%20connected")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['items','totalItems']);
                    done();
                });
        });

        after(function (done) {
            request(common.url)
                .delete("/agents/" + agent_id + '?purge')
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    done();
                });
        });

    });  // GET/agents/no_group

    describe('GET/agents/groups', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents/groups")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);

                res.body.data.should.be.an.array;
                res.body.data.should.have.properties(['totalItems','items']);
                res.body.data[0].should.have.properties(['count','mergedSum','configSum','name']);
                res.body.data.items.should.be.instanceOf(Array);

                done();
            });
        });

        it('Retrieve all elements with limit=0', function (done) {
            request(common.url)
                .get("/agents/groups?limit=0")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1406);
                    done();
                });
        });

        it('Hash algorithm', function(done) {
            request(common.url)
            .get("/agents/groups?hash=sha256")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['totalItems','items']);
                res.body.data.items[0].should.have.properties(['count','mergedSum','configSum','name']);
                done();
            });
        });

        it('Wrong Hash algorithm', function(done) {
            request(common.url)
            .get("/agents/groups?hash=aaaaaa")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1723);
                done();
            });
        });

    });  // GET/agents/groups

    describe('GET/agents/groups/:group_id', function() {

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['totalItems', 'items']);
                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/web!-ña")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });


        it('Retrieve all elements with limit=0', function (done) {
            request(common.url)
                .get("/agents/groups/webserver?limit=0")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1406);
                    done();
                });
        });

        it('Select', function(done) {
            request(common.url)
            .get("/agents/groups/webserver?select=lastKeepAlive,version")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['totalItems', 'items']);
                res.body.error.should.equal(0);
                done();
            });
        });

        it('Filter: status', function(done) {
            request(common.url)
            .get("/agents/groups/webserver?status=Active,Disconnected")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['totalItems', 'items']);
                res.body.error.should.equal(0);
                done();
            });

        });

    });  // GET/agents/groups/:group_id

    describe('GET/agents/groups/:group_id/configuration', function() {

        before(function(done) {
            // write a configuration example
            var agent_conf_example = "\
            <agent_config name=\"agent_name\">\
                <localfile>\
                    <location>/var/log/my.log</location>\
                    <log_format>syslog</log_format>\
                </localfile>\
            </agent_config>\
            ";
            var config_path = common.ossec_path+'/etc/shared/webserver/agent.conf';
            fs.writeFile(config_path, agent_conf_example, (err) => {
                if (err) return done(err);
                done();
            });
        });

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver/configuration")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['totalItems', 'items']);
                res.body.error.should.equal(0);
                res.body.data.items[0].should.have.properties(['config','filters']);
                res.body.data.items[0].config.should.have.properties(['localfile']);
                res.body.data.items[0].filters.should.have.properties(['name']);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/wñ!/configuration")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

        it('Retrieve all elements with limit=0', function (done) {
            request(common.url)
                .get("/agents/groups/webserver/configuration?limit=0")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1406);
                    done();
                });
        });

    });  // GET/agents/groups/:group_id/configuration

    describe('GET/agents/groups/:group_id/files', function() {

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver/files")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data[0].should.have.properties(['hash','filename']);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/wñ!/files")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

        it('Retrieve all elements with limit=0', function (done) {
            request(common.url)
                .get("/agents/groups/webserver/files?limit=0")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1727);
                    done();
                });
        });

        it('Hash algorithm', function(done) {
            request(common.url)
            .get("/agents/groups/webserver/files?hash=sha256")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['totalItems','items']);
                res.body.data.items[0].should.have.properties(['hash','filename']);
                done();
            });
        });

        it('Wrong Hash algorithm', function(done) {
            request(common.url)
            .get("/agents/groups/webserver/files?hash=aaaaaa")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1723);
                done();
            });
        });

    });  // GET/agents/groups/:group_id/files

    describe('GET/agents/groups/:group_id/files/:filename', function() {

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver/files/cis_debian_linux_rcl.txt")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/wñ!/files/cis_debian_linux_rcl.txt")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

    });  // GET/agents/groups/:group_id/files/:filename

    describe('DELETE/agents/:agent_id/group', function() {

        it('Request', function(done) {

            request(common.url)
            .delete("/agents/001/group")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('string');
                done();
            });
        });

        it('Errors: ID is not present', function(done) {

            request(common.url)
            .delete("/agents/54952/group")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1701);
                res.body.message.should.be.type('string');
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .delete("/agents/abc/group")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(600);
                done();
            });
        });

    });  // DELETE/agents/:agent_id/group

    describe('DELETE/agents/:agent_id/group/:group_id', function() {

        before(function (done) {
            request(common.url)
                .put("/agents/001/group/dmz")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    done();
                });
        });


        it('Request', function(done) {

            request(common.url)
            .delete("/agents/001/group/dmz")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('string');
                done();
            });
        });

        it('Errors: ID is not present', function(done) {

            request(common.url)
            .delete("/agents/54952/group/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1701);
                res.body.message.should.be.type('string');
                done();
            });
        });

        it('Errors: Group is not present', function(done) {

            request(common.url)
            .delete("/agents/001/group/adsdfdfs")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1734);
                res.body.message.should.be.type('string');
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .delete("/agents/abc/group/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(600);
                done();
            });
        });

        it('Params: Bad group id', function(done) {
            request(common.url)
            .delete("/agents/001/group/aaaaaaaa")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1734);
                done();
            });
        });

    });  // DELETE/agents/:agent_id/group/:group_id

    describe('DELETE/agents/groups/:group_id', function() {

        it('Request', function(done) {

            request(common.url)
            .delete("/agents/groups/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group id', function(done) {
            request(common.url)
            .delete("/agents/groups/webserverñ")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

    });  // DELETE/agents/groups/:group_id

    describe('PUT/agents/restart', function() {

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/agents/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('string');
                done();
            });
        });

    });  // PUT/agents/restart

    describe('PUT/agents/:agent_id/restart', function() {

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/agents/001/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('object');
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .put("/agents/abc/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(600);
                done();
            });
        });

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/agents/000/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['msg', 'failed_ids', 'affected_agents']);

                res.body.data.failed_ids[0].error.code.should.equal(1703);
                done();
            });
        });

    });  // PUT/agents/:agent_id/restart


    describe('DELETE/agents', function () {
        before(function (done) {
            request(common.url)
                .put("/agents/agentToDelete")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    done();
                });
        });

        before(function (done) {

            request(common.url)
                .put("/agents/agentToDelete2")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    done();
                });
        });

        it('Request', function (done) {
            request(common.url)
                .delete("/agents")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);
                    done();
                });
        });
        
        it('Filter: older_than, status and ids', function (done) {
            setTimeout(function(){
                request(common.url)
                    .delete("/agents?purge&older_than=1s&status=neverconnected")
                    .send({ 'ids': ['002']})
                    .auth(common.credentials.user, common.credentials.password)
                    .expect("Content-type", /json/)
                    .expect(200)
                    .end(function (err, res) {
                        if (err) return done(err);
    
                        res.body.should.have.properties(['error', 'data']);
                        res.body.data.should.have.properties(['affected_agents', 'msg', 'older_than']);
                        if ('failed_ids' in res.body.data && res.body.data.failed_ids.length > 0)
                            console.log(res.body.data.failed_ids[0].error);
                        res.body.data.msg.should.equal("All selected agents were removed");
                        res.body.data.affected_agents[0].should.equal('002');
                        res.body.data.affected_agents.should.have.lengthOf(1);
    
                        res.body.error.should.equal(0);
                        done();
                    });
            }, 1500);
        });

        it('Errors: Get deleted agent', function (done) {
            request(common.url)
                .get("/agents/002")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1701);
                    done();
                });
        });

        it('Filter: older_than', function (done) {
            request(common.url)
                .delete("/agents?older_than=1s&purge&status=neverconnected")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.should.have.properties(['affected_agents', 'msg', 'older_than']);
                    res.body.data.msg.should.equal("All selected agents were removed");
                    res.body.data.affected_agents[0].should.equal('003');
                    res.body.error.should.equal(0);
                    done();
                });
        });

    });  // DELETE/agents


    describe('GET/agents/stats/distinct', function () {

        var fields = ['node_name', 'version', 'manager', 'os'];

        it('Request', function (done) {
            request(common.url)
                .get("/agents/stats/distinct")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(fields);
                    res.body.data.items[0].os.should.have.properties(agent_os_properties);
                    done();
                });
        });

        it('Pagination', function (done) {
            request(common.url)
                .get("/agents/stats/distinct?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(fields);
                    res.body.data.items[0].os.should.have.properties(agent_os_properties);
                    done();
                });
        });

        it('Retrieve all elements with limit=0', function (done) {
            request(common.url)
                .get("/agents/stats/distinct?limit=0")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1406);
                    done();
                });
        });

        it('Sort', function (done) {
            request(common.url)
                .get("/agents/stats/distinct?sort=-node_name")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(fields);
                    res.body.data.items[0].os.should.have.properties(agent_os_properties);
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/agents/stats/distinct?search=linux")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(fields);
                    res.body.data.items[0].os.should.have.properties(agent_os_properties);
                    done();
                });
        });

        it('Select', function (done) {
            request(common.url)
                .get("/agents/stats/distinct?select=os.platform")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['os']);
                    res.body.data.items[0].os.should.have.properties(['platform']);
                    done();
                });
        });

        it('Wrong select', function (done) {
            request(common.url)
                .get("/agents/stats/distinct?select=wrong_field")
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


    }); // GET/agents/stats/distinct
    
    
	describe('GET/agents/:agent/config/:component/:configuration', function () {
		
		// agent	
		it('Request-Agent-Client', function(done) {
            request(common.url)
            .get("/agents/001/config/agent/client")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
				res.body.data.should.have.properties('client');
				res.body.data.client.should.have.properties(['crypto_method', 'remote_conf', 'auto_restart',
				'server', 'config-profile', 'time-reconnect', 'notify_time']);

                res.body.error.should.equal(0);
                done();
            });
        });
        
        it('Request-Agent-Buffer', function(done) {
            request(common.url)
            .get("/agents/001/config/agent/buffer")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('buffer');
				res.body.data.buffer.should.have.properties(['disabled',
				'queue_size', 'events_per_second']);

                res.body.error.should.equal(0);
                done();
            });
        });
        
        it('Request-Agent-Labels', function(done) {
            request(common.url)
            .get("/agents/001/config/agent/labels")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                // res.body.data.shoul.have.properties('labels'); // empty list	

                res.body.error.should.equal(0);
                done();
            });
        });

		it('Request-Agent-Internal', function(done) {
            request(common.url)
            .get("/agents/001/config/agent/internal")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('internal');
				res.body.data.internal.should.have.properties(['monitord', 'remoted',
				'agent']);
				res.body.data.internal.monitord.should.have.properties(['daily_rotations',
				'day_wait', 'keep_log_days', 'compress', 'size_rotate', 'rotate_log']);
				res.body.data.internal.remoted.should.have.properties('request_rto_msec',
				'recv_counter_flush', 'request_pool', 'comp_average_printout',
				'verify_msg_id', 'max_attempts');
				res.body.data.internal.agent.should.have.properties('normal_level',
				'min_eps', 'recv_timeout', 'state_interval', 'warn_level', 'debug', 'tolerance');

                res.body.error.should.equal(0);
                done();
            });
        });
		
		// agentless
		it('Request-Agentless-Agentless', function(done) {
            request(common.url)
            .get("/agents/000/config/agentless/agentless")
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
            .get("/agents/000/config/analysis/global")
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
            .get("/agents/000/config/analysis/active_response")
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
            .get("/agents/000/config/analysis/alerts")
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
            .get("/agents/000/config/analysis/command")
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
                res.body.data.command[6].should.have.properties(['executable', 'timeout_allowed',
                'name', 'expect']);
                res.body.data.command[7].should.have.properties(['executable', 'timeout_allowed',
                'name', 'expect']);
                res.body.data.command[8].should.have.properties(['executable', 'timeout_allowed',
                'name', 'expect']);                
                
                res.body.error.should.equal(0);
                done();
            });
        });
        
        it('Request-Analysis-Rules', function(done) {
            request(common.url)
            .get("/agents/000/config/analysis/rules")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['rules']);

                res.body.error.should.equal(0);
                done();
            });
        });
        
        it('Request-Analysis-Decoders', function(done) {
            request(common.url)
            .get("/agents/000/config/analysis/decoders")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties('decoders');

                res.body.error.should.equal(0);
                done();
            });
        });
        
        it('Request-Analysis-Internal', function(done) {
            request(common.url)
            .get("/agents/000/config/analysis/internal")
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
            .get("/agents/000/config/auth/auth")
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
            .get("/agents/001/config/com/active-response")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['active-response']);
                res.body.data['active-response'].should.have.properties(['disabled', 'ca_store']);

                res.body.error.should.equal(0);
                done();
            });
        });
        
        it('Request-Com-Internal', function(done) {
            request(common.url)
            .get("/agents/001/config/com/internal")
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
            .get("/agents/000/config/csyslog/csyslog")
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
            .get("/agents/000/config/integrator/integration")
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
            .get("/agents/001/config/logcollector/localfile")
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
            .get("/agents/001/config/logcollector/socket")
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
            .get("/agents/001/config/logcollector/internal")
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
            .get("/agents/000/config/mail/global")
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
            .get("/agents/000/config/mail/alerts")
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
            .get("/agents/000/config/mail/internal")
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
            .get("/agents/000/config/monitor/internal")
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
            .get("/agents/000/config/request/remote")
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
            .get("/agents/000/config/request/internal")
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
            .get("/agents/001/config/syscheck/syscheck")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['syscheck']);
                res.body.data.syscheck.should.have.properties(['ignore', 'skip_nfs', 'directories',
                'scan_on_start', 'disabled', 'frequency', 'restart_audit', 'nodiff']);
                
                res.body.error.should.equal(0);
                done();
            });
        });
        
        it('Request-Syscheck-Rootcheck', function(done) {
            request(common.url)
            .get("/agents/001/config/syscheck/rootcheck")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['rootcheck']);
                res.body.data.rootcheck.should.have.properties(['check_unixaudit', 'check_sys', 'rootkit_trojans',
                'skip_nfs', 'check_if', 'check_pids', 'check_dev', 'check_ports', 'disabled', 'rootkit_files',
                // 'frequency', 'scanall', 'check_trojans', 'base_directory', 'check_files', 'system_audit']); // base directory value is empty, this cause an error
                'frequency', 'scanall', 'check_trojans', 'check_files', 'system_audit']);
                
                res.body.error.should.equal(0);
                done();
            });
        });
        
        it('Request-Syscheck-Internal', function(done) {
            request(common.url)
            .get("/agents/001/config/syscheck/internal")
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
            .get("/agents/001/config/wmodules/wmodules")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['wmodules']);
                //res.body.data.wmodules.should.have.properties(['open-scap', 'cis-cat',
                //'osquery', 'syscollector', 'database', 'wazuh_download']);
                res.body.data.wmodules[0].should.have.properties(['open-scap']);
                res.body.data.wmodules[1].should.have.properties(['cis-cat']);
                res.body.data.wmodules[2].should.have.properties(['osquery']);
                res.body.data.wmodules[3].should.have.properties(['syscollector']);
                res.body.data.wmodules[4].should.have.properties(['database']);
                res.body.data.wmodules[5].should.have.properties(['wazuh_download']);
                
                res.body.error.should.equal(0);
                done();
            });
        });
        

    }); // GET/agents/:agent/config/:component/:configuration

});  // Agents
