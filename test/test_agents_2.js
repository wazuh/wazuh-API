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

var should  = require('should');
var assert  = require('assert');
var request = require('supertest');
var glob    = require('glob');
var common  = require('./common.js');

function is_auth_d_running() {
    var files = glob.sync("ossec-authd-*", {cwd: common.ossec_path + "/var/run/"});
    return (files.length > 0);
}

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

describe('Agents', function() {

	describe('PUT/agents/:agent_name', function() {
        var agent_id = 0;

        // before(function(done){
        //     // We must check if authd is running. If it's running, the test must be skipped.
        //     // Because this test is without authd.
        //     if (is_auth_d_running()) done(new Error("Authd is running"));
        //     else done();
        // });

        after(function(done) {
            request(common.url)
            .delete("/agents/" + agent_id + '?purge')
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) return done(err);
                done();
              });
        });

        it('Request', function(done) {

            request(common.url)
            .put("/agents/testingNewAgentPut")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['id', 'key']);

                res.body.error.should.equal(0);
                res.body.data.id.should.match(/^\d+$/);
                res.body.data.key.should.match(/^[a-zA-Z0-9=]+$/);
                agent_id = res.body.data.id;
                done();
            });
        });

        it('Errors: Name already present', function(done) {

            request(common.url)
            .put("/agents/testingNewAgentPut")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                if (is_auth_d_running()) res.body.error.should.equal(9008);
                else                     res.body.error.should.equal(1705);
                res.body.message.should.be.type('string');
                done();
            });
        });

        it('Params: Bad agent name', function(done) {
            request(common.url)
            .put("/agents/testingNewAgent!!")
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

    });  // PUT/agents/:agent_name

    describe('DELETE/agents/:agent_id', function() {
        var agent_id = 0;

        before(function(done) {
            request(common.url)
            .put("/agents/TestingDeleteAgent")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) throw err;
                agent_id = res.body.data.id;
                setTimeout(function(){ 
                    done();
                }, 30)
              });
        });

        it('Request', function(done) {

            request(common.url)
            .delete("/agents/" + agent_id + '?purge')
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['msg', 'affected_agents']);

                res.body.error.should.equal(0);
                res.body.data.msg.should.be.type('string');
                res.body.data.affected_agents[0].should.equal(agent_id);
                done();
            });
        });

        it('Errors: ID is not present', function(done) {

            request(common.url)
            .delete("/agents/" + agent_id)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                if (is_auth_d_running()) res.body.data.failed_ids[0].error.code.should.equal(9011);
                else                     res.body.data.failed_ids[0].error.code.should.equal(1701);
                res.body.data.msg.should.be.type('string');
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .delete("/agents/abc")
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

    }); // DELETE/agents/:agent_id

    describe('POST/agents', function() {
        describe('Any', function() {
            var agent_id = 0;

            after(function(done) {
                request(common.url)
                .delete("/agents/" + agent_id + '?purge')
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err, res) {
                    if (err) return done(err);
                    done();
                  });

            });

            it('Request', function(done) {

                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost', 'ip':'any'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.should.have.properties(['id', 'key']);

                    res.body.error.should.equal(0);
                    res.body.data.id.should.match(/^\d+$/);
                    res.body.data.key.should.match(/^[0-9a-zA-Z=]+$/);
                    agent_id = res.body.data.id;
                    agent_key = res.body.data.key;
                    setTimeout(function(){ 
                        done();
                    }, 30)
                });
            });

            it('Check key', function (done) {
                request(common.url)
                    .get("/agents/" + agent_id + "/key")
                    .auth(common.credentials.user, common.credentials.password)
                    .expect("Content-type", /json/)
                    .expect(200)
                    .end(function (err, res) {
                        if (err) return done(err);

                        res.body.should.have.properties(['error', 'data']);

                        res.body.error.should.equal(0);
                        res.body.data.should.equal(agent_key);
                        done();
                    });
            });

            it('Errors: Name already present', function(done) {
                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost', 'ip':'any'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    if (is_auth_d_running()) res.body.error.should.equal(9008);
                    else                     res.body.error.should.equal(1705);
                    res.body.message.should.be.type('string');
                    done();
                });
            });

            it('Filters: Missing field name', function(done) {

                request(common.url)
                .post("/agents")
                .send({'ip':'any'})
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

            it('Filters: Invalid field', function(done) {

                request(common.url)
                .post("/agents")
                .send({'extraField': 'invalid', 'name': 'testagentpost', 'ip':'any'})
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

        });  // Any

        describe('IP Automatic', function() {
            var agent_id = 0;

            after(function(done) {
                request(common.url)
                .delete("/agents/" + agent_id + '?purge')
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err, res) {
                    if (err) return done(err);
                    done();
                  });

            });

            it('Request: Automatic IP', function(done) {

                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost2'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.should.have.properties(['id', 'key']);

                    res.body.error.should.equal(0);
                    res.body.data.id.should.match(/^\d+$/);
                    res.body.data.key.should.match(/^[0-9a-zA-Z=]+$/);
                    agent_id = res.body.data.id;
                    setTimeout(function(){ 
                        done();
                    }, 30)
                });
            });

            it('Errors: Duplicated IP', function(done) {
                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost3'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    if (is_auth_d_running()) res.body.error.should.equal(9007);
                    else                     res.body.error.should.equal(1706);
                    done();
                });
            });
        });  // IP Automatic

        describe('IP', function() {
            var agent_id = 0;

            afterEach(function(done) {
                if (agent_id != 0){
                    request(common.url)
                    .delete("/agents/" + agent_id + '?purge')
                    .auth(common.credentials.user, common.credentials.password)
                    .expect("Content-type",/json/)
                    .expect(200)
                    .end(function(err, res) {
                        if (err) return done(err);
                        done();
                      });
                }
                else {
                    done();
                }

            });

            it('Request', function(done) {

                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost4', 'ip': '192.246.247.248'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.id.should.match(/^\d+$/);
                    res.body.data.key.should.match(/^[0-9a-zA-Z=]+$/);
                    agent_id = res.body.data.id;
                    done();
                });
            });

            it('Filters: Bad IP', function(done) {

                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost4', 'ip': 'A.B.C.D'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(400)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(606);
                    done();
                });
            });

            it('Filters: Bad IP 2', function(done) {

                request(common.url)
                .post("/agents")
                .send({'name':'NewAgentPost4', 'ip': '333.333.333.333'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(400)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(606);
                    done();
                });
            });
        });  // IP

    }); //POST/agents

    describe('POST/agents/insert', function() {
        describe('Any', function() {
            var agent_id = 0;

            after(function(done) {
                request(common.url)
                .delete("/agents/" + agent_id + '?purge')
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err, res) {
                    if (err) return done(err);
                    done();
                  });

            });

            it('Request', function(done) {

                request(common.url)
                .post("/agents/insert")
                .send({'name':'NewAgentPostInsert', 'ip':'any', 'id':'750', 'key':'1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi64'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.should.have.properties(['id','key']);
                    res.body.error.should.equal(0);
                    res.body.data.id.should.match(/^\d+$/);
                    res.body.data.key.should.match(/^[a-zA-Z0-9=]+/);
                    agent_id = res.body.data.id;
                    setTimeout(function(){
                        done();
                    }, 30)
                });
            });

            it('Insert agent with force parameter (ID and name already presents)', function(done) {

                request(common.url)
                .post("/agents/insert")
                .send({'name':'NewAgentPostInsert', 'ip':'any', 'id':'750', 'key':'1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi64', 'force': '0'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.should.have.properties(['id','key']);
                    res.body.error.should.equal(0);
                    res.body.data.id.should.match(/^\d+$/);
                    res.body.data.key.should.match(/^[a-zA-Z0-9=]+/);
                    agent_id = res.body.data.id;
                    setTimeout(function(){
                        done();
                    }, 30)
                });
            });

            it('Errors: Name already present', function(done) {
                request(common.url)
                .post("/agents/insert")
                .send({'name':'NewAgentPostInsert', 'ip':'any', 'id':'751', 'key':'1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi64'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    if (is_auth_d_running()) res.body.error.should.equal(9008);
                    else                     res.body.error.should.equal(1705);
                    res.body.message.should.be.type('string');
                    done();
                });
            });

            it('Errors: ID already present', function(done) {
                request(common.url)
                .post("/agents/insert")
                .send({'name':'NewAgentPostInsert', 'ip':'any', 'id':'750', 'key':'1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi64'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    if (is_auth_d_running()) res.body.error.should.equal(9012);
                    else                     res.body.error.should.equal(1708);
                    res.body.message.should.be.type('string');
                    done();
                });
            });

            it('Errors: Invalid key', function(done) {
                request(common.url)
                .post("/agents/insert")
                .send({'name':'NewAgentPostInsert', 'ip':'any', 'id':'750', 'key':'short'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(1709);
                    res.body.message.should.be.type('string');
                    done();
                });
            });

            it('Filters: Missing fields', function(done) {

                request(common.url)
                .post("/agents/insert")
                .send({'ip':'any'})
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

            it('Filters: Invalid field', function(done) {

                request(common.url)
                .post("/agents/insert")
                .send({'extraField': 'invalid', 'name':'NewAgentPostInsert', 'ip':'any', 'id':'750', 'key':'1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi64'})
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

        });  // Any

        describe('IP Automatic', function() {
            var agent_id = 0;

            after(function(done) {
                request(common.url)
                .delete("/agents/" + agent_id + '?purge')
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err, res) {
                    if (err) return done(err);
                    done();
                  });

            });

            it('Request: Automatic IP', function(done) {

                request(common.url)
                .post("/agents/insert")
                .send({'name':'NewAgentPostInsert', 'id':'755', 'key':'1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi64'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.should.have.properties(['id', 'key']);
                    res.body.error.should.equal(0);
                    res.body.data.id.should.match(/^\d+$/);
                    res.body.data.key.should.match(/^[a-zA-Z0-9=]+/);
                    agent_id = res.body.data.id;
                    done();
                });
            });

            it('Errors: Duplicated IP', function(done) {
                request(common.url)
                .post("/agents/insert")
                .send({'name':'NewAgentPostInsert3', 'id':'756', 'key':'1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi64'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    if (is_auth_d_running()) res.body.error.should.equal(9007);
                    else                     res.body.error.should.equal(1706);
                    done();
                });
            });
        });  // IP Automatic

        describe('IP', function() {
            var agent_id = 0;

            afterEach(function(done) {
                if (agent_id != 0){
                    request(common.url)
                    .delete("/agents/" + agent_id + '?purge')
                    .auth(common.credentials.user, common.credentials.password)
                    .expect("Content-type",/json/)
                    .expect(200)
                    .end(function(err, res) {
                        if (err) return done(err);
                        done();
                      });
                }
                else {
                    done();
                }

            });

            it('Request', function(done) {

                request(common.url)
                .post("/agents/insert")
                .send({'name':'NewAgentPostInsert4', 'ip':'192.246.247.249', 'id':'760', 'key':'1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi64'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);
                    // res.body.data.should.have.properties(['id', 'key']);
                    res.body.error.should.equal(0);
                    res.body.data.id.should.match(/^\d+$/);
                    res.body.data.key.should.match(/^[a-zA-Z0-9=]+/);
                    agent_id = res.body.data.id;
                    done();
                });
            });

            it('Filters: Bad IP', function(done) {

                request(common.url)
                .post("/agents/insert")
                .send({'name':'NewAgentPostInsert', 'ip':'192.246.247.d', 'id':'760', 'key':'1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi64'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(400)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(606);
                    done();
                });
            });

            it('Filters: Bad IP 2', function(done) {

                request(common.url)
                .post("/agents/insert")
                .send({'name':'NewAgentPostInsert4', 'ip':'333.333.333.333', 'id':'760', 'key':'1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi64'})
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(400)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(606);
                    done();
                });
            });
        });  // IP

    }); //POST/agents/insert

}); // Agents
