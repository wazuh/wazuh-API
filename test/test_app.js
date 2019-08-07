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

describe('App', function() {

    describe('Authentication', function() {
        it('Wrong USER', function(done) {
            request(common.url)
            .get("/")
            .auth('random', common.credentials.password)
            .expect("Content-type","text/plain")
            .expect(401)
            .end(function(err,res){
                if (err) return done(err);
                done();
            });
        });

        it('Wrong password', function(done) {
            request(common.url)
            .get("/")
            .auth(common.credentials.user, 'random')
            .expect("Content-type","text/plain")
            .expect(401)
            .end(function(err,res){
                if (err) return done(err);
                done();
            });
        });

        it('Home', function(done) {
            request(common.url)
            .get("/")
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

    });

    describe('Requests', function() {

        it('Inexistent request', function(done) {
            request(common.url)
            .get("/random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(404)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(603);
                done();
            });
        });

        it('API version', function(done) {
            request(common.url)
            .get("/version")
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

    });
});
