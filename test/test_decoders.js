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

describe('Decoders', function() {

    describe('GET/decoders', function() {
        it('Request', function(done) {
            request(common.url)
            .get("/decoders")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                done();
            });
        });

        it('Pagination', function(done) {
            request(common.url)
            .get("/decoders?offset=0&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                done();
            });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/decoders?limit=0")
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
            .get("/decoders?sort=-name")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                done();
            });
        });

        it('Search', function(done) {
            request(common.url)
            .get("/decoders?search=apache")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                done();
            });
        });

        it('Filters: File', function(done) {
            request(common.url)
            .get("/decoders?file=local_decoder.xml")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                done();
            });
        });

        it('Filters: Path', function(done) {
            request(common.url)
            .get("/decoders?path=etc/decoders")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                done();
            });
        });

        it('Filters: query 1', function(done) {
            request(common.url)
            .get("/decoders?q=name=wazuh;position=0")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['items', 'totalItems']);
                res.body.data.totalItems.should.equal(1);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                res.body.data.items[0].name.should.equal('wazuh');
                res.body.data.items[0].position.should.equal(0);

                done();
            });
        });

        it('Filters: query 2', function(done) {
            request(common.url)
            .get("/decoders?q=file~0450;position<3")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['items', 'totalItems']);
                res.body.data.totalItems.should.equal(3);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                res.body.data.items[0].position.should.be.below(3);

                done();
            });
        });

        it('Filters: query 3', function(done) {
            request(common.url)
            .get("/decoders?q=file~0380;position=10,file~0400;position=2")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['items', 'totalItems']);
                res.body.data.totalItems.should.equal(2);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                res.body.data.items[0].file.should.startWith('0380');
                res.body.data.items[0].position.should.equal(10);
                res.body.data.items[1].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                res.body.data.items[1].file.should.startWith('0400');
                res.body.data.items[1].position.should.equal(2);

                done();
            });
        });

        it('Filters: Invalid filter', function(done) {
            request(common.url)
                .get("/decoders?random=yes")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(604);
                res.body.message.should.be.type('string');
                done();
            });
        });

        it('Filters: Invalid filter - Extra field', function(done) {
            request(common.url)
                .get("/decoders?file=apache_decoders.xml&random=yes")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(604);
                res.body.message.should.be.type('string');
                done();
            });
        });
    });  // GET/decoders

    describe('GET/decoders/files', function() {
        it('Request', function(done) {
            request(common.url)
            .get("/decoders/files")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['status', 'path', 'file']);
                done();
            });
        });

        it('Pagination', function(done) {
            request(common.url)
            .get("/decoders/files?offset=0&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(['status', 'path', 'file']);
                done();
            });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/decoders/files?limit=0")
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
            .get("/decoders/files?sort=-file")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['status', 'path', 'file']);
                done();
            });
        });

        it('Search', function(done) {
            request(common.url)
            .get("/decoders/files?search=ssh")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(['status', 'path', 'file']);
                done();
            });
        });

    });  // GET/decoders/files

    describe('GET/decoders/parents', function() {
        it('Request', function(done) {
            request(common.url)
            .get("/decoders/parents")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                done();
            });
        });

        it('Pagination', function(done) {
            request(common.url)
            .get("/decoders/parents?offset=0&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                done();
            });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/decoders/parents?limit=0")
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
            .get("/decoders/parents?sort=-name")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                done();
            });
        });

        it('Search', function(done) {
            request(common.url)
            .get("/decoders/parents?search=apache")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                done();
            });
        });

    });  // GET/decoders/parents

    describe('GET/decoders/:decoder_name', function() {

            it('Request', function(done) {
                request(common.url)
                .get("/decoders/ar_log")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                    done();
                });
            });

            it('Pagination', function(done) {
                request(common.url)
                .get("/decoders/ar_log?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                    done();
                });
            });

            it('Retrieve all elements with limit=0', function(done) {
                request(common.url)
                .get("/decoders/ar_log?limit=0")
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
                .get("/decoders/ar_log?sort=-name")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                    done();
                });
            });

            it('Search', function(done) {
                request(common.url)
                .get("/decoders/ar_log?search=active")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type",/json/)
                .expect(200)
                .end(function(err,res){
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['position', 'details', 'path', 'file', 'name', 'status']);
                    done();
                });
            });

    });  // GET/decoders/:decoder_name

});  // Decoders
