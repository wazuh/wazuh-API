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

describe('Syscheck', function() {

    describe('GET/syscheck/:agent_id', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/syscheck/000")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['date', 'mtime', 'file',
                'size', 'perm', 'uname', 'gname', 'md5', 'sha1', 'sha256', 'inode', 'gid',
                'uid', 'type']);

                done();
            });
        });

        it('Pagination', function(done) {
            request(common.url)
            .get("/syscheck/000?offset=0&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(['date', 'mtime', 'file',
                'size', 'perm', 'uname', 'gname', 'md5', 'sha1', 'sha256', 'inode', 'gid',
                'uid', 'type']);
                done();
            });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/syscheck/000?limit=0")
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
            .get("/syscheck/000?sort=date&offset=0&limit=10")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['date', 'mtime', 'file',
                'size', 'perm', 'uname', 'gname', 'md5', 'sha1', 'sha256', 'inode', 'gid',
                'uid', 'type']);
                done();
            });
        });

        it('Search', function(done) {
            request(common.url)
            .get("/syscheck/000?search=a&offset=0&limit=10")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['date', 'mtime', 'file',
                'size', 'perm', 'uname', 'gname', 'md5', 'sha1', 'sha256', 'inode', 'gid',
                'uid', 'type']);
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .get("/syscheck/abc")
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
            .get("/syscheck/9999999")
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

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .get("/syscheck/000?random")
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
            .get("/syscheck/000?search=added&random")
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

        it('Filters: file', function(done) {
            request(common.url)
            .get("/syscheck/000?file=/var/ossec/etc/ossec.conf&offset=0&limit=10")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.an.integer;
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: type', function(done) {
            request(common.url)
            //.get("/syscheck/000?filetype=file&offset=0&limit=10")
            .get("/syscheck/000?type=file&offset=0&limit=10")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['date', 'mtime', 'file',
                'size', 'perm', 'uname', 'gname', 'md5', 'sha1', 'sha256', 'inode', 'gid',
                'uid', 'type']);
                done();
            });
        });

        it('Filters: summary', function(done) {
            request(common.url)
            .get("/syscheck/000?summary=yes&offset=0&limit=10")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['date', 'file', 'mtime']);
                done();
            });
        });

        it('Filters: md5', function(done) {
            request(common.url)
            .get("/syscheck/000?md5=88238db1ba8ce3df2c6d5f5d861b0306")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.an.integer;
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: sha1', function(done) {
            request(common.url)
            .get("/syscheck/000?sha1=fbed7cd200928050bc8d1a8d8ca342dd23723027")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.an.integer;
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });
        
        it('Filters: sha256', function(done) {
            request(common.url)
            .get("/syscheck/000?sha256=f221a45d80d6df1cc6b00c148e20096f78af459722c432d6e6df9b228668de8h")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.an.integer;
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: hash', function(done) {
            request(common.url)
            .get("/syscheck/000?hash=fbed7cd200928050bc8d1a8d8ca342dd23723027")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.an.integer;
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: distinct', function(done) {
            request(common.url)
            .get("/syscheck/000?select=uid&distinct")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.equal(1);
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: "%Y-%m-%d" date', function(done) {
            request(common.url)
            .get("/syscheck/000?q=mtime>2018-01-01")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.an.integer;
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: "%Y-%m-%d %H:%M:%S" date', function(done) {
            request(common.url)
            .get("/syscheck/000?q=mtime>" + encodeURI("2018-01-01 00:00:00"))
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.an.integer;
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

        it('Filters: timestamp date', function(done) {
            request(common.url)
            .get("/syscheck/000?q=mtime>1514761200")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.an.integer;
                res.body.data.items.should.be.instanceof(Array)
                done();
            });
        });

    });  // GET/syscheck/:agent_id

    describe('GET/syscheck/:agent_id/last_scan', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/syscheck/000/last_scan")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['end', 'start']);
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .get("/syscheck/abc/last_scan")
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
            .get("/syscheck/9999999/last_scan")
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

    });  // GET/syscheck/:agent_id/last_scan

    describe('DELETE/syscheck/:agent_id', function() {

        it('Request', function(done) {
            this.timeout(common.timeout);
            request(common.url)
            .delete("/syscheck/000")
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

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .delete("/syscheck/abc")
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
            .delete("/syscheck/9999999")
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

    });  // DELETE/syscheck/:agent_id

    describe('DELETE/experimental/syscheck', function() {

        it('Request', function(done) {
            this.timeout(common.timeout);
            request(common.url)
            .delete("/experimental/syscheck")
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

    });  // DELETE/experimental/syscheck

    describe('PUT/syscheck/:agent_id', function() {

        it('Request', function(done) {
            request(common.url)
            .put("/syscheck/000")
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

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .put("/syscheck/abc")
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
            .put("/syscheck/9999999")
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
    });  // PUT/syscheck/:agent_id

    describe('PUT/syscheck', function() {

        it('Request', function(done) {
            request(common.url)
            .put("/syscheck")
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

    });  // PUT/syscheck

});  // Decoders
