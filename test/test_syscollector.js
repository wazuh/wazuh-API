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

describe('Syscollector', function () {


    agent_id = "000"
    os_fields = ["sysname","version","architecture","scan","release","hostname","os"]
    describe('GET/syscollector/:agent_id/os', function () {
        var expected_hostname = "";
        var expected_architecture = "";
        before(function (done) {
            request(common.url)
                .get("/agents/" + agent_id)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['os', 'manager']);
                    res.body.data.os.should.have.properties(['arch', 'platform']);
                    expected_hostname = res.body.data.manager;
                    expected_architecture = res.body.data.os.arch;
                    done();
                });
        });

        it('Request', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/os")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.array;
                    res.body.data.should.have.properties(os_fields);
                    res.body.data.os.should.have.properties(['name', 'version']);
                    res.body.data.scan.should.have.properties(['id', 'time']);
                    res.body.data.hostname.should.be.equal(expected_hostname);
                    res.body.data.architecture.should.be.equal(expected_architecture);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/os?select=os_version,sysname,release")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['os_version', 'sysname', 'release']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/os?select=wrongParam")
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

    });  // GET/syscollector/:agent_id/os

    hardware_fields = ['ram', 'scan', 'board_serial', 'cpu']
    describe('GET/syscollector/:agent_id/hardware', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/hardware")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.be.an.array;
                    res.body.data.should.have.properties(hardware_fields);
                    res.body.data.ram.should.have.properties(['free', 'total']);
                    res.body.data.scan.should.have.properties(['id', 'time']);
                    res.body.data.cpu.should.have.properties(['name', 'cores', 'mhz']);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/hardware?select=ram_free,board_serial,cpu_name,ram_total")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['board_serial', 'ram', 'cpu_name']);
                    res.body.data.ram.should.have.properties(['free', 'total']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/hardware?select=wrongParam")
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

    });  // GET/syscollector/:agent_id/os

    packages_fields = ['vendor', 'description', 'format', 'version', 'architecture', 'name', 'scan']
    describe('GET/syscollector/:agent_id/packages', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(packages_fields);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?select=scan_id,description,architecture")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['description', 'architecture', 'scan_id']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(packages_fields);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        it('Sort -', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?sort=-name&limit=2")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
                    res.body.data.items[0].should.have.properties(['name']);
                    res.body.data.items[1].should.have.properties(['name']);
                    //res.body.data.items[0].name.should.not.be.greaterThan(res.body.data.items[1].name);
                    done();
                });
        });

        it('Sort +', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?sort=+name&limit=2")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
                    res.body.data.items[0].should.have.properties(['name']);
                    res.body.data.items[1].should.have.properties(['name']);
                    //res.body.data.items[1].name.should.not.be.greaterThan(res.body.data.items[0].name);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        var expected_name = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['name']);
                    expected_name = res.body.data.items[0].name;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?search=" + expected_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(packages_fields);
                    res.body.data.items[0].name.should.be.equal(expected_name);
                    done();
                });
        });

        var expected_vendor = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['vendor']);
                    expected_vendor = res.body.data.items[0].vendor;
                    done();
                });
        });

        it('Filter: vendor', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?vendor=" + expected_vendor)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['vendor']);
                    res.body.data.items[0].vendor.should.be.equal(expected_vendor);
                    done();
                });
        });

        var expected_filter_name = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['name']);
                    expected_filter_name = res.body.data.items[0].name;
                    done();
                });
        });

        it('Filter: name', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?name=" + expected_filter_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['name']);
                    res.body.data.items[0].name.should.be.equal(expected_filter_name);
                    done();
                });
        });

        var expected_architecture = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['architecture']);
                    expected_architecture = res.body.data.items[0].architecture;
                    done();
                });
        });

        it('Filter: architecture', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?architecture=" + expected_architecture)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['architecture']);
                    res.body.data.items[0].architecture.should.be.equal(expected_architecture);
                    done();
                });
        });

        var expected_format = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['format']);
                    expected_format = res.body.data.items[0].format;
                    done();
                });
        });

        it('Filter: format', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?format=" + expected_format)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['format']);
                    res.body.data.items[0].format.should.be.equal(expected_format);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/packages?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

    });  // GET/syscollector/:agent_id/packages


    describe('GET/experimental/syscollector/packages', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(packages_fields);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?select=scan_id,description,scan_time,architecture")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['scan', 'description', 'architecture']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(packages_fields);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        it('Sort -', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?sort=-name&limit=2")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
                    res.body.data.items[0].should.have.properties(['name']);
                    res.body.data.items[1].should.have.properties(['name']);
                    //res.body.data.items[0].name.should.not.be.greaterThan(res.body.data.items[1].name);
                    done();
                });
        });

        it('Sort +', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?sort=+name&limit=2")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
                    res.body.data.items[0].should.have.properties(['name']);
                    res.body.data.items[1].should.have.properties(['name']);
                    //res.body.data.items[1].name.should.not.be.greaterThan(res.body.data.items[0].name);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        var expected_name = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['name']);
                    expected_name = res.body.data.items[0].name;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?search=" + expected_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(packages_fields);
                    res.body.data.items[0].name.should.be.equal(expected_name);
                    done();
                });
        });

        var expected_vendor = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['vendor']);
                    expected_vendor = res.body.data.items[0].vendor;
                    done();
                });
        });

        it('Filter: vendor', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?vendor=" + expected_vendor)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['vendor']);
                    res.body.data.items[0].vendor.should.be.equal(expected_vendor);
                    done();
                });
        });

        var expected_filter_name = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['name']);
                    expected_filter_name = res.body.data.items[0].name;
                    done();
                });
        });

        it('Filter: name', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?name=" + expected_filter_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['name']);
                    res.body.data.items[0].name.should.be.equal(expected_filter_name);
                    done();
                });
        });

        var expected_architecture = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['architecture']);
                    expected_architecture = res.body.data.items[0].architecture;
                    done();
                });
        });

        it('Filter: architecture', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?architecture=" + expected_architecture)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['architecture']);
                    res.body.data.items[0].architecture.should.be.equal(expected_architecture);
                    done();
                });
        });

        var expected_format = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['format']);
                    expected_format = res.body.data.items[0].format;
                    done();
                });
        });

        it('Filter: format', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?format=" + expected_format)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['format']);
                    res.body.data.items[0].format.should.be.equal(expected_format);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/experimental/syscollector/packages?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

    });  // GET/syscollector/packages



    describe('GET/experimental/syscollector/os', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/experimental/syscollector/os")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(os_fields);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?select=sysname,version,release,os_version")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['sysname', 'version', 'release', 'os_version']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(os_fields);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        var expected_name = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['sysname']);
                    expected_name = res.body.data.items[0].sysname;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?search=" + expected_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(os_fields);
                    res.body.data.items[0].sysname.should.be.equal(expected_name);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        var expected_architecture = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['architecture']);
                    expected_architecture = res.body.data.items[0].architecture;
                    done();
                });
        });

        it('Filter: architecture', function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?architecture=" + expected_architecture)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['architecture']);
                    res.body.data.items[0].architecture.should.be.equal(expected_architecture);
                    done();
                });
        });

        var expected_os_name = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/os")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['os']);
                    res.body.data.os.should.have.properties(['name']);
                    expected_os_name = res.body.data.os.name;
                    done();
                });
        });

        it('Filter: os_name', function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?os_name=" + expected_os_name)
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
                    res.body.data.items[0].os.name.should.be.equal(expected_os_name);
                    done();
                });
        });

        var expected_os_version = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['os']);
                    expected_os_version = res.body.data.items[0].os_version;
                    done();
                });
        });

        var expected_release = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(['release']);
                    expected_release = res.body.data.items[0].release;
                    done();
                });
        });

        it('Filter: release', function (done) {
            request(common.url)
                .get("/experimental/syscollector/os?release=" + expected_release)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['release']);
                    res.body.data.items[0].release.should.be.equal(expected_release);
                    done();
                });
        });

    });  // GET/experimental/syscollector/os

    describe('GET/experimental/syscollector/hardware', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(hardware_fields);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware?select=ram_free,board_serial,cpu_name,agent_id,cpu_mhz")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['ram_free', 'board_serial', 'cpu', 'agent_id', 'cpu']);
                    res.body.data.items[0].cpu.should.have.properties(['mhz','name']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(hardware_fields);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        var expected_ram_free = "";
        it('Search', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware?search=Intel")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(hardware_fields);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        var expected_ram_total = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/hardware")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['ram']);
                    res.body.data.ram.should.have.properties(['total']);
                    expected_ram_total = res.body.data.ram.total;
                    done();
                });
        });

        it('Filter: ram_total', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware?ram_total=" + expected_ram_total)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['ram']);
                    res.body.data.items[0].ram.total.should.be.equal(expected_ram_total);
                    done();
                });
        });

        var expected_cpu_cores = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/hardware")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['cpu']);
                    res.body.data.cpu.should.have.properties(['cores']);
                    expected_cpu_cores = res.body.data.cpu.cores;
                    done();
                });
        });

        it('Filter: cpu_cores', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware?cpu_cores=" + expected_cpu_cores)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['cpu']);
                    res.body.data.items[0].cpu.cores.should.be.equal(expected_cpu_cores);
                    done();
                });
        });

        var expected_cpu_mhz = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/hardware")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['cpu']);
                    res.body.data.cpu.should.have.properties(['mhz']);
                    expected_cpu_mhz = res.body.data.cpu.mhz;
                    done();
                });
        });

        it('Filter: cpu_mhz', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware?cpu_mhz=" + expected_cpu_mhz)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['cpu']);
                    res.body.data.items[0].cpu.mhz.should.be.equal(expected_cpu_mhz);
                    done();
                });
        });

        var expected_board_serial = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/hardware")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.should.have.properties(['board_serial']);
                    expected_board_serial = res.body.data.board_serial;
                    done();
                });
        });

        it('Filter: board_serial', function (done) {
            request(common.url)
                .get("/experimental/syscollector/hardware?board_serial=" + expected_board_serial)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['board_serial']);
                    res.body.data.items[0].board_serial.should.be.equal(expected_board_serial);
                    done();
                });
        });

    });  // GET experimental/syscollector/hardware



    describe('GET/experimental/syscollector/processes', function () {
        processes_properties = ['tty', 'rgroup', 'sgroup', 'resident', 'share',
        'session', 'scan_time', 'size', 'scan_id', 'egroup', 'tgid', 'priority',
        'fgroup', 'state', 'nlwp', 'nice', 'euser', 'start_time', 'stime',
        'vm_size', 'utime', 'ppid', 'name', 'pgrp', 'ruser', 'suser', 'processor',
        'agent_id']

        it('Request', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(processes_properties);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?select=tty,sgroup,share,session,scan_id")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['tty', 'sgroup', 'share', 'session', 'scan_id']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        expected_state = "";
        expected_ppid = "";
        expected_egroup = "";
        expected_euser = "";
        expected_fgroup = "";
        expected_name = "";
        expected_nlwp = "";
        expected_pgrp = "";
        expected_priority = "";
        expected_rgroup = "";
        expected_ruser = "";
        expected_sgroup = "";
        expected_suser = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    expected_state = res.body.data.items[0].state;
                    expected_ppid = res.body.data.items[0].ppid;
                    expected_egroup = res.body.data.items[0].egroup;
                    expected_euser = res.body.data.items[0].euser;
                    expected_fgroup = res.body.data.items[0].fgroup;
                    expected_name = res.body.data.items[0].name;
                    expected_nlwp = res.body.data.items[0].nlwp;
                    expected_pgrp = res.body.data.items[0].pgrp;
                    expected_priority = res.body.data.items[0].priority;
                    expected_rgroup = res.body.data.items[0].rgroup;
                    expected_ruser = res.body.data.items[0].ruser;
                    expected_sgroup = res.body.data.items[0].sgroup;
                    expected_suser = res.body.data.items[0].suser;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?search=" + expected_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].name.should.be.equal(expected_name);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        it('Filter: state', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=2&offset=1&state=" + expected_state)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].state.should.be.equal(expected_state);
                    done();
                });
        });

        it('Filter: ppid', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=2&offset=1&ppid=" + expected_ppid)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].ppid.should.be.equal(expected_ppid);
                    done();
                });
        });

        it('Filter: egroup', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=2&offset=1&egroup=" + expected_egroup)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].egroup.should.be.equal(expected_egroup);
                    done();
                });
        });

        it('Filter: euser', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=2&offset=1&euser=" + expected_euser)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].euser.should.be.equal(expected_euser);
                    done();
                });
        });

        it('Filter: fgroup', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=2&offset=1&fgroup=" + expected_fgroup)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].fgroup.should.be.equal(expected_fgroup);
                    done();
                });
        });

        it('Filter: name', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?name=" + expected_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].name.should.be.equal(expected_name);
                    done();
                });
        });

        it('Filter: nlwp', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=2&offset=1&nlwp=" + expected_nlwp)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].nlwp.should.be.equal(expected_nlwp);
                    done();
                });
        });

        it('Filter: pgrp', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?pgrp=" + expected_pgrp)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].pgrp.should.be.equal(expected_pgrp);
                    done();
                });
        });

        it('Filter: priority', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=2&offset=1&priority=" + expected_priority)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].priority.should.be.equal(expected_priority);
                    done();
                });
        });

        it('Filter: rgroup', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=2&offset=1&rgroup=" + expected_rgroup)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].rgroup.should.be.equal(expected_rgroup);
                    done();
                });
        });

        it('Filter: ruser', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=2&offset=1&ruser=" + expected_ruser)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].ruser.should.be.equal(expected_ruser);
                    done();
                });
        });

        it('Filter: sgroup', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=2&offset=1&sgroup=" + expected_sgroup)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].sgroup.should.be.equal(expected_sgroup);
                    done();
                });
        });

        it('Filter: suser', function (done) {
            request(common.url)
                .get("/experimental/syscollector/processes?limit=2&offset=1&suser=" + expected_suser)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].suser.should.be.equal(expected_suser);
                    done();
                });
        });


    });  // GET/syscollector/processes



    ports_properties = ['scan', 'protocol', 'local', 'remote', 'tx_queue',
                        'rx_queue', 'inode', 'state']
    describe('GET/experimental/syscollector/ports', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(ports_properties);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?select=protocol,remote_ip,tx_queue,state")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['protocol', 'remote_ip', 'tx_queue', 'state']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        expected_protocol = "";
        expected_local_ip = "";
        expected_local_port = "";
        expected_remote_ip = "";
        expected_tx_queue = "";
        expected_state = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    expected_protocol = res.body.data.items[0].protocol;
                    expected_local_ip = res.body.data.items[0].local.ip;
                    expected_local_port = res.body.data.items[0].local.port;
                    expected_remote_ip = res.body.data.items[0].remote.ip;
                    expected_tx_queue = res.body.data.items[0].tx_queue;
                    expected_state = res.body.data.items[0].state;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?search=" + expected_remote_ip)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].remote.ip.should.be.equal(expected_remote_ip);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        it('Filter: protocol', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?protocol=" + expected_protocol)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].protocol.should.be.equal(expected_protocol);
                    done();
                });
        });

        it('Filter: local_ip', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?local_ip=" + expected_local_ip)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].local.ip.should.be.equal(expected_local_ip);
                    done();
                });
        });

        it('Filter: local_port', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?local_port=" + expected_local_port)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].local.port.should.be.equal(expected_local_port);
                    done();
                });
        });

        it('Filter: remote_ip', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?remote_ip=" + expected_remote_ip)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].remote.ip.should.be.equal(expected_remote_ip);
                    done();
                });
        });

        it('Filter: tx_queue', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?tx_queue=" + expected_tx_queue)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].tx_queue.should.be.equal(expected_tx_queue);
                    done();
                });
        });

        it('Filter: state', function (done) {
            request(common.url)
                .get("/experimental/syscollector/ports?state=" + expected_state)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].state.should.be.equal(expected_state);
                    done();
                });
        });



    });  // GET/experimental/syscollector/ports


    describe('GET/syscollector/netaddr', function () {
        netaddr_properties = ['scan_id', 'iface', 'proto', 'address', 'netmask', 'broadcast', 'agent_id']

        it('Request', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?select=proto,netmask,broadcast")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['proto', 'netmask', 'broadcast']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        expected_iface = "";
        expected_proto = "";
        expected_address = "";
        expected_broadcast = "";
        expected_netmask = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    expected_proto = res.body.data.items[0].proto;
                    expected_address = res.body.data.items[0].address;
                    expected_broadcast = res.body.data.items[0].broadcast;
                    expected_netmask = res.body.data.items[0].netmask;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?search=" + expected_broadcast)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].broadcast.should.be.equal(expected_broadcast);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        it('Filter: iface', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?iface=" + expected_iface)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].iface.should.be.equal(expected_iface);
                    done();
                });
        });

        it('Filter: proto', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?proto=" + expected_proto)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].proto.should.be.equal(expected_proto);
                    done();
                });
        });

        it('Filter: address', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?address=" + expected_address)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].address.should.be.equal(expected_address);
                    done();
                });
        });

        it('Filter: broadcast', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?broadcast=" + expected_broadcast)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].broadcast.should.be.equal(expected_broadcast);
                    done();
                });
        });

        it('Filter: netmask', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netaddr?netmask=" + expected_netmask)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].netmask.should.be.equal(expected_netmask);
                    done();
                });
        });

    });  // GET/syscollector/netaddr

    describe('GET/experimental/syscollector/netproto', function () {
        netproto_properties = ['scan_id', 'iface', 'type', 'gateway', 'dhcp']

        it('Request', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?select=iface,gateway,dhcp")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['iface', 'gateway', 'dhcp']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        expected_iface = "";
        expected_type = "";
        expected_gateway = "";
        expected_dhcp = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    expected_iface = res.body.data.items[0].iface;
                    expected_type = res.body.data.items[0].type;
                    expected_gateway = res.body.data.items[0].gateway;
                    expected_dhcp = res.body.data.items[0].dhcp;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?search=" + expected_dhcp)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    res.body.data.items[0].dhcp.should.be.equal(expected_dhcp);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        it('Filter: iface', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?=" + expected_proto)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    res.body.data.items[0].iface.should.be.equal(expected_iface);
                    done();
                });
        });

        it('Filter: type', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?=" + expected_proto)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    res.body.data.items[0].type.should.be.equal(expected_type);
                    done();
                });
        });

        it('Filter: gateway', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?=" + expected_proto)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    res.body.data.items[0].gateway.should.be.equal(expected_gateway);
                    done();
                });
        });

        it('Filter: dhcp', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netproto?=" + expected_proto)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    res.body.data.items[0].dhcp.should.be.equal(expected_dhcp);
                    done();
                });
        });
    });  // GET/syscollector/netproto


    netiface_properties = ['scan', 'name', 'type', 'state', 'mtu', 'mac', 'tx', 'rx', 'agent_id']
    describe('GET/experimental/syscollector/netiface', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?select=type,rx_bytes,tx_errors,tx_dropped,mac")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.items[0].should.have.properties(['type', 'rx_bytes', 'tx', 'mac']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        expected_name = "";
        expected_adapter = "";
        expected_type = "";
        expected_state = "";
        expected_mtu = "";
        expected_tx_packets = "";
        expected_rx_packets = "";
        expected_tx_bytes = "";
        expected_rx_bytes = "";
        expected_tx_errors = "";
        expected_rx_errors = "";
        expected_tx_dropped = "";
        expected_rx_dropped = "";
        expected_mac = "";
        before(function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    expected_name = res.body.data.items[0].name;
                    expected_adapter = res.body.data.items[0].adapter;
                    expected_type = res.body.data.items[0].type;
                    expected_state = res.body.data.items[0].state;
                    expected_mtu = res.body.data.items[0].mtu;
                    expected_tx_packets = res.body.data.items[0].tx.packets;
                    expected_rx_packets = res.body.data.items[0].rx.packets;
                    expected_tx_bytes = res.body.data.items[0].tx.bytes;
                    expected_rx_bytes = res.body.data.items[0].rx.bytes;
                    expected_tx_errors = res.body.data.items[0].tx.errors;
                    expected_rx_errors = res.body.data.items[0].rx.errors;
                    expected_tx_dropped = res.body.data.items[0].tx.dropped;
                    expected_rx_dropped = res.body.data.items[0].rx.dropped;
                    expected_mac = res.body.data.items[0].mac;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?search=" + expected_mac)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].mac.should.be.equal(expected_mac);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        it('Filter: name', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?name=" + expected_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].name.should.be.equal(expected_name);
                    done();
                });
        });

        it('Filter: type', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?type=" + expected_type)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].type.should.be.equal(expected_type);
                    done();
                });
        });

        it('Filter: state', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?state=" + expected_state)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].state.should.be.equal(expected_state);
                    done();
                });
        });

        it('Filter: mtu', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?mtu=" + expected_mtu)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].mtu.should.be.equal(expected_mtu);
                    done();
                });
        });

        it('Filter: tx_packets', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?tx_packets=" + expected_tx_packets)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].tx.packets.should.be.equal(expected_tx_packets);
                    done();
                });
        });

        it('Filter: rx_packets', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?rx_packets=" + expected_rx_packets)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].rx.packets.should.be.equal(expected_rx_packets);
                    done();
                });
        });

        it('Filter: tx_bytes', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?tx_bytes=" + expected_tx_bytes)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].tx.bytes.should.be.equal(expected_tx_bytes);
                    done();
                });
        });

        it('Filter: rx_bytes', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?rx_bytes=" + expected_rx_bytes)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].rx.bytes.should.be.equal(expected_rx_bytes);
                    done();
                });
        });

        it('Filter: tx_errors', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?tx_errors=" + expected_tx_errors)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].tx.errors.should.be.equal(expected_tx_errors);
                    done();
                });
        });

        it('Filter: rx_errors', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?rx_errors=" + expected_rx_errors)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].rx.errors.should.be.equal(expected_rx_errors);
                    done();
                });
        });

        it('Filter: tx_dropped', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?tx_dropped=" + expected_tx_dropped)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].tx.dropped.should.be.equal(expected_tx_dropped);
                    done();
                });
        });

        it('Filter: rx_dropped', function (done) {
            request(common.url)
                .get("/experimental/syscollector/netiface?rx_dropped=" + expected_rx_dropped)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].rx.dropped.should.be.equal(expected_rx_dropped);
                    done();
                });
        });


    });  // GET/syscollector/netiface


    describe('GET/syscollector/' + agent_id + '/processes', function () {
        processes_properties = ['tty', 'rgroup', 'sgroup', 'resident',
            'share', 'session', 'scan', 'size', 'egroup', 'tgid', 'priority',
            'fgroup', 'state', 'nlwp', 'nice', 'euser', 'start_time',
            'stime', 'vm_size', 'utime', 'ppid', 'name', 'pgrp', 'ruser', 'suser',
            'processor']

        it('Request', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(processes_properties);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?select=tty,sgroup,share,session,scan_id")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['tty', 'sgroup', 'share', 'session', 'scan_id']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        expected_state = "";
        expected_ppid = "";
        expected_egroup = "";
        expected_euser = "";
        expected_fgroup = "";
        expected_name = "";
        expected_nlwp = "";
        expected_pgrp = "";
        expected_priority = "";
        expected_rgroup = "";
        expected_ruser = "";
        expected_sgroup = "";
        expected_suser = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    expected_state = res.body.data.items[0].state;
                    expected_ppid = res.body.data.items[0].ppid;
                    expected_egroup = res.body.data.items[0].egroup;
                    expected_euser = res.body.data.items[0].euser;
                    expected_fgroup = res.body.data.items[0].fgroup;
                    expected_name = res.body.data.items[0].name;
                    expected_nlwp = res.body.data.items[0].nlwp;
                    expected_pgrp = res.body.data.items[0].pgrp;
                    expected_priority = res.body.data.items[0].priority;
                    expected_rgroup = res.body.data.items[0].rgroup;
                    expected_ruser = res.body.data.items[0].ruser;
                    expected_sgroup = res.body.data.items[0].sgroup;
                    expected_suser = res.body.data.items[0].suser;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?search=" + expected_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].name.should.be.equal(expected_name);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        it('Filter: state', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=2&offset=1&state=" + expected_state)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].state.should.be.equal(expected_state);
                    done();
                });
        });

        it('Filter: ppid', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=2&offset=1&ppid=" + expected_ppid)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].ppid.should.be.equal(expected_ppid);
                    done();
                });
        });

        it('Filter: egroup', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=2&offset=1&egroup=" + expected_egroup)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].egroup.should.be.equal(expected_egroup);
                    done();
                });
        });

        it('Filter: euser', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=2&offset=1&euser=" + expected_euser)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].euser.should.be.equal(expected_euser);
                    done();
                });
        });

        it('Filter: fgroup', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=2&offset=1&fgroup=" + expected_fgroup)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].fgroup.should.be.equal(expected_fgroup);
                    done();
                });
        });

        it('Filter: name', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?name=" + expected_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].name.should.be.equal(expected_name);
                    done();
                });
        });

        it('Filter: nlwp', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=2&offset=1&nlwp=" + expected_nlwp)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].nlwp.should.be.equal(expected_nlwp);
                    done();
                });
        });

        it('Filter: pgrp', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?pgrp=" + expected_pgrp)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].pgrp.should.be.equal(expected_pgrp);
                    done();
                });
        });

        it('Filter: priority', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=2&offset=1&priority=" + expected_priority)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].priority.should.be.equal(expected_priority);
                    done();
                });
        });

        it('Filter: rgroup', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=2&offset=1&rgroup=" + expected_rgroup)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].rgroup.should.be.equal(expected_rgroup);
                    done();
                });
        });

        it('Filter: ruser', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=2&offset=1&ruser=" + expected_ruser)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].ruser.should.be.equal(expected_ruser);
                    done();
                });
        });

        it('Filter: sgroup', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=2&offset=1&sgroup=" + expected_sgroup)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].sgroup.should.be.equal(expected_sgroup);
                    done();
                });
        });

        it('Filter: suser', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/processes?limit=2&offset=1&suser=" + expected_suser)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(processes_properties);
                    res.body.data.items[0].suser.should.be.equal(expected_suser);
                    done();
                });
        });


    });  // GET/syscollector/:agent_id/processes


    describe('GET/syscollector/' + agent_id + '/ports', function () {
        it('Request', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(ports_properties);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?select=protocol,remote_ip,tx_queue,state")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['protocol', 'remote_ip', 'tx_queue', 'state']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        expected_protocol = "";
        expected_local_ip = "";
        expected_local_port = "";
        expected_remote_ip = "";
        expected_tx_queue = "";
        expected_state = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    expected_protocol = res.body.data.items[0].protocol;
                    expected_local_ip = res.body.data.items[0].local.ip;
                    expected_local_port = res.body.data.items[0].local.port;
                    expected_remote_ip = res.body.data.items[0].remote.ip;
                    expected_tx_queue = res.body.data.items[0].tx_queue;
                    expected_state = res.body.data.items[0].state;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?search=" + expected_remote_ip)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].remote.ip.should.be.equal(expected_remote_ip);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        it('Filter: protocol', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?protocol=" + expected_protocol)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].protocol.should.be.equal(expected_protocol);
                    done();
                });
        });

        it('Filter: local_ip', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?local_ip=" + expected_local_ip)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].local.ip.should.be.equal(expected_local_ip);
                    done();
                });
        });

        it('Filter: local_port', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?local_port=" + expected_local_port)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].local.port.should.be.equal(expected_local_port);
                    done();
                });
        });

        it('Filter: remote_ip', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?remote_ip=" + expected_remote_ip)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].remote.ip.should.be.equal(expected_remote_ip);
                    done();
                });
        });

        it('Filter: tx_queue', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?tx_queue=" + expected_tx_queue)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].tx_queue.should.be.equal(expected_tx_queue);
                    done();
                });
        });

        it('Filter: state', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/ports?state=" + expected_state)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(ports_properties);
                    res.body.data.items[0].state.should.be.equal(expected_state);
                    done();
                });
        });



    });  // GET/syscollector/:agent_id/ports


    describe('GET/syscollector/' + agent_id + '/netaddr', function () {
        netaddr_properties.splice(netaddr_properties.indexOf('agent_id'), 1)

        it('Request', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?select=proto,netmask,broadcast")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['proto', 'netmask', 'broadcast']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        expected_iface = "";
        expected_proto = "";
        expected_address = "";
        expected_broadcast = "";
        expected_netmask = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    expected_iface = res.body.data.items[0].iface;
                    expected_proto = res.body.data.items[0].proto;
                    expected_address = res.body.data.items[0].address;
                    expected_broadcast = res.body.data.items[0].broadcast;
                    expected_netmask = res.body.data.items[0].netmask;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?search=" + expected_broadcast)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].broadcast.should.be.equal(expected_broadcast);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        it('Filter: iface', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?iface=" + expected_iface)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].iface.should.be.equal(expected_iface);
                    done();
                });
        });

        it('Filter: proto', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?proto=" + expected_proto)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].proto.should.be.equal(expected_proto);
                    done();
                });
        });

        it('Filter: address', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?address=" + expected_address)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].address.should.be.equal(expected_address);
                    done();
                });
        });

        it('Filter: broadcast', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?broadcast=" + expected_broadcast)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].broadcast.should.be.equal(expected_broadcast);
                    done();
                });
        });

        it('Filter: netmask', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netaddr?netmask=" + expected_netmask)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netaddr_properties);
                    res.body.data.items[0].netmask.should.be.equal(expected_netmask);
                    done();
                });
        });

    });  // GET/syscollector/:agent_id/netaddr

    describe('GET/syscollector/' + agent_id + '/netproto', function () {
        netproto_properties = ['scan_id', 'iface', 'type', 'gateway', 'dhcp']

        it('Request', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?select=iface,gateway,dhcp")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(['iface', 'gateway', 'dhcp']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        expected_iface = "";
        expected_type = "";
        expected_gateway = "";
        expected_dhcp = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    expected_iface = res.body.data.items[0].iface;
                    expected_type = res.body.data.items[0].type;
                    expected_gateway = res.body.data.items[0].gateway;
                    expected_dhcp = res.body.data.items[0].dhcp;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?search=" + expected_dhcp)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    res.body.data.items[0].dhcp.should.be.equal(expected_dhcp);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        it('Filter: iface', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?=" + expected_proto)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    res.body.data.items[0].iface.should.be.equal(expected_iface);
                    done();
                });
        });

        it('Filter: type', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?=" + expected_proto)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    res.body.data.items[0].type.should.be.equal(expected_type);
                    done();
                });
        });

        it('Filter: gateway', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?=" + expected_proto)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    res.body.data.items[0].gateway.should.be.equal(expected_gateway);
                    done();
                });
        });

        it('Filter: dhcp', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netproto?=" + expected_proto)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netproto_properties);
                    res.body.data.items[0].dhcp.should.be.equal(expected_dhcp);
                    done();
                });
        });

    });  // GET/syscollector/:agent_id/netproto

    describe('GET/syscollector/' + agent_id + '/netiface', function () {
        netiface_properties.splice(netiface_properties.indexOf('agent_id'), 1);

        it('Request', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    done();
                });
        });

        it('Selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?select=type,rx_bytes,tx_errors,tx_dropped,mac")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array);
                    res.body.data.items[0].should.have.properties(['type', 'rx_bytes', 'tx', 'mac']);
                    done();
                });
        });

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?select=wrongParam")
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

        it('Pagination', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?offset=0&limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    done();
                });
        });

        it('Wrong limit', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?offset=0&limit=1a")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'message']);

                    res.body.error.should.equal(600);
                    done();
                });
        });

        expected_name = "";
        expected_adapter = "";
        expected_type = "";
        expected_state = "";
        expected_mtu = "";
        expected_tx_packets = "";
        expected_rx_packets = "";
        expected_tx_bytes = "";
        expected_rx_bytes = "";
        expected_tx_errors = "";
        expected_rx_errors = "";
        expected_tx_dropped = "";
        expected_rx_dropped = "";
        expected_mac = "";
        before(function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.error.should.equal(0);
                    res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                    expected_name = res.body.data.items[0].name;
                    expected_adapter = res.body.data.items[0].adapter;
                    expected_type = res.body.data.items[0].type;
                    expected_state = res.body.data.items[0].state;
                    expected_mtu = res.body.data.items[0].mtu;
                    expected_tx_packets = res.body.data.items[0].tx.packets;
                    expected_rx_packets = res.body.data.items[0].rx.packets;
                    expected_tx_bytes = res.body.data.items[0].tx.bytes;
                    expected_rx_bytes = res.body.data.items[0].rx.bytes;
                    expected_tx_errors = res.body.data.items[0].tx.errors;
                    expected_rx_errors = res.body.data.items[0].rx.errors;
                    expected_tx_dropped = res.body.data.items[0].tx.dropped;
                    expected_rx_dropped = res.body.data.items[0].rx.dropped;
                    expected_mac = res.body.data.items[0].mac;
                    done();
                });
        });

        it('Search', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?search=" + expected_mac)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);

                    res.body.should.have.properties(['error', 'data']);

                    res.body.error.should.equal(0);
                    res.body.data.totalItems.should.be.above(0);
                    res.body.data.items.should.be.instanceof(Array)
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].mac.should.be.equal(expected_mac);
                    done();
                });
        });

        it('Wrong filter', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?wrongFilter=value")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(400)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(604);
                    done();
                });
        });

        it('Wrong Sort', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'message']);
                    res.body.error.should.equal(1403);
                    done();
                });
        });

        it('Filter: name', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?name=" + expected_name)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].name.should.be.equal(expected_name);
                    done();
                });
        });

        it('Filter: type', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?type=" + expected_type)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].type.should.be.equal(expected_type);
                    done();
                });
        });

        it('Filter: state', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?state=" + expected_state)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].state.should.be.equal(expected_state);
                    done();
                });
        });

        it('Filter: mtu', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?mtu=" + expected_mtu)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].mtu.should.be.equal(expected_mtu);
                    done();
                });
        });

        it('Filter: tx_packets', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?tx_packets=" + expected_tx_packets)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].tx.packets.should.be.equal(expected_tx_packets);
                    done();
                });
        });

        it('Filter: rx_packets', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?rx_packets=" + expected_rx_packets)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].rx.packets.should.be.equal(expected_rx_packets);
                    done();
                });
        });

        it('Filter: tx_bytes', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?tx_bytes=" + expected_tx_bytes)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].tx.bytes.should.be.equal(expected_tx_bytes);
                    done();
                });
        });

        it('Filter: rx_bytes', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?rx_bytes=" + expected_rx_bytes)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].rx.bytes.should.be.equal(expected_rx_bytes);
                    done();
                });
        });

        it('Filter: tx_errors', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?tx_errors=" + expected_tx_errors)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].tx.errors.should.be.equal(expected_tx_errors);
                    done();
                });
        });

        it('Filter: rx_errors', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?rx_errors=" + expected_rx_errors)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].rx.errors.should.be.equal(expected_rx_errors);
                    done();
                });
        });

        it('Filter: tx_dropped', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?tx_dropped=" + expected_tx_dropped)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].tx.dropped.should.be.equal(expected_tx_dropped);
                    done();
                });
        });

        it('Filter: rx_dropped', function (done) {
            request(common.url)
                .get("/syscollector/" + agent_id + "/netiface?rx_dropped=" + expected_rx_dropped)
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err);
                    res.body.should.have.properties(['error', 'data']);
                    res.body.data.items[0].should.have.properties(netiface_properties);
                    res.body.data.items[0].rx.dropped.should.be.equal(expected_rx_dropped);
                    done();
                });
        });


    });  // GET/syscollector/:agent_id/netiface

});  // Syscollector
