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

var should = require('should')
var assert = require('assert')
var request = require('supertest')
var common = require('./common.js')


process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

describe('Vulndetector', function () {

    vuln_fields = ['cveid', 'os', 'package', 'pending', 'operation', 'operation_value', 'check_vars']
    expected_total_items_vuln = 0

    describe('GET/vulndetector', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/vulndetector?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])
                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_fields)

                    expected_total_items_vuln = res.body.data.totalItems

                    done()
                })
        })

        it('Selector', function (done) {
            request(common.url)
                .get("/vulndetector?select=cveid,os")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])
                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(['cveid', 'os'])
                    res.body.data.totalItems.should.be.equal(expected_total_items_vuln)

                    expected_total_items = res.body.data.totalItems

                    done()
                })
        })

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/vulndetector?select=wrongParam")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'message'])
                    res.body.error.should.equal(1724)

                    done()
                })
        })

        it('Pagination', function (done) {
            request(common.url)
                .get("/vulndetector?offset=2&limit=3")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_fields)

                    done()
                })
        })

        it('Sort -', function (done) {
            request(common.url)
                .get("/vulndetector?sort=-cveid")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_fields)

                    done()
                })
        })

        it('Sort +', function (done) {
            request(common.url)
                .get("/vulndetector?sort=+cveid")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_fields)

                    done()
                })
        })

        it('Wrong sort', function (done) {
            request(common.url)
                .get("/vulndetector?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'message'])
                    res.body.error.should.equal(1403)

                    done()
                })
        })

        it('Search', function (done) {
            request(common.url)
                .get("/vulndetector?search=bionic&limit=3")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_fields)

                    done()
                })
        })

        it('Query 1', function (done) {
            request(common.url)
                .get("/vulndetector?q=os=rhel7&limit=3")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_fields)

                    done()
                })
        })

        it('Query 2', function (done) {
            request(common.url)
                .get("/vulndetector?q=os=stretch;cveid~cve-2019&limit=2")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_fields)

                    done()
                })
        })

        it('Query 3', function (done) {
            request(common.url)
                .get("/vulndetector?q=package~python;os~rhel&limit=4")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_fields)

                    done()
                })
        })

    })  // GET/syscollector/:agent_id/os

    vuln_info_fields = ['id', 'severity', 'reference', 'published', 'rationale', 'os']
    expected_total_items_vuln_info = 0

    describe('GET/vulndetector/info', function () {

        it('Request', function (done) {
            request(common.url)
                .get("/vulndetector/info?limit=1")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])
                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_info_fields)

                    expected_total_items_vuln_info = res.body.data.totalItems

                    done()
                })
        })

        it('Selector', function (done) {
            request(common.url)
                .get("/vulndetector/info?select=id,os")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])
                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(['id', 'os'])
                    res.body.data.totalItems.should.be.equal(expected_total_items_vuln_info)

                    expected_total_items_vuln_info = res.body.data.totalItems

                    done()
                })
        })

        it('Not allowed selector', function (done) {
            request(common.url)
                .get("/vulndetector/info?select=wrongParam")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'message'])
                    res.body.error.should.equal(1724)

                    done()
                })
        })

        it('Pagination', function (done) {
            request(common.url)
                .get("/vulndetector/info?offset=2&limit=3")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_info_fields)

                    done()
                })
        })

        it('Sort -', function (done) {
            request(common.url)
                .get("/vulndetector/info?sort=-id")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_info_fields)

                    done()
                })
        })

        it('Sort +', function (done) {
            request(common.url)
                .get("/vulndetector/info?sort=+id")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_info_fields)

                    done()
                })
        })

        it('Wrong sort', function (done) {
            request(common.url)
                .get("/vulndetector/info?sort=-wrongParameter")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'message'])
                    res.body.error.should.equal(1403)

                    done()
                })
        })

        it('Search', function (done) {
            request(common.url)
                .get("/vulndetector/info?search=redhat&limit=3")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_info_fields)

                    done()
                })
        })

        it('Query 1', function (done) {
            request(common.url)
                .get("/vulndetector/info?q=os=redhat&limit=3")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_info_fields)

                    done()
                })
        })

        it('Query 2', function (done) {
            request(common.url)
                .get("/vulndetector/info?q=os=bionic;id~cve-2019&limit=2")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_info_fields)

                    done()
                })
        })

        it('Query 3', function (done) {
            request(common.url)
                .get("/vulndetector/info?q=severity=low,severity=medium&limit=4")
                .auth(common.credentials.user, common.credentials.password)
                .expect("Content-type", /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) return done(err)

                    res.body.should.have.properties(['error', 'data'])

                    res.body.error.should.equal(0)
                    res.body.data.should.have.properties(['items', 'totalItems'])
                    res.body.data.items[0].should.have.properties(vuln_info_fields)

                    done()
                })
        })

    })  // GET/syscollector/:agent_id/os

})  // Vulndetector
