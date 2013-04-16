describe("restrictip", function() {
  var restrict = require('../lib/restrictip');
  var req, res, next;

  beforeEach(function() {
    // mock request
    req = {
      connection: { 
        remoteAddress: null
      } 
    };
    // mock response and spy on end()
    res = {
      end: function() {},
      statusCode: null
    }
    spyOn(res, 'end');
    // spy on next()
    next = jasmine.createSpy('next')
  });

  describe("whitelister with no options", function() {
    it("should allow a request from a single whitelisted IP", function() {
      req.connection.remoteAddress = '127.0.0.1';
      
      restrict('127.0.0.1').whitelist(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it("should allow all requests from multiple whitelisted IPs", function() {
      var remotes = [ '127.0.0.3', '127.0.0.2', '127.0.0.1', '127.0.0.5', '127.0.0.4' ];
      var restrictList = remotes.slice(0);

      remotes.forEach(function (item) {
        req.connection.remoteAddress = item;
        restrict(restrictList).whitelist(req, res, next);
      });

      expect(next.calls.length).toEqual(5);
    });

    it("should disallow a request from a single non-whitelisted IP", function() {
      req.connection.remoteAddress = '127.0.0.1';
      
      restrict('127.0.0.2').whitelist(req, res, next);

      expect(next.calls.length).toEqual(0);
      expect(res.statusCode).toBe(404);
      expect(res.end).toHaveBeenCalled();
    });

    it("should disallow all requests from multiple non-whitelisted IPs", function() {
      var remotes = [ '192.0.0.3', '192.0.0.2', '192.0.0.1', '192.0.0.5', '192.0.0.4' ];
      var restrictList = [ '127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.5' ];

      remotes.forEach(function (item) {
        req.connection.remoteAddress = item;
        restrict(restrictList).whitelist(req, res, next);

        expect(res.statusCode).toBe(404);
      });

      expect(res.end.calls.length).toEqual(5);
      expect(next.calls.length).toEqual(0);
    });
  });

  describe("blacklister with no options", function() {
    it("should disallow a request from a single blacklisted IP", function() {
      req.connection.remoteAddress = '127.0.0.1';
      
      restrict('127.0.0.1').blacklist(req, res, next);

      expect(next.calls.length).toEqual(0);
    });

    it("should disallow all requests from multiple non-blacklisted IPs", function() {
      var remotes = [ '192.0.0.3', '192.0.0.2', '192.0.0.1', '192.0.0.5', '192.0.0.4' ];
      var restrictList = remotes.slice(0);

      remotes.forEach(function (item) {
        req.connection.remoteAddress = item;
        restrict(restrictList).blacklist(req, res, next);

        expect(res.statusCode).toBe(404);
      });

      expect(res.end.calls.length).toEqual(5);
      expect(next.calls.length).toEqual(0);
    });

    it("should allow a request from a single non-blacklisted IP", function() {
      req.connection.remoteAddress = '127.0.0.1';
      
      restrict('127.0.0.7').blacklist(req, res, next);

      expect(next.calls.length).toEqual(1);
    });

    it("should allow all requests from multiple non-blacklisted IPs", function() {
      var remotes = [ '127.0.0.3', '127.0.0.2', '127.0.0.1', '127.0.0.5', '127.0.0.4' ];
      var restrictList = [ '127.0.1.1', '127.2.0.2', '127.0.8.3', '127.0.10.4', '127.90.0.5' ];

      remotes.forEach(function (item) {
        req.connection.remoteAddress = item;
        restrict(restrictList).blacklist(req, res, next);
      });

      expect(next.calls.length).toEqual(5);
    });

  });

  describe("whitelister chained with blacklister (both with no options)", function() {
    it("should only allow the IPs that are both whitelisted and non-blacklisted", function() {
      var remotes =  [ '127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.5' ];
      var wListIPs = [ '127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.254' ];
      var bListIPs = [ '127.0.0.1', '127.0.0.99', '127.0.0.3' ];

      var wListCount = 0, bListCount = 0;
      remotes.forEach(function (item) {
        req.connection.remoteAddress = item;
        restrict(wListIPs).whitelist(req, res, next);

        // super-unelegant way to simulate connect's handler chaining
        // TODO: fix to do something like: https://github.com/senchalabs/connect/blob/master/lib/proto.js
        if(next.wasCalled) {
          wListCount++;

          next = jasmine.createSpy('next');
          restrict(bListIPs).blacklist(req, res, next);

          if(next.wasCalled) {
            bListCount++;
          }
        }
        next = jasmine.createSpy('next');
      });

      expect(wListCount).toBe(3);
      expect(bListCount).toBe(1);
    });
  });

});
