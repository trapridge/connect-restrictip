module.exports = function (ipList, options) {

  var ip = require('ip'),
    util = require('util'),
    status = require('http-status');

  _validateIpList();
  if(options) _validateOptions();

  return {
    whitelist: function (req, res, next) {
      if(isInList(req.connection.remoteAddress)) {
          next();
      }
      else {
        _denyAccess(res, req, next);
      }
    },
    blacklist: function (res, req, next) {
      if(isInList(req.connection.remoteAddress)) {
        _denyAccess(res, req, next);
      }
      else {
          next();
      }
    }
  }

  function _validateIpList() {
    ipList = typeof ipList === 'string' ? [ipList] : ipList;
    
    var valids = [];
    if (util.isArray(ipList)) {
      ipList.forEach(function(item) {
        var valid = true;
        try {
          ip.toBuffer(item);
        }
        catch(e) {
          console.warn('IP not valid for list - IP will be ignored: ' + e.message);
          valid = false;
        }
        finally {
          if(valid) valids.push(item);
        }
      });  
    } else {
      console.warn('IP list not an array - list will be ignored: ' + e.message);
    }
    ipList = valids;
  }

  function _validateOptions() {
    if(!hasValidErrorCode() && !hasValidCallback) {
        console.warn('Invalid options. They are ignored. Given options: ' 
          + util.inspect(options));
        options = null;
    }

    function hasValidErrorCode() {
      return options.hasOwnProperty('errorCode') && (typeof options.errorCode === 'number')
        && status.hasOwnProperty(options.errorCode);
    }

    function hasValidCallback() {
      return options.hasOwnProperty('callback') && (typeof options.callback === 'function');
    }
  }

  function _isInList(remoteAddress) {
    console.log('## performing IP based filtering');
    console.log('## remote: ' + remoteAddress);
    console.log('## ipList: ' + util.inspect(ipList));

    return !!~ipList.indexOf(remoteAddress);
  }

  function _denyAccess(res, req, next) {
    if (options && options.callback) return options.callback(req, res, next);
    if (options && options.errorCode) {
      res.statusCode = options.errorCode;
    } else {
      res.statusCode = 404;
    }
    res.end();
  }

};
