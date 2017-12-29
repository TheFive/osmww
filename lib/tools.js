var cryptoz = require('crypto')

var pg = require('pg');


var tools = {

  isValidUser: function (user,connectStr,callback) {
    pg.connect(connectStr, function(err, client, pgdone) {
      if (err)  {
        pgdone();
        callback(err);
        return;
      }
      client.query("select data->>'email' as email,data->>'OSMUser' as osmuser from usert where data->>'OSMUser' = $1 and data->>'access' = 'full' ",[user.displayName],function(err,result){
        pgdone();
        if (err) return callback(err);
        if (result.rows.length!= 1) return callback(null,false);
        user.email = result.rows[0].email;
        return callback(null,true);
      });
    });
  },

  isAuthorized: function (email, pattern, emptyEmailMatches) {

    // specific OSMBC Code to check, wether the user is known in OSMBC


    // Special case where the email is not returned by the backend authorization system
    if (email === 'jingouser') {
      return !!emptyEmailMatches
    }

    if (!email || !email.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b/i)) {
      return false
    }

    if (!pattern || pattern.trim() === '') {
      return true
    }

    var tests = pattern.split(',').map(function (str) {
      return str.trim()
    })
    var expr
    for (var i = 0; i < tests.length; i++) {
      try {
        expr = expr || !!email.match(new RegExp('^' + tests[i] + '$', 'i'))
      } catch (e) { // Invalid regular expression
        return false
      }
    }

    return expr
  },

  hashify: function (str) {
    var shasum = cryptoz.createHash('sha1')
    shasum.update(str)
    return shasum.digest('hex')
  }
}

module.exports = tools
