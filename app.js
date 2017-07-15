var process = require('process');
var express = require('express');
var inspect = require('util').inspect;
var crypto = require('crypto');
var fs = require('fs');
var querystring = require('querystring');

var secrets = JSON.parse(fs.readFileSync('secrets.json', 'utf-8'));

var app = express();

app.get('/', function(req, res) {
  return res.status(200).send('this is the home page');
});

app.use('/proxy', function(req, res, next) {
  var hash, input, query, query_string, ref, ref1, ref2, signature;
  query_string = (ref = (ref1 = req.url.match(/\?(.*)/)) != null ? ref1[1] : void 0) != null ? ref : '';
  query = querystring.parse(query_string);
  signature = (ref2 = query.signature) != null ? ref2 : '';
  delete query.signature;
  input = Object.keys(query).sort().map(function(key) {
    var value;
    value = query[key];
    if (!Array.isArray(value)) {
      value = [value];
    }
    return key + "=" + (value.join(','));
  }).join('');
  hash = crypto.createHmac('sha256', secrets.shopify_shared_secret).update(input).digest('hex');
  if (signature !== hash) {
    res.status(403).send("Signature verification for shopify proxy request failed");
  } else {
    next();
  }
  return null;
});

app.get('/proxy', function(req, res) {
  return res.set('Content-Type', 'application/liquid').sendFile("proxy.liquid", {
    root: '.'
  });
});

require('http').createServer(app).listen(process.env.PORT, process.env.IP);
