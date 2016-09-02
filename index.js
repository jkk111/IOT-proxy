var sql = require("sqlite3").verbose();
var db = new sql.Database(__dirname + "/db");
var express = require("express");
var app = express();
var bodyParser = require("body-parser");
var request = require("request");
var crypto = require("crypto");
app.use(bodyParser.urlencoded({ extended: true }));
app.listen(8080);

var connections = {};

function cleanSchedule() {
  var msinhour = 1000 * 60 * 60;
  var remaining = msinhour - (Date.now() % (msinhour));
  setTimeout(function() {
    connections = {};
    process.nextTick(cleanSchedule);
  }, remaining);
}
db.serialize(function() {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, user TEXT UNIQUE, password TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS devices (id TEXT, owner INT, request TEXT)");
});

function addDevice(id, owner, payload, cb) {
  payload = JSON.stringify(payload);
  db.run("INSERT INTO devices (id, owner, request) VALUES($id, $owner, $request)", { $id: id, $owner: owner, $request: payload }, function(err) {
    if(err) {
      console.error(err);
      cb(err);
    }
    cb(true);
  })
}

function addUser(user, email, pass, cb) {
  console.log("Adding user");
  pass = crypto.pbkdf2Sync(pass, crypto.randomBytes(128), 1000, 512, "sha512");
  db.run("INSERT INTO users (user, email, password) VALUES($user, $email, $password)", { $user: user, $email: email, $password: pass }, function(err) {
    console.log(arguments);
    if(err) {
      console.error(err);
      cb(err);
    } 
    cb(this);
  })
}

app.use("/update/:id", function(req, res) {
  var id = req.params.id;
  var method = req.method;
  var data;
  if(method == "POST") {
    data = req.body;
  } else {
    data = req.query;
  }
  db.each("SELECT * FROM devices WHERE id = $id", { $id: id }, function(err, row) {
    console.log(this, arguments);
    connections[id] = (connections[id] || 0) + 1;
    row.request = JSON.parse(row.request);
    handleRequest(row, data, req.method, function(result) {
      res.send(result);
    });
  });
});

app.post("/login", function(req, res) {

})

app.get("/devices", function(req, res) {
  var id = req.cookie.id;
  if(id) {
    getDevices(id, function(result) {
      res.send(result);
    })
  } else {
    cb({ err: "NOCOOKIE" });
  }
});

function getDevices(id, cb) {
  var q = "SELECT id, request FROM devices WHERE owner = ?";
  db.all(q, [id], function(err, data) {
    if(err) cb(err);
    else cb(data);
  });
}

function extend(base, data) {
  for(var key in data) {
    base[key] = data;
  }
  return base;
}

function handleRequest(info, data, method, cb) {
  var payload = {
    url: info.request.url,
    method: info.request.method
  }
  if(method == "POST") {
    payload["form"] = extend(info.request.form || {}, data);
  } else {
    payload["qs"] = extend(info.request.form || {}, data);
  }
  request(payload, function(err, data, body) {
    cb(err || body);
  })
}
