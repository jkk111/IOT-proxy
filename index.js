var sql = require("sqlite3").verbose();
var db = new sql.Database(__dirname + "/db");
var express = require("express");
var app = express();
var bodyParser = require("body-parser");
var fs = require("fs");
var request = require("request");
var crypto = require("crypto");
app.use(bodyParser.urlencoded({ extended: true }));
app.listen(8080);
var conf;
try {
  conf = require("./config.json");
} catch(e) {
  conf = {};
  conf.salt = crypto.randomBytes(128).toString("base64");
  fs.writeFileSync(__dirname + "/config.json", JSON.stringify(conf));
}

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
  db.run("CREATE TABLE IF NOT EXISTS devices (id TEXT, owner INT, request TEXT, updated INT)");
  db.run("CREATE TABLE IF NOT EXISTS tokens (id TEXT, user INT, expiry INT)");
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

function hashPass(pass) {
  console.log("beginning hash");
  pass = crypto.pbkdf2Sync(pass, conf.salt, 1000, 512, "sha512").toString("base64");
  console.log("end hash");
  return pass;
}

function addUser(user, email, pass, cb) {
  pass = hashPass(pass);
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
      db.run("UPDATE devices SET UPDATED = ? WHERE id = ?", [Date.now(), id], function() {
        res.send(result);
      })
    });
  });
});

function login(user, cb) {
  var expires = Date.now() + (60 * 60 * 1000);
  var token = crypto.randomBytes(16).toString("base64");
  db.run("INSERT INTO tokens (id, user, expiry) VALUES(?, ?, ?)",
          [user, token, expires], function(err, data) {
            if(err) return console.error(err);
            cb(token, expires);
          })
}

app.post("/login", function(req, res) {
  db.all("SELECT * FROM users WHERE user = ?", [req.body.user], function(err, data) {
    console.log("DB QUERY!", data, this);
    // check data, gen token and redirect
    if(err) return console.error(err);
    var user = data[0];
    if(!user || user.password != hashPass(req.body.pass)) {
      return res.status(401).send({ success: false })
    }
    login(user.id, function(token, expires) {
      res.cookie("auth", token, new Date(expires)).send({ success: true });
    })
  })
});

function register(user, pass, email, cb) {
  pass = hashPass(pass);
  console.log("here");
  db.run("INSERT INTO users (email, user, password) VALUES(?,?,?)",
          [email, user, pass],
          function(err, data) {
            if(err) return cb(false);
            var insertId = this.lastID;
            cb(insertId);
          })
}

app.post("/register", function(req, res) {
  // add user, then login
  if(req.body.user && req.body.pass && req.body.email) {
    register(req.body.user, req.body.pass, req.body.email, function(id) {
      if(id === false) {
        return res.send({ success: false });
      }
      login(id, function(token, expires) {
        res.cookie("auth", token, new Date(expires)).send({ success: true });
      })
    });
  } else {
    res.send("no");
  }
});

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
