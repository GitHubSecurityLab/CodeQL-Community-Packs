var cp = require("child_process")

var input = process.argv[1];

cp.exec("foo")
cp.exec(input)
cp.spawn('/bin/sh', [ input ])

var exec = require('child_process').exec;

exec(input)
