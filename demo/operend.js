// from the Mocha tests for the operend server
conf=require("./config_tests");
AUTH = { "user": conf.USERNAME, "pass": conf.PASSWORD }
stream=require("stream");
util=require("util");
var request=require("request");
var fs=require("fs")

function StringReader(str)
{
    stream.Readable.call(this);
    this.content=str;
}

util.inherits(StringReader, stream.Readable);



StringReader.prototype._read = function()
{
    this.push(this.content)
    this.emit('end')
}

function fixPath(path)
{
    if(path[0]!="/")
    {
	path="/"+path
    }
    return conf.HIVE_URL+path
}

exports.conf=conf;

exports.GET = function (auth,path,cb) { bodyless("GET",path,auth,cb); }
exports.DELETE = function (auth,path,cb) { bodyless("DELETE",path,auth,cb); }

exports.PUT = function (auth,path, body, cb) {
	withbody("PUT", path, body,auth, cb); 
}

exports.bodyGET = function (auth,path,body,cb) { withbody("GET",path,body,auth,cb); }

exports.POST = function (auth,path, body, cb) { withbody("POST", path, body,auth,cb); }
exports.filePUT = function (auth,path, fname, cb) { 
    withbody("PUT", path, fs.createReadStream(fname), auth,cb);
}
exports.filePOST = function (auth,path, fname, cb) { 
    withbody("POST", path, fs.createReadStream(fname), auth, cb);
}
exports.batchDELETE = function(auth,paths, done)
{ 
    batchBodyless("DELETE", paths, done);
}
exports.batchPUT = function(auth,paths, bodies, done)
{ 
    batchBodies("PUT", paths, bodies, done);
}
exports.batchPOST = function(auth,paths, bodies, done)
{ 
    batchBodies("POST", paths, bodies, done);
}


function bodyless(method,path,auth,cb)
{
	// if no auth passed in default to AUTH
	if(auth  === undefined){
		auth = AUTH
	}
	//console.log("BODYLESS")
	//console.log({"uri":fixPath(path), "method": method, "auth":auth});
    return request({"uri":fixPath(path), "method": method, "auth":auth}, cb,function(err){
    	console.log("Unexpected error attempting HTTP operation!",err);
	console.log(fixPath(path),method,auth);
    })
}

function withbody(method, path, body,auth,cb)
{
	if(auth  === undefined){
		auth = AUTH
	}
    if(body instanceof stream.Readable)
    {
    	//console.log("WITH BODY STREAM")
    	//console.log({"uri":fixPath(path), "method": method, "auth":auth});
		req=request({"uri":fixPath(path), "method": method, "auth":auth}, cb,function(err){
			console.log(err);
		});
		body.pipe(req);
    }
    else
    {
		if(typeof(body)!="string")
	{
	    body=JSON.stringify(body);
	}
	//console.log("WITH BODY no stream")
	//console.log({"uri":fixPath(path), "body": body, "method": method, "auth":auth});
	req=request({"uri":fixPath(path), "body": body, "method": method, "auth":auth}, cb,function(err){
    	    console.log("Unexpected error attempting HTTP operation with body!",err);
	    console.log(fixPath(path),method,auth);
	    console.log(body);
	});
    }
    return req;
}

exports.batchCallback = function(callback)
{
    items=arguments;
    looper = function(i){
		if(i < items.length-1){
	    	if(items[i].length >3){
				withbody(items[i][0],
			 				items[i][1],
			 				items[i][2],
			 				items[i][3],
			 				function(e,r,b) {
			 					callback(e,r,b)
			 					looper(i+1) 
			 				}
			 			);
	    	}
	    	else {
			bodyless(items[i][0],
						items[i][1],
						items[i][2],
						function(e,r,b) {
							callback(e,r,b)
							looper(i+1) 
						}
					);
	   		}
		}
		else{
	    	items[i].call();
		}
    }
    looper(1);
}
exports.batch = function()
{
    items=arguments;
    looper = function(i){
		if(i < items.length-1){
	    	if(items[i].length > 3){
				withbody(items[i][0],
			 				items[i][1],
			 				items[i][2],
			 				items[i][3],
			 				function(e,r,b) {
			 					looper(i+1) 
			 				}
			 			);
	    	}
	    	else {
			bodyless(items[i][0],
						items[i][1],
						items[i][2],
						function(e,r,b) {
							looper(i+1) 
						}
					);
	   	}
		}
		else{
	    	items[i].call();
		}
    }
    looper(0);
}

function batchBodyless(method,paths,done)
{
    looper = function(i)
    {
	if(i<paths.length)
	{
	    bodyless(method, paths[i], function(e,r,b) { looper(i+1); });
	}
	else
	{
	    done();
	}
    }
    looper(0);
}
