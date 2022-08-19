#!/usr/bin/env node
// Node script to populate some dummy data for playing with entityfs.
POST=require("./operend").POST;
GET=require("./operend").GET;
filePOST=require("./operend").filePOST;
batch = require("./operend").batch;

super_user = { "user": conf.USERNAME, "pass": conf.PASSWORD };

// post a file, inject its new ID into an entity, post the entity
function postEntityWithFile(entity,fileVariable,cb) {
    filePOST(super_user,"v2/WorkFiles",entity[fileVariable].slice(1),
	     function(error,response,body) {
		 var o=JSON.parse(body)
		 wfid=""+o.id;
		 entity[fileVariable]=wfid;
		 POST(super_user,"v2/Entities",entity,
		      function(error,response,body) {
			  console.log(body)
			  cb(error,response,body);
		      }
		     );
	     });
}

function step(step,cb) {
    if(step[0]=="ENTITY+FILE") {
	postEntityWithFile(step[1],step[2],cb);
    }
    else if(step[0]=="CLASS") {
	POST(super_user,"v2/EntityClasses",step[1],cb);
    }
    else if(step[0]=="RULE") {
	POST(super_user,"v2/FilePathRules",step[1],
	     function(error,response,body) {
		 console.log(body);
		 cb(error,response,body)
	     }
	    );	    
    }
}

function manysteps(steps) {
    var i=0;
    function loop() {
	step(steps[i], function() {
	    ++i;
	    if(i<steps.length) { loop(); }
	});
    }
    loop();
}

/* 
   Entities. Note that the @filename thing is something this script is
   doing itself, not an Operend or entityfs thing. When these are sent to the
   server, the @filenames have been replaced with workfile IDs.
*/
stopsign={"_entity_id":"stopsign","_class":"shape",
	  "color":"red","shape":"octagon","graphic":"@stopsign.txt"}
mars={"_entity_id":"mars","_class":"shape",
      "color":"red","shape":"sphere","graphic":"@mars.txt"}
sun={"_entity_id":"sun","_class":"shape",
     "color":"yellow","shape":"sphere","graphic":"@sun.txt"}
yieldsign={"_entity_id":"yield","_class":"shape",
	   "color":"yellow","shape":"triangle",
	   "graphic":"@yield.txt"}
shapeClass={
    "name":"shape",
    "variables":{
	"shape": { "type":"T"},
	"color": { "type":"T"},
	"graphic": { "type":"W"},
    },
    "permissions": {"group":["U","D","R"],"other":["U","D","R"]}
}
shapeFirst={
    "name":"shapeFirst",
    "class":"shape",
    "fileVariable":"graphic",
    "rule":"/shapesFirst/{shape}/{color}/the-{shape}-colored-{color}"
}
colorFirst={
    "name":"colorFirst",
    "class":"shape",
    "fileVariable":"graphic",
    "rule":"/colorsFirst/{color}/{shape}/the-{color}-{shape}"
}
flat={
    "name":"allShapes",
    "class":"shape",
    "fileVariable":"graphic",
    "rule":"/all/{_entity_id}_{color}_{shape}"
}

manysteps([
    ["CLASS",shapeClass],
    ["RULE",shapeFirst],
    ["RULE",colorFirst],
    ["RULE",flat],    
    ["ENTITY+FILE",sun,"graphic"],
    ["ENTITY+FILE",mars,"graphic"],
    ["ENTITY+FILE",yieldsign,"graphic"],
    ["ENTITY+FILE",stopsign,"graphic"],
]);
