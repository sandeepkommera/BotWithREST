var http = require('http');
var https = require('https');
var request = require('request');
var jwt = require('jsonwebtoken');
var config = require('./config.json');
var json_token, AuthKey, decoded, jwtHeader, alg, jwks_uri, keys ;

var myServer =  http.createServer((request, response) => {
  try{
      console.log('-- Incoming request start --');
      var { headers, method, url } = request;
        
        let body = [];

        request.on('error', (err) => {
          console.error(err);
        }).on('data', (chunk) => {
          body.push(chunk);
        }).on('end', () => {
        body = Buffer.concat(body).toString();
        var jsonbody = JSON.parse(body);
          //Autheticating the request
        jwtHeader = headers.authorization.split(" ");
        decoded = jwt.decode(jwtHeader[1],{complete: true});
        var dateNow = new Date();

        if(headers.authorization.startsWith('Bearer ') && 
        decoded.payload.iss == config.BotValidationURL && 
        decoded.payload.aud == config.MicrsoftAppID && 
        decoded.payload.serviceurl == jsonbody.serviceUrl && 
        decoded.payload.exp < dateNow.getTime())
         {
          
            ValidateJWT(body, headers, () => {
              var headertoken= AuthHeader(body, () => {
                var SendResp = SendReply(body);
                response.statusCode = 200;
                response.end();
                console.log('-- Incoming request complete --');
                });

            });
            
         }
        else
        {
         console.log('-- Rejecting request due to invalid authorizarion --');
         response.statusCode = 403;
         response.end();
        }
        });

    }
   catch (ex) {
    console.log(ex)
  }
}).listen(3978);

  var SendReply = function(body)
  {
    console.log('-- SendReply start --');
    
    var jsonbody = JSON.parse(body);
      // Reply back
       var myJSONObject = { 
        "type": "message",
    "from": {
        "id": config.MicrsoftAppID,
        "name": "SampleNodeBot"
    },
    "conversation": {
        "id": jsonbody.conversation.id,
        "name": "Test Name"
   },
   "recipient": {
        "id": jsonbody.from.id ,
        "name": jsonbody.from.name
    },
    "text": "You said: "+ jsonbody.text,
    "replyToId": jsonbody.from.id

    };
    //Reply Back to the user
    var newurl = jsonbody.serviceUrl+ "v3/conversations/"+jsonbody.conversation.id+"/activities/"+jsonbody.id; 
    var newheader = {'Authorization': 'Bearer ' + AuthKey,'Content-Type': 'application/json;'}
    newbody = myJSONObject;

    request({
        headers: newheader,
        url: newurl,
        method: "POST",
        json: true, 
        body: newbody
    }, function (error, response, body){
        if(error!=undefined)
        console.log(error);
        console.log('-- SendReply completed. --');
    });
  };


  function AuthHeader(body, callback)
  {
    console.log('-- Getting Auth bearer key --');
    // Get the authorization token
 var header = {
     'Content-Type':     'application/x-www-form-urlencoded'
 }
 
 var options = {
     url: config.AuthHeaderURL,
     method: 'POST',
     headers: header,
     form: {'grant_type': 'client_credentials', 'client_id': config.MicrsoftAppID,'client_secret': config.MicrosoftAppPassword,'scope': config.ScopeURL}
 }
 
 request(options, function (error, response, body) {
     if (!error && response.statusCode == 200) {
         // Print out the response body
         json_token = JSON.parse(body);
         AuthKey = json_token.access_token;
         console.log('-- Getting Auth bearer key completed --');
         callback(AuthKey);
     }
 })
}

  function getKeys(newurl, callback)
 {
  console.log('-- Validating JWT signature start --');
  https.get(newurl, res => {
  res.setEncoding("utf8");
  let body = "";
  res.on("data", data => {
    body += data;
  });
  res.on("end", () => {
    body = JSON.parse(body);
    //keys= body.keys;
    keys = body.keys.filter((key) => key.kid && Array.isArray(key.x5c) && key.x5c.length > 0);
    
    //const signingKey = keys.find((key) => key.endorsements === "msteams");
    const signingKey = (keys.find((key) => key.kid === decoded.header.kid)).x5c[0];
    try {
      const openSSLKey = toOpenSSL(signingKey);

      jwt.verify(jwtHeader[1],openSSLKey,
        {
          audience: decoded.aud,
          algorithms:decoded.headeralg,
          issuer:decoded.iss
        });
    } catch(err) {
      console.log('-- Invalid JWT signature --' +err);
      return;
    }
    console.log('-- Validating JWT signature completed. --');
    callback();
  });
});
}

//Get OpenID document location
 function ValidateJWT(body, headers, callback)
 {
   //var result = true;
  console.log('-- Authenticate reuqest start --');
  var url=config.OpenIdDocUrl;
  https.get(url, res => {
      res.setEncoding("utf8");
      let body = "";
      res.on("data", data => {
        body += data;
      });
      res.on("end", () => {
        body = JSON.parse(body);
        jwks_uri= body.jwks_uri;
        alg=body.id_token_signing_alg_values_supported[0];
        if(getKeys(jwks_uri, ()=>{callback()}))
        {
          callback();
        }
        console.log('-- Authenticate reuqest completed --');
      });
    });
 }

var toOpenSSL = function(key) {
  const beginCert = "-----BEGIN CERTIFICATE-----";
    const endCert = "-----END CERTIFICATE-----";

    let cert = key;
    cert = cert.replace("\n", "");
    cert = cert.replace(beginCert, "");
    cert = cert.replace(endCert, "");

    let result = beginCert;
    while (cert.length > 0) {
      if (cert.length > 64) {
        result += "\n" + cert.substring(0, 64);
        cert = cert.substring(64, cert.length);
      }
      else {
        result += "\n" + cert;
        cert = "";
      }
    }

    if (result[result.length ] !== "\n") {
      result += "\n";
    }
    result += endCert + "\n";
    return result;
}