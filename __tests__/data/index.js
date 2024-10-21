
module.exports.clone = function(data){
    return JSON.parse(JSON.stringify(data));
}


module.exports.default = {};
module.exports.default.get = function(){

    return {
        "request": {
            "host": "api.mydomain.com",
            "method": "GET",
            "path": "/v1/authentication/me",
            "port": "443",
            "queryString": {},
            "headers": {
                "host": "api.mydomain.com",
                "connection": "keep-alive",
                "sec-ch-ua-platform": "\"macOS\"",
                "authorization": "Bearer tok_2nk7WwnTWA9vEMTrALo8RhRHZ4z2nk7WszyOUfCgphNAbb4dyKUuls",
                "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
            },
            "body": null,
            "url": "https://api.mydomain.com/v1/authentication/me",
            "contentType": null,
            "size": null
        },
        "response": {
            "statusCode": 200,
            "headers": {
                "content-type": "application/json; charset=utf-8",
                "cache-control": "no-cache",
                "content-length": 445,
                "accept-ranges": "bytes",
                "response-token": "tok_2nk7WwnTWA9vEMTrALo8RhRHZ4z2nk7WszyOUfCgphNAbb4dyKUuls",
            },
            "body": "{\"sid\":\"usr_2P0CJwkRhFlUBPG183GgJ2Xq78o\",\"phone\":\"555-555-1212\",\"birthday\":\"1980-02-28\",\"firstName\":\"Jason\",\"lastName\":\"Fill\",\"email\":\"jason@unocal.io\",\"timezone\":\"America/Detroit\",\"defaultAccountSid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"createdAt\":\"2023-04-27T08:35:43.705Z\",\"accounts\":[{\"sid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"name\":\"Jason Fill\",\"isPrimary\":true,\"createdAt\":\"2023-04-27T08:35:44.018Z\"}],\"chat\":{\"userHash\":\"2950e5795a1c8e7a7b74be71edce2f8cf384c6d3f7050f6db18e70dca4047a66\"}}"
        }
   }

}