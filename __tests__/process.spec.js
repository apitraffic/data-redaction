const redact = require("../");
const data = require("./data");

describe("When processing multiple rules", () => {
    test("should successfully stack rules together.", async ()=> {
        const httpData = data.default.get();

        const rules = [
            {
                "scopes": [
                    "*"
                ],
                "level": "mask",
                "type": "phone"
            },
            {
                "scopes": [
                    "*"
                ],
                "level": "full",
                "type": "ssn"
            },
            {
                "scopes": [
                    "*"
                ],
                "level": "full",
                "type": "email"
            },
            {
                "scopes": [
                    "*"
                ],
                "level": "partial",
                "type": "jwt"
            }
        ];

        // add the property to test...
        httpData.request.headers.phone = "205-396-4533";
        httpData.request.headers.ssn = "123-45-6789";
        httpData.request.headers.jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        // clone the object then insert what we expect to come back..
        const expectedMatch = data.clone(httpData);
            expectedMatch.request.headers.phone = "************"
            expectedMatch.request.headers.ssn = "***REDACTED***"
            expectedMatch.request.headers.jwt = "eyJ...w5c";
            expectedMatch.response.body = "{\"sid\":\"usr_2P0CJwkRhFlUBPG183GgJ2Xq78o\",\"phone\":\"************\",\"birthday\":\"1980-02-28\",\"firstName\":\"Pete\",\"lastName\":\"Tester\",\"email\":\"***REDACTED***\",\"timezone\":\"America/Detroit\",\"defaultAccountSid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"createdAt\":\"2023-04-27T08:35:43.705Z\",\"accounts\":[{\"sid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"name\":\"Pete Tester\",\"isPrimary\":true,\"createdAt\":\"2023-04-27T08:35:44.018Z\"}],\"chat\":{\"userHash\":\"2950e5795a1c8e7a7b74be71edce2f8cf384c6d3f7050f6db18e70dca4047a66\"}}";

        const result = redact.process(rules, httpData, {replaceWith: "***REDACTED***"})
        
        expect(result).toEqual(expectedMatch);
    });

});  