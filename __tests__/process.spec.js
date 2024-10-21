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

        const result = redact.process(rules, httpData, {replaceWith: "***REDACTED***"})
        
        expect(result).toEqual(expectedMatch);
    });

});  