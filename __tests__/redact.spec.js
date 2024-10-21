const redact = require("../");
const data = require("./data");

describe("Redaction Process", () => {
    describe("when testing the built-in patterns", () => {
        test("should successfully mask phone.", async ()=> {
            const httpData = data.default.get();

            const rule = {
                "scopes": [
                    "*"
                ],
                "level": "mask",
                "type": "phone"
            }

            // add the property to test...
            httpData.request.headers.phone = "205-396-4533";

            // clone the object then insert what we expect to come back..
            const expectedMatch = data.clone(httpData);
                expectedMatch.request.headers.phone = "************"

            const result = redact.processRule(rule,httpData)
            
            expect(result).toEqual(expectedMatch);
        });

        test("should successfully mask birthday.", async ()=> {
            const httpData = data.default.get();

            const rule = {
                "scopes": [
                    "*"
                ],
                "level": "mask",
                "type": "birthday"
            }

            // add the property to test...
            httpData.request.headers.birthday = "2024-01-01";

            // clone the object then insert what we expect to come back..
            const expectedMatch = data.clone(httpData);
                expectedMatch.request.headers.birthday = "**********"

            const result = redact.processRule(rule, httpData)
            
            expect(result).toEqual(expectedMatch);
        });

        test("should successfully mask ipV4.", async ()=> {
            const httpData = data.default.get();

            const rule = {
                "scopes": [
                    "*"
                ],
                "level": "mask",
                "type": "ipV4"
            }

            // add the property to test...
            httpData.request.headers.ip = "127.0.0.1";

            // clone the object then insert what we expect to come back..
            const expectedMatch = data.clone(httpData);
                expectedMatch.request.headers.ip = "*********"

            const result = redact.processRule(rule, httpData)
            
            expect(result).toEqual(expectedMatch);
        });

        test("should successfully mask credit card.", async ()=> {
            const httpData = data.default.get();

            const rule = {
                "scopes": [
                    "*"
                ],
                "level": "mask",
                "type": "creditCard"
            }

            // add the property to test...
            httpData.request.headers.creditCard = "4111-1111-1111-1111";

            // clone the object then insert what we expect to come back..
            const expectedMatch = data.clone(httpData);
                expectedMatch.request.headers.creditCard = "*******************"

            const result = redact.processRule(rule, httpData)
            
            expect(result).toEqual(expectedMatch);
        });

        test("should successfully mask email address.", async ()=> {
            const httpData = data.default.get();

            const rule = {
                "scopes": [
                    "*"
                ],
                "level": "mask",
                "type": "email"
            }

            // add the property to test...
            httpData.request.headers.email = "name@domain.com";

            // clone the object then insert what we expect to come back..
            const expectedMatch = data.clone(httpData);
                expectedMatch.request.headers.email = "***************"

            const result = redact.processRule(rule, httpData)
            
            expect(result).toEqual(expectedMatch);
        });

        test("should successfully mask social security number.", async ()=> {
            const httpData = data.default.get();

            const rule = {
                "scopes": [
                    "*"
                ],
                "level": "mask",
                "type": "ssn"
            }

            // add the property to test...
            httpData.request.headers.ssn = "123-45-6789";

            // clone the object then insert what we expect to come back..
            const expectedMatch = data.clone(httpData);
                expectedMatch.request.headers.ssn = "***********"

            const result = redact.processRule(rule, httpData)
            
            expect(result).toEqual(expectedMatch);
        });

        test("should successfully mask a VIN.", async ()=> {
            const httpData = data.default.get();

            const rule = {
                "scopes": [
                    "*"
                ],
                "level": "mask",
                "type": "vin"
            }

            // add the property to test...
            httpData.request.headers.vin = "JH4TB2H26CC000000";

            // clone the object then insert what we expect to come back..
            const expectedMatch = data.clone(httpData);
                expectedMatch.request.headers.vin = "*".repeat(httpData.request.headers.vin.length)

            const result = redact.processRule(rule, httpData)
            
            expect(result).toEqual(expectedMatch);
        });

        test("should successfully mask a JWT.", async ()=> {
            const httpData = data.default.get();

            const rule = {
                "scopes": [
                    "*"
                ],
                "level": "mask",
                "type": "jwt"
            }

            // add the property to test...
            httpData.request.headers.jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

            // clone the object then insert what we expect to come back..
            const expectedMatch = data.clone(httpData);
                expectedMatch.request.headers.jwt = "*".repeat(httpData.request.headers.jwt.length)

            const result = redact.processRule(rule, httpData)
            
            expect(result).toEqual(expectedMatch);
        });

    });  
});