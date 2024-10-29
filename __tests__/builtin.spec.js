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
            httpData.request.headers.phone = "333-555-1010";

            // clone the object then insert what we expect to come back..
            const expectedMatch = data.clone(httpData);
                expectedMatch.request.headers.phone = "************"
                expectedMatch.response.body = "{\"sid\":\"usr_2P0CJwkRhFlUBPG183GgJ2Xq78o\",\"phone\":\"************\",\"birthday\":\"1980-02-28\",\"firstName\":\"Pete\",\"lastName\":\"Tester\",\"email\":\"pete@email.io\",\"timezone\":\"America/Detroit\",\"defaultAccountSid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"createdAt\":\"2023-04-27T08:35:43.705Z\",\"accounts\":[{\"sid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"name\":\"Pete Tester\",\"isPrimary\":true,\"createdAt\":\"2023-04-27T08:35:44.018Z\"}],\"chat\":{\"userHash\":\"2950e5795a1c8e7a7b74be71edce2f8cf384c6d3f7050f6db18e70dca4047a66\"}}";

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
                expectedMatch.response.body = "{\"sid\":\"usr_2P0CJwkRhFlUBPG183GgJ2Xq78o\",\"phone\":\"555-555-1212\",\"birthday\":\"**********\",\"firstName\":\"Pete\",\"lastName\":\"Tester\",\"email\":\"pete@email.io\",\"timezone\":\"America/Detroit\",\"defaultAccountSid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"createdAt\":\"2023-04-27T08:35:43.705Z\",\"accounts\":[{\"sid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"name\":\"Pete Tester\",\"isPrimary\":true,\"createdAt\":\"2023-04-27T08:35:44.018Z\"}],\"chat\":{\"userHash\":\"2950e5795a1c8e7a7b74be71edce2f8cf384c6d3f7050f6db18e70dca4047a66\"}}";

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
                expectedMatch.response.body = "{\"sid\":\"usr_2P0CJwkRhFlUBPG183GgJ2Xq78o\",\"phone\":\"555-555-1212\",\"birthday\":\"1980-02-28\",\"firstName\":\"Pete\",\"lastName\":\"Tester\",\"email\":\"*************\",\"timezone\":\"America/Detroit\",\"defaultAccountSid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"createdAt\":\"2023-04-27T08:35:43.705Z\",\"accounts\":[{\"sid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"name\":\"Pete Tester\",\"isPrimary\":true,\"createdAt\":\"2023-04-27T08:35:44.018Z\"}],\"chat\":{\"userHash\":\"2950e5795a1c8e7a7b74be71edce2f8cf384c6d3f7050f6db18e70dca4047a66\"}}";

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