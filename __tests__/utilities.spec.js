const redact = require("../");
const data = require("./data");

describe("Redaction utilities functions", () => {
    describe("when testing the body checking function against JSON values.", () => {
        test("should successfully inflate a stringified json object.", async ()=> {
            const body = '{\"sid\":\"usr_2P0CJwkRhFlUBPG183GgJ2Xq78o\",\"phone\":\"555-555-1212\",\"birthday\":\"1980-02-28\",\"firstName\":\"Pete\",\"lastName\":\"Tester\",\"email\":\"pete@email.io\",\"timezone\":\"America/Detroit\",\"defaultAccountSid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"createdAt\":\"2023-04-27T08:35:43.705Z\",\"accounts\":[{\"sid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"name\":\"Pete Tester\",\"isPrimary\":true,\"createdAt\":\"2023-04-27T08:35:44.018Z\"}],\"chat\":{\"userHash\":\"2950e5795a1c8e7a7b74be71edce2f8cf384c6d3f7050f6db18e70dca4047a66\"}}';
            const inflated = JSON.parse(body);

            const result = redact.getBody(body);

            expect(result.data).toEqual(inflated);
            expect(result.isJson).toEqual(true);
            expect(result.inflated).toEqual(true);
        });

        test("should fail to inflate a stringified json object.", async ()=> {
            const body = '{\"sid\"\"usr_2P0CJwkRhFlUBPG183GgJ2Xq78o\",\"phone\":\"555-555-1212\",\"birthday\":\"1980-02-28\",\"firstName\":\"Pete\",\"lastName\":\"Tester\",\"email\":\"pete@email.io\",\"timezone\":\"America/Detroit\",\"defaultAccountSid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"createdAt\":\"2023-04-27T08:35:43.705Z\",\"accounts\":[{\"sid\":\"acc_2P0CJy3C0QyK71VwmqdsPZiMCc1\",\"name\":\"Pete Tester\",\"isPrimary\":true,\"createdAt\":\"2023-04-27T08:35:44.018Z\"}],\"chat\":{\"userHash\":\"2950e5795a1c8e7a7b74be71edce2f8cf384c6d3f7050f6db18e70dca4047a66\"}}';

            const result = redact.getBody(body)
            
            expect(result.data).toEqual(body);
            expect(result.isJson).toEqual(false);
            expect(result.inflated).toEqual(false);
        });






    });  

    describe("when testing the body checking function against XML values.", () => {
        test("should successfully inflate a stringified json object.", async ()=> {
            const body = `
                            <reply>
                                <accounts>
                                    <account>
                                        <createdAt>2023-04-27T08:35:44.018Z</createdAt>
                                        <isPrimary>true</isPrimary>
                                        <name>Pete Tester</name>
                                        <sid>acc_2P0CJy3C0QyK71VwmqdsPZiMCc1</sid>
                                    </account>
                                </accounts>
                                <birthday>1980-02-28</birthday>
                                <chat>
                                    <userHash>2950e5795a1c8e7a7b74be71edce2f8cf384c6d3f7050f6db18e70dca4047a66</userHash>
                                </chat>
                                <createdAt>2023-04-27T08:35:43.705Z</createdAt>
                                <defaultAccountSid>acc_2P0CJy3C0QyK71VwmqdsPZiMCc1</defaultAccountSid>
                                <email>pete@email.io</email>
                                <firstName>Pete</firstName>
                                <lastName>Tester</lastName>
                                <phone>555-555-1212</phone>
                                <sid>usr_2P0CJwkRhFlUBPG183GgJ2Xq78o</sid>
                                <timezone>America/Detroit</timezone>
                            </reply>
            `;

            const result = redact.getBody(body);

            expect(result.data).toEqual(body);
            expect(result.isJson).toEqual(false);
            expect(result.inflated).toEqual(false);
        });

    });
});