const redact = require("../");
const data = require("./data");

describe("When processing custom key rules", () => {
    test("should successfully redact from the header.", async ()=> {
        const httpData = data.default.get();
        const fullRedactionReplacement = "***REDACTED***";
        const rules = [
                {
                  "scopes": [
                    "*"
                  ],
                  "level": "full",
                  "type": "custom",
                  "applyTo": "key",
                  "pattern": "full",
                  "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
                },
                {
                  "scopes": [
                    "*"
                  ],
                  "level": "partial",
                  "type": "custom",
                  "applyTo": "key",
                  "pattern": "partial",
                  "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
                },
                {
                  "scopes": [
                    "*"
                  ],
                  "level": "mask",
                  "type": "custom",
                  "applyTo": "key",
                  "pattern": "mask",
                  "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
                },
        ];

        // add the property to test...
        httpData.request.headers.full = "This is a sample string";
        httpData.request.headers.partial = "This is a sample string";
        httpData.request.headers.mask = "This is a sample string";
        
        // clone the object then insert what we expect to come back..
        const expectedMatch = data.clone(httpData);
            expectedMatch.request.headers.full = fullRedactionReplacement;
            expectedMatch.request.headers.partial = "Thi...ing";
            expectedMatch.request.headers.mask = "*".repeat(httpData.request.headers.mask.length);
            
        const result = redact.process(rules, httpData, {replaceWith: fullRedactionReplacement})
        
        expect(result).toEqual(expectedMatch);
    });

    test("should successfully redact from the query string.", async ()=> {
      const httpData = data.default.get();
      const fullRedactionReplacement = "***REDACTED***";
      const rules = [
              {
                "scopes": [
                  "*"
                ],
                "level": "full",
                "type": "custom",
                "applyTo": "key",
                "pattern": "full",
                "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
              },
              {
                "scopes": [
                  "*"
                ],
                "level": "partial",
                "type": "custom",
                "applyTo": "key",
                "pattern": "partial",
                "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
              },
              {
                "scopes": [
                  "*"
                ],
                "level": "mask",
                "type": "custom",
                "applyTo": "key",
                "pattern": "mask",
                "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
              },
      ];

      // add the property to test...
      httpData.request.queryString.full = "This is a sample string";
      httpData.request.queryString.partial = "This is a sample string";
      httpData.request.queryString.mask = "This is a sample string";
      
      // clone the object then insert what we expect to come back..
      const expectedMatch = data.clone(httpData);
          expectedMatch.request.queryString.full = fullRedactionReplacement;
          expectedMatch.request.queryString.partial = "Thi...ing";
          expectedMatch.request.queryString.mask = "*".repeat(httpData.request.queryString.mask.length);

      const result = redact.process(rules, httpData, {replaceWith: fullRedactionReplacement})
      
      expect(result).toEqual(expectedMatch);
  });

  test("should successfully redact from the body.", async ()=> {
    const httpData = data.default.get();
    const fullRedactionReplacement = "***REDACTED***";
    const rules = [
            {
              "scopes": [
                "*"
              ],
              "level": "full",
              "type": "custom",
              "applyTo": "key",
              "pattern": "full",
              "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
            },
            {
              "scopes": [
                "*"
              ],
              "level": "partial",
              "type": "custom",
              "applyTo": "key",
              "pattern": "partial",
              "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
            },
            {
              "scopes": [
                "*"
              ],
              "level": "mask",
              "type": "custom",
              "applyTo": "key",
              "pattern": "mask",
              "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
            },
    ];

    httpData.request.body = {};

    // add the property to test...
    httpData.request.body.full = "This is a sample string";
    httpData.request.body.partial = "This is a sample string";
    httpData.request.body.mask = "This is a sample string";
    
    // clone the object then insert what we expect to come back..
    const expectedMatch = data.clone(httpData);
        expectedMatch.request.body.full = fullRedactionReplacement;
        expectedMatch.request.body.partial = "Thi...ing";
        expectedMatch.request.body.mask = "*".repeat(httpData.request.body.mask.length);

    const result = redact.process(rules, httpData, {replaceWith: fullRedactionReplacement})
    
    expect(result).toEqual(expectedMatch);
  });

  test("should successfully redact from an XML string.", async ()=> {
    const httpData = data.default.get();
    const fullRedactionReplacement = "***REDACTED***";
    const rules = [
            {
              "scopes": [
                "*"
              ],
              "level": "full",
              "type": "custom",
              "applyTo": "key",
              "pattern": "full",
              "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
            },
            {
              "scopes": [
                "*"
              ],
              "level": "partial",
              "type": "custom",
              "applyTo": "key",
              "pattern": "partial",
              "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
            },
            {
              "scopes": [
                "*"
              ],
              "level": "mask",
              "type": "custom",
              "applyTo": "key",
              "pattern": "mask",
              "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
            },
    ];

    httpData.request.body = `
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
        <full>This is a sample string</full>
        <partial>This is a sample string</partial>
        <mask>This is a sample string</mask>
    </reply>
`;

    // clone the object then insert what we expect to come back..
    const expectedMatch = data.clone(httpData);

    expectedMatch.request.body = `
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
        <full>${fullRedactionReplacement}</full>
        <partial>Thi...ing</partial>
        <mask>***********************</mask>
    </reply>
`;

    const result = redact.process(rules, httpData, {replaceWith: fullRedactionReplacement})

    expect(result).toEqual(expectedMatch);
  });

});  