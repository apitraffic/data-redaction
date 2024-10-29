const redact = require("../");
const data = require("./data");

describe("When processing custom value rules", () => {
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
                  "applyTo": "value",
                  "pattern": "tok_full_[a-zA-Z0-9]*",
                  "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
                },
                {
                  "scopes": [
                    "*"
                  ],
                  "level": "partial",
                  "type": "custom",
                  "applyTo": "value",
                  "pattern": "tok_partial_[a-zA-Z0-9]*",
                  "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
                },
                {
                  "scopes": [
                    "*"
                  ],
                  "level": "mask",
                  "type": "custom",
                  "applyTo": "value",
                  "pattern": "tok_mask_[a-zA-Z0-9]*",
                  "sid": "red_2o3msqkw8wTjqwDYAOCdqX95ysZ"
                },
        ];

        // add the property to test...
        httpData.request.headers.authorization_full = "Bearer tok_full_i3din2l3923jd8dy3n4ndod03jendocd93nbdend";
        httpData.request.headers.authorization_partial = "Bearer tok_partial_i3din2l3923jd8dy3n4ndod03jendocd93nbdend";
        httpData.request.headers.authorization_mask = "Bearer tok_mask_i3din2l3923jd8dy3n4ndod03jendocd93nbdend";
        
        
        // clone the object then insert what we expect to come back..
        const expectedMatch = data.clone(httpData);
          expectedMatch.request.headers.authorization_full = `Bearer ${fullRedactionReplacement}`;
          expectedMatch.request.headers.authorization_partial = "Bearer Bea...end";
          const mask = "*".repeat(httpData.request.headers.authorization_mask.length);
          expectedMatch.request.headers.authorization_mask = `Bearer ${mask}`;
                          
        const result = redact.process(rules, httpData, {replaceWith: fullRedactionReplacement})
        
        expect(result).toEqual(expectedMatch);
    });

});  