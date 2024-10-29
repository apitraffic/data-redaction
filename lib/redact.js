const defaultPatterns = require("../config/DefaultPatterns")
const {DeepRedact} = require('@hackylabs/deep-redact');

const scopeMappings = {
  "*" : ["request.headers","request.body","request.queryString","response.headers","response.body"],
  "request" : ["request.headers","request.body","request.queryString"],
  "request.header" : ["request.headers"],
  "request.body" : ["request.body"],
  "request.query" : ["request.queryString"],
  "response" : ["response.headers","response.body"],
  "response.header" : ["response.headers"],
  "response.body" : ["response.body"]
}  

/**
 * Returns all the buckets for an account.
 *
 * @method process
 * @param {Array} rules The accountSid for which to return buckets for.
 * @param {ApiTrafficPayload} request The accountSid for which to return buckets for.
 * @return {ApiTrafficPayload} null,{validated:true,token:decode}
 */
const process = function(rules, request, options) {
  // ensure rules is an array...
  if(rules && Array.isArray(rules)){
    // loop all the rules and process each...
    rules.forEach(((rule) => {
      // the result of each process rule is the request payload, so reset it so it will be used in the next loop...
      request = processRule(rule, request, options);
    }));
  }
  return request;
};

/**
 * Returns all the buckets for an account.
 *
 * @method processRule
 * @param {RedactionRule} rule The one specific fule that needs to be applied to the request.
 * @param {ApiTrafficPayload} request The full HTTP request that needs to be redacted.
 * @param {Object} options The full HTTP request that needs to be redacted.
 * @return {ApiTrafficPayload} null,{validated:true,token:decode}
 */
const processRule = function(rule, data, options) {
  // ensure scopes is present and it is an array...
  if(rule.scopes && Array.isArray(rule.scopes)){
    // loop all the scopes in the rule...
    rule.scopes.forEach(function(scope) {
      // ensure that is a valid scope to avoid any errors...
      if(scopeMappings[scope]){
        // loop all the items to be checked for this scope...
        scopeMappings[scope].forEach(function(scopePart) {
          // All parts are split with a period, so grab the second part which is the area to redact...
          const parts = scopePart.split('.');
          if(parts.length === 2){
            const partData = parts[0];
            const requestPart = parts[1];
            if(redactPart[requestPart] && data[partData] && data[partData][requestPart]){
              //console.log(`${partData}:${requestPart}`);
              const redacted = redactPart[requestPart](rule, data[partData][requestPart], options);
              data[partData][requestPart] = redacted;
            }
          }        
        });
      }
    });
  }
  return data;
};

const redactPart = {
  headers : function(rule, data, options={}){
    options.isJson = true;
    const redact = getRedactor("header", rule, options);   
    const redacted = redact.redact(data);
    return redacted;
  },
  body : function(rule, data, options={}){
    options.isJson = true;
    // figure out if the value is a string or an object...
    const body = getBody(data);

    options.isJson = body.isJson;
    
    const redact = getRedactor("body", rule, options);

    let redacted = redact.redact(body.data);

    // since we inflated the body, we need to convert it back to a string...
    if(body.inflated){
      redacted = JSON.stringify(redacted);
    }

    return redacted;
  },
  queryString : function(rule, data, options={}){
    options.isJson = true;
    const redact = getRedactor("query", rule, options);
    const redacted = redact.redact(data);
    return redacted;
  }
};

const maskString = function(input) {
  return '*'.repeat(input.length);
}

const getBody = function(body) {
  const returnObj = {isJson: false, inflated: false, body: null};
  
  if(typeof body === 'object'){
    returnObj.isJson = true;
    returnObj.inflated = false;
    returnObj.data = body;
  }else{
    // it is not already an object...can it be parsed into an object?
    try {
      const parsed = JSON.parse(body);
      returnObj.isJson = true;
      returnObj.inflated = true;
      returnObj.data = parsed;
    } catch (e) {
      // ok it could not be parsed into an object, so we can take as it is.
      returnObj.data = body;
    }
  }
  return returnObj;
}

const dataReplacer = function(value, pattern, level, replaceWith, xmlReplacement=false) {

  let replacementText = value;

  if(xmlReplacement){
    replacementText = [...value.matchAll(pattern)];
    if(Array.isArray(replacementText) && Array.isArray(replacementText[0])){
      replacementText = replacementText[0][2];
    }
  }    

  if(level === 'partial'){
    if(replacementText.length > 6){
      const firstThree = replacementText.substring(0, 3); // Get the first 3 characters
      const lastThree = replacementText.substring(replacementText.length - 3);
      replaceWith = `${firstThree}...${lastThree}`;
    }else if(replacementText.length > 2){
      const firstOne = replacementText.substring(0, 1); // Get the first character
      const lastOne = replacementText.substring(replacementText.length - 1);
      replaceWith = `${firstOne}...${lastOne}`;
    }else{
      replaceWith = maskString(replacementText);
    }
  }else if(level === 'mask'){
    replaceWith = maskString(replacementText);
  }else{
    if(!replaceWith){
      replaceWith = "[REDACTED]";
    }
  }
  if(pattern && xmlReplacement){
    return value.replace(pattern, `<$1>${replaceWith}</$1>`);
  }else if(pattern){
    return value.replace(pattern, replaceWith);
  }else{
    return replaceWith;
  }
};

const getRedactor = function(scope, rule, options){
  let redact;
  const config = {};

  if(rule.type !== "custom"){
    // get the pre-defined type...
    if(defaultPatterns[rule.type]){
      config.stringTests = [
        {
          pattern : new RegExp(`${defaultPatterns[rule.type].pattern}`, "gi"), 
          replacer: (value, pattern) => dataReplacer(value, pattern, rule.level, options?.replaceWith, false)
        }
      ];
    }else{
      // Throw error since there is no type for this rule...
    }
  }else if (rule.type === "custom") {
    
      if(rule.applyTo === "key"){
        if(options.isJson){
          // apply to value...
          config.blacklistedKeys = [];
          config.blacklistedKeys.push(rule.pattern);
          config.replacement = (value, pattern) => dataReplacer(value, pattern, rule.level, options?.replaceWith, false)
        }else{
          // this is not a JSON object, so check the XML string type...
          config.stringTests = [
            {
              pattern : new RegExp(`<(${rule.pattern})>([^<]+)</${rule.pattern}>`, "gi"), 
              replacer: (value, pattern) => dataReplacer(value, pattern, rule.level, options?.replaceWith, true)
            }
          ];
        }
      }else{
        // Run against all values now...
        config.stringTests = [
          {
            pattern : new RegExp(`${rule.pattern}`, "gi"), 
            replacer: (value, pattern) => dataReplacer(value, pattern, rule.level, options?.replaceWith, false)
          }
        ];
      }    
  }
  redact = new DeepRedact(config);

  

  return redact;

}

module.exports.process = process;
module.exports.processRule = processRule;
module.exports.getBody = getBody;