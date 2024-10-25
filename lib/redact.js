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
    rules.forEach(function(rule) {
      // the result of each process rule is the request payload, so reset it so it will be used in the next loop...
      request = processRule(rule, request, options);
    });
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
  headers : function(rule, data, options){
    const redact = getRedactor(rule, options);   
    const redacted = redact.redact(data);
    return redacted;
  },
  body : function(rule, data, options){
    const redact = getRedactor(rule, options);
    const redacted = redact.redact(data);
    return redacted;
  },
  queryString : function(rule, data, options){
    const redact = getRedactor(rule, options);
    const redacted = redact.redact(data);
    return redacted;
  }
};

const maskString = function(input) {
  return '*'.repeat(input.length);
}

const dataReplacer = function(value, pattern, level, replaceWith) {

  if(level === 'partial'){
    if(value.length > 6){
      const firstThree = value.substring(0, 3); // Get the first 3 characters
      const lastThree = value.substring(value.length - 3);
      replaceWith = `${firstThree}...${lastThree}`;
    }else if(value.length > 2){
      const firstOne = value.substring(0, 1); // Get the first character
      const lastOne = value.substring(value.length - 1);
      replaceWith = `${firstOne}...${lastOne}`;
    }else{
      replaceWith = maskString(value);
    }
  }else if(level === 'mask'){
    replaceWith = maskString(value);
  }else{
    if(!replaceWith){
      replaceWith = "[REDACTED]";
    }
  }
  return value.replace(pattern, replaceWith);
};

const getRedactor = function(rule, options){
  
  const config = {};

  if(rule.type !== "custom"){
    // get the pre-defined type...
    if(defaultPatterns[rule.type]){
      config.stringTests = [
        {
          //pattern : new RegExp(`${defaultPatterns[rule.type].pattern}`), 
          pattern : new RegExp(`${defaultPatterns[rule.type].pattern}/gi`), 
          replacer: (value, pattern) => dataReplacer(value, pattern, rule.level, options?.replaceWith)
        }
        
      ]
    }
  }else{

  }


  const redact = new DeepRedact(config);

  return redact;

}

module.exports.process = process;
module.exports.processRule = processRule;