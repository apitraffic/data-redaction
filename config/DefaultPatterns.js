const patterns = {};
const boundaryPrefix = `(^|\s)`;
const boundarySuffix = `(\s|$)`;

/*
// Address patterns
const zipPattern = `\d{5}(?:-\d{4})?`
const cityPattern = `(?:[A-Z][a-z.-]+[ ]?){0,20}`
const stateAbbrvPattern = `AL|AK|AS|AZ|AR|CA|CO|CT|DE|DC|FM|FL|GA|GU|HI|ID|IL|IN|IA|KS|KY|LA|ME|MH|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|MP|OH|OK|OR|PW|PA|PR|RI|SC|SD|TN|TX|UT|VT|VI|VA|WA|WV|WI|WY`
const cityStateZipPattern = `${cityPattern},\s*(?:${stateAbbrvPattern}),?\s*${zipPattern}`
const streetSuffixPattern = `Avenue|Lane|Road|Boulevard|Place|Drive|Street|Ave|Dr|Rd|Blvd|Ln|St|Pl`
const directionPattern = `(?:[nN](?:orth)?|[eE](?:ast)?|[sS](?:outh)?|[wW](?:est)?)\.?`
const streetPattern = `\d{1,4} [\w\s]{1,20}(?:\b${streetSuffixPattern}\b)\.?(?:[ ]${directionPattern})?`
const addressPattern = `(?:${streetPattern}\s${cityStateZipPattern})|(?:${streetPattern})|(?:${cityStateZipPattern})`
*/

// Driver License patterns
const dlPatternMap = {
  AL: String.raw`${boundaryPrefix}\d{7}${boundarySuffix}`,
  AZ: String.raw`${boundaryPrefix}[a-zA-Z][0-9]{8}${boundarySuffix}|${boundaryPrefix}[0-9]{9}${boundarySuffix}`,
  AR: String.raw`${boundaryPrefix}9[0-9]{8}${boundarySuffix}`,
  CA: String.raw`${boundaryPrefix}[a-zA-Z][0-9]{7}${boundarySuffix}`,
  CO: String.raw`${boundaryPrefix}[0-9]{2}-[0-9]{3}-[0-9]{4}${boundarySuffix}`,
  FL: String.raw`${boundaryPrefix}[a-zA-Z][0-9]{12}${boundarySuffix}|${boundaryPrefix}[a-zA-Z][0-9]{3}-[0-9]{3}-[0-9]{2}-[0-9]{3}-[0-9]${boundarySuffix}|${boundaryPrefix}[a-zA-Z]-[0-9]{3}-[0-9]{3}-[0-9]{3}-[0-9]{3}${boundarySuffix}`,
  ID: String.raw`${boundaryPrefix}[a-zA-Z]{2}[0-9]{6}[a-zA-Z]${boundarySuffix}`,
  IL: String.raw`${boundaryPrefix}[a-zA-Z][0-9]{11}${boundarySuffix}|${boundaryPrefix}[a-zA-Z][0-9]{3}-[0-9]{4}-[0-9]{4}${boundarySuffix}`,
  IN: String.raw`${boundaryPrefix}[0-9]{4}-[0-9]{2}-[0-9]{4}${boundarySuffix}`,
  IA: String.raw`${boundaryPrefix}[0-9]{3}[a-zA-Z]{2}[0-9]{4}${boundarySuffix}`,
  KS: String.raw`${boundaryPrefix}[a-zA-Z][0-9]{2}-[0-9]{2}-[0-9]{4}${boundarySuffix}`,
  KY: String.raw`${boundaryPrefix}[a-zA-Z][0-9]{2}-[0-9]{3}-[0-9]{3}${boundarySuffix}`,
  MA: String.raw`${boundaryPrefix}S[0-9]{8}${boundarySuffix}|${boundaryPrefix}SA[0-9]{7}${boundarySuffix}`,
  MI: String.raw`${boundaryPrefix}[a-zA-Z][ ][0-9]{3}[ ][0-9]{3}[ ][0-9]{3}[ ][0-9]{3}${boundarySuffix}`,
  MN: String.raw`${boundaryPrefix}[a-zA-Z][0-9]{3}-[0-9]{3}-[0-9]{3}-[0-9]{3}${boundarySuffix}`,
  MS: String.raw`${boundaryPrefix}[0-9]{3}-[0-9]{2}-[0-9]{4}${boundarySuffix}`,
  MT: String.raw`${boundaryPrefix}(?:(?:[0][1-9]|[1][0-2])[0-9]{3}(?:[1-9][0-9]{3})41(?:[0][1-9]|[1][0-9]|[2][0-9]|[3][0-1]))${boundarySuffix}`,
  NV: String.raw`${boundaryPrefix}[0-9]{10}${boundarySuffix}|${boundaryPrefix}[0-9]{12}${boundarySuffix}`,
  NH: String.raw`${boundaryPrefix}(?:[0][1-9]|[1][0-2])[a-zA-Z]{3}[0-9]{2}(?:0[1-9]|[1-2][0-9]|3[0-1])[0-9]${boundarySuffix}`,
  NJ: String.raw`${boundaryPrefix}[a-zA-Z][0-9]{4} [0-9]{5} [0-9]{5}${boundarySuffix}|${boundaryPrefix}[a-zA-Z][0-9]{14}${boundarySuffix}`,
  NY: String.raw`${boundaryPrefix}[0-9]{3} [0-9]{3} [0-9]{3}${boundarySuffix}`,
  ND: String.raw`${boundaryPrefix}[a-zA-Z]{3}-[0-9]{2}-[0-9]{4}${boundarySuffix}|${boundaryPrefix}[a-zA-Z][0-9]{9}${boundarySuffix}`,
  OH: String.raw`${boundaryPrefix}[a-zA-Z]{2}[0-9]{6}${boundarySuffix}`,
  PA: String.raw`${boundaryPrefix}[0-9]{2} [0-9]{3} [0-9]{3}${boundarySuffix}`,
  RI: String.raw`${boundaryPrefix}[1-9]{2}[0-9]{5}${boundarySuffix}`,
  SD: String.raw`${boundaryPrefix}[0-9]{8}${boundarySuffix}`,
  VT: String.raw`${boundaryPrefix}[0-9]{7}[a-zA-Z]${boundarySuffix}`,
  WA: String.raw`${boundaryPrefix}[a-zA-Z\*]{5}[a-zA-Z]{2}[0-9]{3}[a-zA-Z0-9]{2}${boundarySuffix}|${boundaryPrefix}WDL[a-zA-Z0-9]{9}${boundarySuffix}`,
  WV: String.raw`${boundaryPrefix}[a-zA-Z][0-9]{6}${boundarySuffix}`,
  WI: String.raw`${boundaryPrefix}[a-zA-Z][0-9]{3}-[0-9]{4}-[0-9]{4}-[0-9]{2}${boundarySuffix}|${boundaryPrefix}[a-zA-Z][0-9]{13}${boundarySuffix}`,
  WY: String.raw`${boundaryPrefix}[0-9]{6}-[0-9]{3}${boundarySuffix}`,
}
patterns.driversLicense = {name : "US Drivers License", pattern : Object.values(dlPatternMap).join("|")};

// Geographic Coordinate patterns
const geoPatterns = {
    latitudePattern : String.raw`[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)`,
    longitudePattern : String.raw`[-+]?(?:180(?:\.0+)?|(?:(?:1[0-7]\d)|(?:[1-9]?\d))(?:\.\d+)?)`,
}
const coordinatePattern = String.raw`${boundaryPrefix}${geoPatterns.latitudePattern}\s*,\s*${geoPatterns.longitudePattern}${boundarySuffix}`
patterns.geographic = {name:"Geographic Coordinates", pattern : coordinatePattern};

// Birthday patterns (min: 1900, max: 2099)
const birthdayPatterns = {
    yyyyMmDd : String.raw`${boundaryPrefix}(?:19\d{2}|20[01][0-9]|20\d{2})[-/.](?:0[1-9]|1[012])[-/.](?:0[1-9]|[12][0-9]|3[01])${boundarySuffix}`,
    mmDdYyyy : String.raw`${boundaryPrefix}(?:0[1-9]|1[012])[-/.](?:0[1-9]|[12][0-9]|3[01])[-/.](?:19\d{2}|20[01][0-9]|20\d{2})${boundarySuffix}`,
    ddMmYyyy : String.raw`${boundaryPrefix}(?:0[1-9]|[12][0-9]|3[01])[-/.](?:0[1-9]|1[012])[-/.](?:19\d{2}|20[01][0-9]|20\d{2})${boundarySuffix}`,
}
const dobPattern = String.raw`${birthdayPatterns.yyyyMmDd}|${birthdayPatterns.mmDdYyyy}|${birthdayPatterns.ddMmYyyy}`

patterns.birthday = {name:"Birthday", pattern : dobPattern};

// IP address patterns
const ipV4Pattern = String.raw`${boundaryPrefix}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)${boundarySuffix}`
patterns.ipV4 = {name:"IP4V", pattern : ipV4Pattern};


// Credit card patterns
const creditCardPatterns = {
    americanExpressPattern : String.raw`${boundaryPrefix}3[47][0-9]{13}${boundarySuffix}|${boundaryPrefix}3[47][0-9]{2}-[0-9]{6}-[0-9]{5}${boundarySuffix}|${boundaryPrefix}3[47][0-9]{2}[ ][0-9]{6}[ ][0-9]{5}${boundarySuffix}`,
    visaPattern : String.raw`${boundaryPrefix}4[0-9]{12}(?:[0-9]{3})?${boundarySuffix}|${boundaryPrefix}4[0-9]{3}-[0-9]{4}-[0-9]{4}-[0-9]{4}${boundarySuffix}|${boundaryPrefix}4[0-9]{3}[ ][0-9]{4}[ ][0-9]{4}[ ][0-9]{4}${boundarySuffix}`,
    mastercardPattern : String.raw`${boundaryPrefix}5[1-5][0-9]{14}${boundarySuffix}|${boundaryPrefix}(?:222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[0-1]\d|2720)[0-9]{12}${boundarySuffix}`,
    discoverPattern : String.raw`${boundaryPrefix}6(?:011\d{12,15}|5\d{14,17}|4[4-9]\d{13,16}|22(?:1(?:2[6-9]|[3-9]\d)|[2-8]\d{2}|9(?:[01]\d|2[0-5]))\d{10,13})${boundarySuffix}`,
    jcbPattern : String.raw`${boundaryPrefix}(?:2131|1800|35[0-9]{3})[0-9]{11}${boundarySuffix}`
};
patterns.creditCard = {name:"Credit Card", pattern : Object.values(creditCardPatterns).join("|")};

// Email patterns
const emailPattern = String.raw`${boundaryPrefix}(?:[a-z0-9!#$%&'*+/=?^_${"`"}{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_${"`"}{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])${boundarySuffix}`
patterns.email = {name:"Email", pattern : emailPattern};


// SSN patterns
const ssnPattern = String.raw`${boundaryPrefix}[0-9]{3}[- ]?[0-9]{2}[- ]?[0-9]{4}${boundarySuffix}`
patterns.ssn = {name:"Social Security Number", pattern : ssnPattern};


// Phone number patterns
const phoneNumberPattern = String.raw`${boundaryPrefix}(?:\+?1)?[-.\s]?\s?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}${boundarySuffix}`
patterns.phone = {name:"Phone Number", pattern : phoneNumberPattern};

// Vehicle identification patterns
const vinPattern = String.raw`${boundaryPrefix}[A-HJ-NPR-Z0-9]{17}${boundarySuffix}`
patterns.vin = {name:"Vehicle Identification Number", pattern : vinPattern};

// Aadhar number pattern
const aadharPatern = String.raw`${boundaryPrefix}(([0-9]{12})|([0-9]{4} [0-9]{4} [0-9]{4}))${boundarySuffix}`
patterns.aadhar = {name:"Aadhar Number", pattern : aadharPatern};

// Brazil CPF Pattern
const brazilCPFPattern = String.raw`${boundaryPrefix}([-\.\s]?(\d{3})){3}[-\.\s]?(\d{2})${boundarySuffix}`
patterns.brazilCPF = {name:"Brazil CPF Number", pattern : brazilCPFPattern};

// JWT Pattern
const jwtPattern = String.raw`${boundaryPrefix}(eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*)${boundarySuffix}`
patterns.jwt = {name:"JWT", pattern : jwtPattern};

module.exports = patterns;