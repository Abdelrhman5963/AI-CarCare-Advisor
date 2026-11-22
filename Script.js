/* AI CarCare Advisor - application logic
   SWE 401, Group 19.
   The prototype runs fully in the browser. JavaScript plays the role of the
   back end and localStorage plays the role of the database. Emails are
   delivered to a demo inbox page instead of a real mail server. */
"use strict";

/* =========================================================
   1. Helpers
   ========================================================= */

// Every element created by script must be one of the allowed tags.
var ALLOWED_TAGS = ["div", "span", "p", "b", "i", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6",
  "hr", "br", "a", "img", "center", "form", "input", "select", "option", "textarea"];

function $(id) { return document.getElementById(id); }

function el(tag, attrs, kids) {
  if (ALLOWED_TAGS.indexOf(tag) === -1) { throw new Error("Tag not allowed: " + tag); }
  var node = document.createElement(tag);
  if (attrs) {
    Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === undefined || v === null) { return; }
      if (k === "text") { node.textContent = v; }
      else if (k === "cls") { node.className = v; }
      else if (k.indexOf("on") === 0) { node.addEventListener(k.substring(2), v); }
      else if (k === "value") { node.value = v; }
      else if (k === "checked") { node.checked = !!v; }
      else { node.setAttribute(k, v); }
    });
  }
  (kids || []).forEach(function (c) {
    if (c === null || c === undefined || c === false) { return; }
    node.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  });
  return node;
}

function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }
function fill(node, kids) { clear(node); kids.forEach(function (k) { if (k) { node.appendChild(k); } }); }

function msg(id, type, text) {
  var box = $(id);
  clear(box);
  box.className = "msg";
  if (text) { box.appendChild(el("div", { cls: type, text: text })); }
}

function pad2(n) { return (n < 10 ? "0" : "") + n; }
function isoDate(d) { return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()); }
function today() { return isoDate(new Date(Date.now())); }
function parseDate(s) { var p = s.split("-"); return new Date(+p[0], +p[1] - 1, +p[2]); }
function addMonths(s, n) { var d = parseDate(s); d.setMonth(d.getMonth() + n); return isoDate(d); }
function addDays(s, n) { var d = parseDate(s); d.setDate(d.getDate() + n); return isoDate(d); }
function daysUntil(s) { return Math.round((parseDate(s) - parseDate(today())) / 86400000); }
var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function fmtDate(s) { if (!s) { return "-"; } var d = parseDate(s); return d.getDate() + " " + MONTHS[d.getMonth()] + " " + d.getFullYear(); }
function fmtStamp(ms) { var d = new Date(ms); return fmtDate(isoDate(d)) + ", " + pad2(d.getHours()) + ":" + pad2(d.getMinutes()); }
function fmtNum(n) { return Math.round(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ","); }
function fmtKm(n) { return (n === null || n === undefined || isNaN(n)) ? "-" : fmtNum(n) + " km"; }
function fmtAed(n) { return "AED " + fmtNum(n); }
function toNum(s) {
  var t = String(s === undefined || s === null ? "" : s).replace(/[,\s]/g, "").replace(/km$/i, "");
  if (t === "" || !/^\d+(\.\d+)?$/.test(t)) { return NaN; }
  return parseFloat(t);
}
function uid(prefix) { return prefix + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
function randomToken() {
  var out = "";
  if (window.crypto && window.crypto.getRandomValues) {
    var arr = new Uint8Array(16);
    window.crypto.getRandomValues(arr);
    arr.forEach(function (b) { out += ("0" + b.toString(16)).slice(-2); });
    return out;
  }
  for (var i = 0; i < 32; i++) { out += Math.floor(Math.random() * 16).toString(16); }
  return out;
}
function vehicleName(v) { return v ? (v.year + " " + v.make + " " + v.model) : "-"; }
function badge(text, cls) { return el("span", { cls: "badge " + cls, text: text }); }

/* =========================================================
   2. Password hashing (salted SHA-256, repeated)
   ========================================================= */
function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
var SHA_K = [], SHA_H0 = [];
(function () {
  var primes = [], n = 2;
  while (primes.length < 64) {
    var isPrime = true;
    for (var j = 0; j < primes.length; j++) { if (n % primes[j] === 0) { isPrime = false; break; } }
    if (isPrime) { primes.push(n); }
    n++;
  }
  function frac(x) { return ((x - Math.floor(x)) * 4294967296) >>> 0; }
  for (var i = 0; i < 64; i++) { SHA_K[i] = frac(Math.pow(primes[i], 1 / 3)); }
  for (var h = 0; h < 8; h++) { SHA_H0[h] = frac(Math.sqrt(primes[h])); }
})();

function sha256(str) {
  var bytes = new TextEncoder().encode(str);
  var len = bytes.length, total = ((len + 9 + 63) >> 6) << 6;
  var buf = new Uint8Array(total);
  buf.set(bytes);
  buf[len] = 0x80;
  var bits = len * 8, hi = Math.floor(bits / 4294967296), lo = bits >>> 0;
  buf[total - 8] = hi >>> 24; buf[total - 7] = (hi >>> 16) & 255; buf[total - 6] = (hi >>> 8) & 255; buf[total - 5] = hi & 255;
  buf[total - 4] = lo >>> 24; buf[total - 3] = (lo >>> 16) & 255; buf[total - 2] = (lo >>> 8) & 255; buf[total - 1] = lo & 255;
  var H = SHA_H0.slice(), W = new Array(64);
  for (var off = 0; off < total; off += 64) {
    for (var t = 0; t < 16; t++) {
      W[t] = ((buf[off + 4 * t] << 24) | (buf[off + 4 * t + 1] << 16) | (buf[off + 4 * t + 2] << 8) | buf[off + 4 * t + 3]) >>> 0;
    }
    for (t = 16; t < 64; t++) {
      var s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      var s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }
    var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], hh = H[7];
    for (t = 0; t < 64; t++) {
      var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      var ch = (e & f) ^ (~e & g);
      var t1 = (hh + S1 + ch + SHA_K[t] + W[t]) >>> 0;
      var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + hh) >>> 0;
  }
  return H.map(function (x) { return ("00000000" + x.toString(16)).slice(-8); }).join("");
}

function hashPassword(salt, password) {
  var h = salt + ":" + password;
  for (var i = 0; i < 300; i++) { h = sha256(h + salt); }
  return h;
}

/* =========================================================
   3. Reference data and default knowledge base
   ========================================================= */
var MAKES = {
  "Toyota": ["Camry", "Corolla", "Land Cruiser", "Prado", "RAV4", "Yaris", "Hilux"],
  "Nissan": ["Patrol", "Altima", "Sunny", "X-Trail", "Pathfinder", "Kicks"],
  "Honda": ["Accord", "Accord Coupe", "Civic", "CR-V", "Pilot", "City"],
  "Mitsubishi": ["Eclipse", "Lancer", "Pajero", "Outlander", "ASX"],
  "Hyundai": ["Elantra", "Sonata", "Tucson", "Santa Fe", "Accent"],
  "Kia": ["Cerato", "Optima", "Sportage", "Sorento", "Picanto"],
  "Lexus": ["ES", "IS", "RX", "GX", "LX"],
  "Mazda": ["Mazda3", "Mazda6", "CX-5", "CX-9"],
  "Ford": ["Explorer", "Edge", "Mustang", "F-150", "Focus"],
  "Chevrolet": ["Tahoe", "Malibu", "Camaro", "Silverado", "Captiva"],
  "Volkswagen": ["Golf", "Passat", "Tiguan", "Touareg"],
  "BMW": ["3 Series", "5 Series", "X3", "X5", "X6"],
  "Mercedes-Benz": ["C-Class", "E-Class", "S-Class", "GLE", "G-Class"],
  "Audi": ["A4", "A6", "Q5", "Q7"]
};

// Rough new-car prices in AED, used only for the used-car price guide.
var BASE_PRICE = {
  "Toyota": 115000, "Nissan": 105000, "Honda": 100000, "Mitsubishi": 85000, "Hyundai": 80000, "Kia": 78000,
  "Lexus": 210000, "Mazda": 90000, "Ford": 120000, "Chevrolet": 115000, "Volkswagen": 105000,
  "BMW": 230000, "Mercedes-Benz": 250000, "Audi": 210000, "Peugeot": 90000, "Other": 100000
};

var MODEL_TIPS = {
  "Mitsubishi": ["Many Mitsubishi engines use a timing belt. Replace it about every 100,000 km.", "Check CVT gearbox fluid on newer models."],
  "Toyota": ["Toyota hybrids need the hybrid battery cooling fan cleaned at services.", "Check the coolant every 40,000 km in hot climates."],
  "Nissan": ["CVT gearboxes on many Nissan models need fluid changes about every 60,000 km."],
  "Honda": ["Older Accords use a timing belt on V6 engines. Check the service book for the change interval."],
  "Peugeot": ["Turbo petrol engines like the 1.6 THP need regular oil changes to protect the turbo and timing chain."],
  "BMW": ["Many BMW models use condition-based servicing. Follow the in-car service display too."],
  "Mercedes-Benz": ["Follow the Service A and Service B pattern shown in the car."],
  "default": ["Hot UAE summers wear batteries and tyres faster. Check them every summer."]
};

var KNOWN_ISSUES = {
  "Nissan": ["CVT gearbox judder or slipping on some models"],
  "Mitsubishi": ["Timing belt changes are often overdue on older cars"],
  "Peugeot": ["Turbo and timing chain wear if oil changes were skipped"],
  "BMW": ["Oil leaks from the valve cover and cooling system parts"],
  "Mercedes-Benz": ["Air suspension faults on some models"],
  "Ford": ["Automatic gearbox shudder on some models"],
  "Chevrolet": ["AC condenser and cooling system wear"],
  "Hyundai": ["Some engines from 2011 to 2019 were recalled for bearing wear"],
  "Kia": ["Some engines from 2011 to 2019 were recalled for bearing wear"],
  "default": ["Check that all recalls for this model were done"]
};

function defaultKb() {
  return {
    services: [
      { id: "oil", name: "Oil change", km: 10000, months: 6, delayKm: 1000, delayDays: 30 },
      { id: "brakes", name: "Brake pads", km: 30000, months: 24, delayKm: 2000, delayDays: 30 },
      { id: "tyres", name: "Tyres (rotation and check)", km: 10000, months: 6, delayKm: 2000, delayDays: 30 },
      { id: "battery", name: "Battery", km: 0, months: 36, delayKm: 0, delayDays: 60 },
      { id: "coolant", name: "Coolant", km: 40000, months: 24, delayKm: 3000, delayDays: 60 },
      { id: "airfilter", name: "Air filter", km: 20000, months: 12, delayKm: 3000, delayDays: 60 },
      { id: "transmission", name: "Transmission service", km: 60000, months: 48, delayKm: 5000, delayDays: 90 },
      { id: "sparkplugs", name: "Spark plugs", km: 40000, months: 36, delayKm: 5000, delayDays: 90 },
      { id: "inspection", name: "General inspection", km: 15000, months: 12, delayKm: 2000, delayDays: 30 }
    ],
    lights: [
      { id: "cel", name: "Check engine", group: "check_engine", info: "The car computer found an engine or emissions fault. Often minor, but get it read soon." },
      { id: "temp", name: "Engine temperature", group: "overheating", info: "The engine is too hot. Stop somewhere safe and let it cool." },
      { id: "oilp", name: "Oil pressure (oil can)", group: "oil_pressure", info: "Oil pressure is low. Turn the engine off as soon as it is safe." },
      { id: "batt", name: "Battery / charging", group: "charging", info: "The battery is not being charged while you drive." },
      { id: "brake", name: "Brake system", group: "brake_pedal", info: "Handbrake on, low brake fluid or a brake fault." },
      { id: "abs", name: "ABS", group: "brake_pedal", info: "Anti-lock braking is off. Normal brakes still work, so drive gently." },
      { id: "tpms", name: "Tyre pressure", group: "tyres", info: "One or more tyres are low on air." },
      { id: "steer", name: "Power steering", group: "steering", info: "Steering assistance has a fault, so steering may feel heavy." },
      { id: "airbag", name: "Airbag", group: "airbag", info: "Airbag system fault. Airbags may not open in a crash." }
    ],
    symptoms: [
      {
        id: "brake_noise", name: "Brake noise", safety: true, urgency: "High",
        keywords: ["squeak", "squeal", "grind", "screech", "brak"],
        questions: [
          { q: "What does the noise sound like?", o: [["High-pitched squeal", { pads: 2, glazed: 1 }], ["Metal grinding", { pads: 3, rotors: 2 }], ["Clicking or knocking", { caliper: 1, loose: 2 }], ["Not sure", {}]] },
          { q: "When do you hear it?", o: [["Only when I press the brake", { pads: 1, glazed: 1 }], ["Even when I am not braking", { caliper: 2, loose: 1 }], ["Mostly in the morning or after rain", { dust: 3 }], ["Not sure", {}]] },
          { q: "Does the car pull to one side when you brake?", o: [["Yes", { caliper: 3 }], ["No", {}], ["Not sure", {}]] },
          { q: "How does the brake pedal feel?", o: [["Normal", {}], ["Soft or goes down further than usual", { pads: 1, caliper: 1 }], ["It vibrates or pulses", { rotors: 3 }], ["Not sure", {}]] },
          { q: "Is the brake warning light on?", o: [["Yes", { pads: 2 }], ["No", {}], ["Not sure", {}]] }
        ],
        causes: [
          { id: "pads", name: "Worn brake pads", weight: 4, service: "brakes", min: 250, max: 600, explain: "Brake pads have a small metal tab that squeals when the pads are nearly worn out. If they wear down fully, metal rubs on metal and damages the discs.", action: "Have the brake pads checked and replaced if they are thin." },
          { id: "rotors", name: "Worn or warped brake discs", weight: 2, min: 600, max: 1500, explain: "The discs that the pads squeeze can wear unevenly. This causes grinding or a pulsing pedal.", action: "Ask the mechanic to measure the discs and resurface or replace them." },
          { id: "glazed", name: "Glazed or low-quality pads", weight: 2, min: 200, max: 450, explain: "Pads that got very hot can harden and squeal even when they are not worn.", action: "Ask for the pads to be cleaned or replaced with better quality ones." },
          { id: "dust", name: "Dust, rust or moisture on the brakes", weight: 2, min: 0, max: 150, explain: "A thin layer of rust or dust after rain or a night parked can squeal for the first few stops. This is usually harmless.", action: "If the noise stops after a few brakes, mention it at your next service." },
          { id: "caliper", name: "Sticking brake caliper", weight: 1, min: 400, max: 1200, explain: "The part that squeezes the pads can stick. The brake then rubs all the time, gets hot and can pull the car to one side.", action: "Get it checked soon. A stuck caliper can overheat the brakes." },
          { id: "loose", name: "Loose brake part or shield", weight: 1, min: 100, max: 300, explain: "A loose clip or dust shield near the wheel can rattle or click.", action: "Ask a mechanic to check and tighten the brake hardware." }
        ]
      },
      {
        id: "brake_pedal", name: "Brake pedal or brake warning", safety: true, urgency: "High",
        keywords: ["pedal", "spongy", "soft brake", "brakes feel", "brake light", "brake warning", "abs", "stopping distance", "brake fluid"],
        questions: [
          { q: "How does the brake pedal feel?", o: [["Soft or spongy", { air: 3, fluid: 2 }], ["Goes almost to the floor", { fluid: 3, master: 2 }], ["It vibrates", { rotors2: 3 }], ["Feels normal", { abs: 1 }], ["Not sure", {}]] },
          { q: "Have you seen fluid near a wheel or under the car?", o: [["Yes", { fluid: 3 }], ["No", {}], ["Not sure", {}]] },
          { q: "Which light is on?", o: [["Red brake light", { fluid: 2, master: 1 }], ["ABS light", { abs: 3 }], ["Both", { fluid: 1, abs: 2 }], ["None", {}], ["Not sure", {}]] }
        ],
        causes: [
          { id: "fluid", name: "Low brake fluid or a leak", weight: 3, min: 150, max: 900, explain: "Brakes work by pushing fluid. If fluid leaks out, the pedal goes soft and the brakes can fail.", action: "Do not drive. Have the car recovered to a garage." },
          { id: "air", name: "Air in the brake lines", weight: 2, min: 150, max: 350, explain: "Air bubbles in the brake fluid squash when you press the pedal, so it feels soft.", action: "Have the brakes bled and the fluid changed." },
          { id: "master", name: "Failing brake master cylinder", weight: 1, min: 800, max: 2000, explain: "The master cylinder turns your foot pressure into fluid pressure. When its seals wear, the pedal sinks.", action: "Have the car recovered and the brake system inspected." },
          { id: "abs", name: "ABS sensor fault", weight: 2, min: 250, max: 700, explain: "A dirty or broken wheel-speed sensor turns off the anti-lock system. Normal braking still works.", action: "Get it checked soon and avoid hard braking until then." },
          { id: "rotors2", name: "Warped brake discs", weight: 2, min: 600, max: 1500, explain: "Uneven discs make the pedal and steering wheel shake when braking.", action: "Have the discs measured and replaced if needed." }
        ]
      },
      {
        id: "overheating", name: "Engine overheating", safety: true, urgency: "High",
        keywords: ["overheat", "temperature", "temp gauge", "too hot", "steam", "sweet smell", "coolant", "on h ", "hot engine"],
        questions: [
          { q: "Can you see steam or smell something sweet?", o: [["Steam", { leak: 3, pump: 1 }], ["Sweet smell", { leak: 3 }], ["Neither", { thermo: 2, fan: 1 }], ["Not sure", {}]] },
          { q: "When does it get hot?", o: [["In traffic or when parked with the AC on", { fan: 3 }], ["On the motorway", { radiator: 2, pump: 1 }], ["Soon after starting", { thermo: 3 }], ["Not sure", {}]] },
          { q: "Is the coolant tank low? (Only check when the engine is cold.)", o: [["Yes", { leak: 3 }], ["No", { thermo: 1, fan: 1 }], ["I have not checked", {}]] },
          { q: "Do you hear the radiator fan running when the engine is hot?", o: [["Yes", { thermo: 1 }], ["No", { fan: 3 }], ["Not sure", {}]] }
        ],
        causes: [
          { id: "leak", name: "Coolant leak or low coolant", weight: 3, service: "coolant", min: 150, max: 900, explain: "Coolant carries heat away from the engine. If it leaks out, the engine overheats quickly.", action: "Let the engine cool fully, then have the cooling system pressure-tested." },
          { id: "thermo", name: "Stuck thermostat", weight: 2, min: 250, max: 600, explain: "The thermostat is a valve that lets coolant flow to the radiator. If it sticks shut, the engine gets hot fast.", action: "Have the thermostat tested and replaced." },
          { id: "fan", name: "Radiator fan not working", weight: 2, min: 400, max: 1200, explain: "In slow traffic the fan pulls air through the radiator. If it stops, the engine heats up when you are not moving.", action: "Have the fan, its fuse and its relay checked." },
          { id: "pump", name: "Failing water pump", weight: 1, min: 700, max: 1800, explain: "The water pump moves coolant around the engine. A worn pump can leak or stop pumping.", action: "Have the water pump inspected." },
          { id: "radiator", name: "Blocked radiator", weight: 1, min: 500, max: 1500, explain: "Dirt or old coolant can block the radiator so it cannot release heat.", action: "Ask for a radiator flush or replacement." }
        ]
      },
      {
        id: "power_loss", name: "Loss of power", safety: true, urgency: "High",
        keywords: ["power", "sluggish", "accelerat", "hesitat", "turbo", "limp", "weak", "slow", "struggl"],
        questions: [
          { q: "Is the check engine light on?", o: [["Yes, steady", { sensor: 2, turbo: 1 }], ["Yes, flashing", { misfire: 3 }, "High"], ["No", { fuel: 1, filter: 1 }], ["Not sure", {}]] },
          { q: "Does your car have a turbo?", o: [["Yes", { turbo: 3 }], ["No", { turbo: -2, fuel: 1 }], ["Not sure", {}]] },
          { q: "When does it happen?", o: [["At high speed or going uphill", { fuel: 2, turbo: 1, cat: 1 }], ["All the time", { cat: 2, filter: 1 }], ["When the engine is cold", { sensor: 1 }], ["Not sure", {}]] },
          { q: "Do you hear a whistle or hiss when you accelerate?", o: [["Yes", { turbo: 3 }], ["No", { turbo: -1 }], ["Not sure", {}]] },
          { q: "Is there smoke from the exhaust?", o: [["Black smoke", { fuel: 1, filter: 2 }], ["Blue smoke", { turbo: 2 }], ["No smoke", {}], ["Not sure", {}]] }
        ],
        causes: [
          { id: "turbo", name: "Turbo or boost pipe fault", weight: 2, min: 1500, max: 6000, explain: "A turbo pushes extra air into the engine. If it or one of its pipes fails, the engine suddenly loses power.", action: "Stop and arrange recovery. Driving on can damage the engine." },
          { id: "fuel", name: "Fuel pump or clogged fuel filter", weight: 2, min: 300, max: 1500, explain: "If not enough fuel reaches the engine, it struggles at high speed or uphill.", action: "Have the fuel pressure tested and the filter replaced." },
          { id: "sensor", name: "Sensor fault putting the engine in limp mode", weight: 2, min: 300, max: 900, explain: "When a sensor gives bad readings, the car computer cuts power to protect the engine.", action: "Have the fault codes read with a scan tool." },
          { id: "cat", name: "Blocked catalytic converter", weight: 1, min: 1500, max: 4500, explain: "The catalytic converter cleans exhaust gas. When it blocks, the engine cannot breathe out.", action: "Ask for an exhaust back-pressure test." },
          { id: "filter", name: "Dirty air filter or airflow sensor", weight: 2, service: "airfilter", min: 80, max: 600, explain: "A dirty filter or airflow sensor means the engine gets less air than it needs.", action: "Replace the air filter and clean the airflow sensor." },
          { id: "misfire", name: "Engine misfire (spark plug or ignition coil)", weight: 1, service: "sparkplugs", min: 300, max: 900, explain: "If one cylinder stops firing, the engine shakes and loses power.", action: "Have the spark plugs and coils checked." }
        ]
      },
      {
        id: "steering", name: "Steering pull or vibration", safety: true, urgency: "High",
        keywords: ["steer", "power steering", "pull", "wobble", "shak", "vibrat", "alignment"],
        questions: [
          { q: "When does it happen?", o: [["All the time while driving", { pressure: 2, align: 2 }], ["Only when braking", { brakeissue: 3 }], ["At high speed (over 80 km/h)", { balance: 3 }], ["When turning", { suspension: 2, ps: 1 }], ["Not sure", {}]] },
          { q: "Did it start suddenly?", o: [["Yes, suddenly", { pressure: 3 }], ["No, it got worse slowly", { align: 2, suspension: 1 }], ["Not sure", {}]] },
          { q: "Have the tyres been checked recently?", o: [["Yes", { align: 1 }], ["No", { pressure: 2, balance: 1 }], ["Not sure", {}]] },
          { q: "Is the steering heavier than normal?", o: [["Yes", { ps: 3, pressure: 1 }], ["No", {}], ["Not sure", {}]] }
        ],
        causes: [
          { id: "pressure", name: "Low tyre pressure or a puncture", weight: 3, service: "tyres", min: 50, max: 250, explain: "A tyre with less air drags on one side, so the car pulls that way.", action: "Stop safely and look at the tyres. Fit the spare or call for help if one is flat." },
          { id: "align", name: "Wheel alignment out", weight: 2, min: 150, max: 300, explain: "Hitting a kerb or pothole can knock the wheels out of line.", action: "Book a wheel alignment." },
          { id: "balance", name: "Wheels out of balance", weight: 2, min: 80, max: 200, explain: "A lost wheel weight makes the steering wheel shake at higher speeds.", action: "Book a wheel balance." },
          { id: "suspension", name: "Worn suspension or steering joints", weight: 1, min: 500, max: 2000, explain: "Worn joints let the wheels move when they should not.", action: "Have the suspension and steering joints inspected." },
          { id: "ps", name: "Power steering fault", weight: 1, min: 300, max: 1500, explain: "Low power steering fluid or a pump or motor fault makes steering heavy.", action: "Check the fluid and have the system inspected." },
          { id: "brakeissue", name: "Sticking brake", weight: 1, min: 400, max: 1200, explain: "A brake that grabs on one side pulls the car when you brake.", action: "Have the brakes inspected." }
        ]
      },
      {
        id: "no_start", name: "Car will not start", safety: false, urgency: "Medium",
        keywords: ["start", "crank", "click", "dead", "battery", "turn over"],
        questions: [
          { q: "What happens when you turn the key or press start?", o: [["Nothing at all", { battery: 2, terminals: 2 }], ["A clicking sound", { battery: 3, starter: 1 }], ["The engine turns but does not run", { fuel2: 3 }], ["The dashboard lights are dim", { battery: 3 }], ["Not sure", {}]] },
          { q: "How old is the battery?", o: [["Under 2 years", { starter: 1, alternator: 1 }], ["2 to 3 years", { battery: 1 }], ["Over 3 years", { battery: 3 }], ["Not sure", {}]] },
          { q: "Did the battery light come on while driving recently?", o: [["Yes", { alternator: 3 }], ["No", {}], ["Not sure", {}]] }
        ],
        causes: [
          { id: "battery", name: "Weak or flat battery", weight: 3, service: "battery", min: 300, max: 700, explain: "Heat wears batteries out fast. A weak battery cannot turn the starter.", action: "Try a jump start, then have the battery tested." },
          { id: "terminals", name: "Loose or corroded battery terminals", weight: 1, min: 0, max: 100, explain: "White or green crust on the battery posts stops power getting through.", action: "Clean and tighten the terminals." },
          { id: "starter", name: "Starter motor fault", weight: 1, min: 600, max: 1500, explain: "The starter turns the engine. If it fails you may hear one click.", action: "Have the starter tested." },
          { id: "alternator", name: "Alternator not charging", weight: 1, min: 900, max: 2200, explain: "The alternator charges the battery while you drive. If it fails, the battery runs flat.", action: "Have the charging system tested." },
          { id: "fuel2", name: "Fuel or ignition problem", weight: 1, min: 200, max: 1000, explain: "If the engine turns but does not run, it is not getting fuel or spark.", action: "Check the fuel level, then have the fuel pump and ignition checked." }
        ]
      },
      {
        id: "check_engine", name: "Check engine light", safety: false, urgency: "Medium",
        keywords: ["check engine", "engine light", "cel", "engine warning", "emission"],
        questions: [
          { q: "Is the light steady or flashing?", o: [["Steady", {}], ["Flashing", { misfire2: 4 }, "High"], ["Not sure", {}]] },
          { q: "Did it come on just after refuelling?", o: [["Yes", { cap: 4 }], ["No", {}], ["Not sure", {}]] },
          { q: "Does the engine run rough or shake at idle?", o: [["Yes", { misfire2: 3 }], ["No", { o2: 1, evap: 1 }], ["Not sure", {}]] },
          { q: "Has fuel use gone up?", o: [["Yes", { o2: 3 }], ["No", {}], ["Not sure", {}]] }
        ],
        causes: [
          { id: "cap", name: "Loose fuel cap", weight: 2, min: 0, max: 50, explain: "A loose cap lets fuel vapour escape and the computer reports a leak.", action: "Tighten the cap until it clicks. The light may take a few days to go off." },
          { id: "o2", name: "Faulty oxygen sensor", weight: 3, min: 300, max: 800, explain: "This sensor measures exhaust gas so the engine can mix fuel correctly. A bad one wastes fuel but is rarely an emergency.", action: "Have the fault code read and the sensor replaced." },
          { id: "misfire2", name: "Misfire (spark plug or ignition coil)", weight: 2, service: "sparkplugs", min: 300, max: 900, explain: "A cylinder that does not fire makes the engine shake and can damage the catalytic converter.", action: "Have the plugs and coils checked." },
          { id: "cat2", name: "Catalytic converter wearing out", weight: 1, min: 1500, max: 4500, explain: "An old converter stops cleaning exhaust gas properly.", action: "Have the converter tested." },
          { id: "evap", name: "Small leak in the fuel vapour system", weight: 1, min: 200, max: 600, explain: "A cracked hose in the vapour system turns on the light but does not affect driving.", action: "Ask for a smoke test to find the leak." }
        ]
      },
      {
        id: "tyres", name: "Tyre pressure warning", safety: false, urgency: "Medium",
        keywords: ["tyre pressure", "tire pressure", "tpms", "flat", "low tyre", "low tire", "puncture"],
        questions: [
          { q: "Does one tyre look lower than the others?", o: [["Yes", { puncture: 3 }], ["No", { temp: 2, tsensor: 1 }], ["Not sure", {}]] },
          { q: "Did the light come on after a cool night or a big temperature change?", o: [["Yes", { temp: 3 }], ["No", {}], ["Not sure", {}]] },
          { q: "Did you inflate the tyres and the light stayed on?", o: [["Yes", { tsensor: 3 }], ["No", {}], ["Not sure", {}]] }
        ],
        causes: [
          { id: "puncture", name: "Slow puncture", weight: 2, service: "tyres", min: 50, max: 150, explain: "A nail or screw can let air out slowly over days.", action: "Drive slowly to a petrol station or tyre shop and have the tyre repaired." },
          { id: "temp", name: "Pressure drop from temperature change", weight: 2, min: 0, max: 20, explain: "Air shrinks when it cools, so pressures drop after a cool night.", action: "Inflate all tyres to the pressure on the driver door sticker. No recovery truck needed." },
          { id: "tsensor", name: "Faulty tyre pressure sensor", weight: 1, min: 200, max: 500, explain: "Each wheel has a sensor with a battery that can run out.", action: "Have the sensors scanned at a tyre shop." }
        ]
      },
      {
        id: "oil_pressure", name: "Oil pressure warning", safety: true, urgency: "High",
        keywords: ["oil light", "oil pressure", "oil warning", "oil can", "low oil", "oil leak"],
        questions: [
          { q: "When did you last change or check the oil?", o: [["Within the last 3 months", { sensor2: 2, pump2: 1 }], ["More than 6 months ago", { lowoil: 3 }], ["Not sure", { lowoil: 1 }]] },
          { q: "Is there oil on the ground where you park?", o: [["Yes", { leak2: 3 }], ["No", {}], ["Not sure", {}]] },
          { q: "Do you hear tapping or knocking from the engine?", o: [["Yes", { pump2: 2, lowoil: 2 }], ["No", { sensor2: 1 }], ["Not sure", {}]] }
        ],
        causes: [
          { id: "lowoil", name: "Low engine oil", weight: 3, service: "oil", min: 150, max: 400, explain: "Without enough oil, metal parts rub together and the engine can be ruined within minutes.", action: "Turn the engine off. Check the dipstick when cool and top up, or call recovery." },
          { id: "leak2", name: "Oil leak", weight: 1, min: 200, max: 1200, explain: "A worn seal or gasket lets oil drip out.", action: "Have the leak found and fixed." },
          { id: "pump2", name: "Oil pump fault", weight: 1, min: 1000, max: 3000, explain: "The pump pushes oil around the engine. If it fails, pressure drops even with a full tank.", action: "Do not drive. Have the car recovered." },
          { id: "sensor2", name: "Faulty oil pressure sensor", weight: 1, min: 150, max: 400, explain: "Sometimes the sensor is wrong, but this must be confirmed with a gauge before driving.", action: "Have the oil pressure measured by a mechanic." }
        ]
      },
      {
        id: "charging", name: "Battery or charging warning", safety: false, urgency: "Medium",
        keywords: ["battery light", "charging", "alternator", "dim lights", "electrical"],
        questions: [
          { q: "Do the headlights or dashboard dim while driving?", o: [["Yes", { alt: 3 }], ["No", { belt: 1, wiring: 1 }], ["Not sure", {}]] },
          { q: "Do you hear a squeal from the engine belt?", o: [["Yes", { belt: 3 }], ["No", {}], ["Not sure", {}]] }
        ],
        causes: [
          { id: "alt", name: "Alternator failing", weight: 3, min: 900, max: 2200, explain: "The alternator charges the battery. When it fails, the car runs on battery power until it goes flat.", action: "Drive straight to a garage with the AC and radio off." },
          { id: "belt", name: "Loose or worn drive belt", weight: 2, min: 150, max: 400, explain: "The belt turns the alternator. A slipping belt squeals and stops charging.", action: "Have the belt and tensioner replaced." },
          { id: "wiring", name: "Loose battery cable", weight: 1, min: 0, max: 150, explain: "A loose cable can stop charging current reaching the battery.", action: "Have the cables checked and tightened." }
        ]
      },
      {
        id: "ac", name: "Air conditioning not cooling", safety: false, urgency: "Low",
        keywords: ["ac", "a/c", "air con", "aircon", "air conditioning", "not cold", "warm air"],
        questions: [
          { q: "What is the air like?", o: [["Warm all the time", { gas: 3, compressor: 1 }], ["Cool at speed, warm in traffic", { condfan: 3 }], ["Cold but very weak airflow", { cabin: 3 }], ["Not sure", {}]] },
          { q: "Do you hear a click from the engine when you turn the AC on?", o: [["Yes", { gas: 1 }], ["No", { compressor: 3 }], ["Not sure", {}]] }
        ],
        causes: [
          { id: "gas", name: "Low AC gas (refrigerant)", weight: 3, min: 150, max: 400, explain: "AC gas slowly leaks over time and the air gets warmer.", action: "Book an AC re-gas and leak test." },
          { id: "compressor", name: "AC compressor fault", weight: 1, min: 1200, max: 3500, explain: "The compressor pumps the gas. If its clutch does not engage, no cooling happens.", action: "Have the compressor and its clutch tested." },
          { id: "condfan", name: "Condenser fan fault", weight: 1, min: 400, max: 1000, explain: "In traffic the fan cools the AC gas. Without it the air turns warm when you stop.", action: "Have the condenser fan checked." },
          { id: "cabin", name: "Blocked cabin filter", weight: 1, min: 50, max: 150, explain: "Dust blocks the filter and weakens airflow.", action: "Replace the cabin filter." }
        ]
      },
      {
        id: "smell_smoke", name: "Burning smell or smoke", safety: true, urgency: "High",
        keywords: ["smoke", "burning", "burnt", "smell"],
        questions: [
          { q: "Where does the smell or smoke come from?", o: [["Under the bonnet", { oilburn: 3, coolant2: 1 }], ["From a wheel", { brakehot: 3 }], ["Inside the cabin or the vents", { electric: 3 }], ["Not sure", {}]] },
          { q: "What does it smell like?", o: [["Burnt oil", { oilburn: 3 }], ["Burning plastic or rubber", { electric: 2, clutch: 1 }], ["Sweet, like syrup", { coolant2: 3 }], ["Hot brakes or carpet", { brakehot: 2, clutch: 2 }], ["Not sure", {}]] },
          { q: "Is the temperature gauge higher than normal?", o: [["Yes", { coolant2: 3 }], ["No", {}], ["Not sure", {}]] }
        ],
        causes: [
          { id: "oilburn", name: "Oil leaking onto the hot exhaust", weight: 2, min: 200, max: 1200, explain: "Oil that drips on the exhaust burns and smokes.", action: "Have the leak found and fixed before it becomes a fire risk." },
          { id: "coolant2", name: "Coolant leak and engine overheating", weight: 2, service: "coolant", min: 150, max: 900, explain: "Hot coolant smells sweet. If the gauge is high, the engine is overheating.", action: "Stop, turn off the engine and let it cool. Do not open the radiator cap." },
          { id: "electric", name: "Electrical short or overheating wire", weight: 1, min: 200, max: 1500, explain: "Burning plastic smell from the vents can mean a wire or fan motor is overheating.", action: "Turn the car off and have the wiring inspected." },
          { id: "brakehot", name: "Overheated or sticking brake", weight: 1, min: 400, max: 1200, explain: "A brake that stays on gets very hot and smells.", action: "Let it cool and have the brake inspected." },
          { id: "clutch", name: "Slipping clutch", weight: 1, min: 1500, max: 3500, explain: "A worn clutch slips and gives a burnt carpet smell.", action: "Have the clutch checked." }
        ]
      },
      {
        id: "transmission", name: "Gearbox problem", safety: false, urgency: "Medium",
        keywords: ["gearbox", "transmission", "gear", "slip", "jerk", "shift", "clutch", "cvt"],
        questions: [
          { q: "What happens?", o: [["Engine revs rise but the car does not speed up", { slip: 3 }], ["Hard or jerky gear changes", { fluidT: 2, solenoid: 2 }], ["Delay when I select Drive or Reverse", { fluidT: 3 }], ["Not sure", {}]] },
          { q: "When was the gearbox oil last changed?", o: [["Within the last 60,000 km", { solenoid: 1 }], ["Longer ago, or never", { fluidT: 3 }], ["Not sure", {}]] }
        ],
        causes: [
          { id: "fluidT", name: "Low or old transmission fluid", weight: 3, service: "transmission", min: 400, max: 900, explain: "Old fluid loses grip and causes slipping and harsh changes.", action: "Book a transmission fluid check and change." },
          { id: "slip", name: "Worn clutch or slipping gearbox", weight: 2, min: 2000, max: 6000, explain: "Worn clutch plates cannot pass engine power to the wheels.", action: "Have the gearbox diagnosed before it gets worse." },
          { id: "solenoid", name: "Gearbox control fault", weight: 1, min: 600, max: 2000, explain: "A solenoid or software fault can make changes harsh.", action: "Have the gearbox computer scanned." }
        ]
      },
      {
        id: "airbag", name: "Airbag warning", safety: false, urgency: "Medium",
        keywords: ["airbag", "srs"],
        questions: [
          { q: "Was a seat moved or something pushed under a seat recently?", o: [["Yes", { connector: 3 }], ["No", { clockspring: 1, module: 1 }], ["Not sure", {}]] }
        ],
        causes: [
          { id: "connector", name: "Loose connector under a seat", weight: 2, min: 100, max: 300, explain: "Airbag wires under the seats can come loose when seats move.", action: "Book a check soon. Airbags may not work until it is fixed." },
          { id: "clockspring", name: "Worn clock spring in the steering wheel", weight: 1, min: 400, max: 900, explain: "The clock spring connects the steering wheel airbag. It wears with use.", action: "Have it replaced by a garage." },
          { id: "module", name: "Airbag module or sensor fault", weight: 1, min: 600, max: 2000, explain: "A crash sensor or the control module may be faulty.", action: "Have the airbag system scanned." }
        ]
      }
    ]
  };
}

// NFR-07: any symptom mentioning these is always treated as safety-critical (High).
var SAFETY_WORDS = ["brak", "steer", "overheat", "temperature", "power", "smoke", "oil pressure"];

/* =========================================================
   4. Database (localStorage)
   ========================================================= */
var DB_KEY = "carcare_db_v1";
var SESSION_KEY = "carcare_session";
var memoryStore = {};

function storeGet(area, key) {
  try { return window[area].getItem(key); } catch (e) { return memoryStore[area + key] || null; }
}
function storeSet(area, key, value) {
  try { window[area].setItem(key, value); } catch (e) { memoryStore[area + key] = value; }
}
function storeRemove(area, key) {
  try { window[area].removeItem(key); } catch (e) { delete memoryStore[area + key]; }
}

var db = null;

function emptyDb() {
  return {
    users: [], vehicles: [], records: [], diagnoses: [], evaluations: [], emails: [],
    shares: [], resetTokens: [], sentReminders: {}, reviewModels: [], kb: defaultKb()
  };
}

function loadDb() {
  var raw = storeGet("localStorage", DB_KEY);
  if (raw) {
    try { db = JSON.parse(raw); } catch (e) { db = null; }
  }
  if (!db) { db = emptyDb(); }
  if (!db.kb) { db.kb = defaultKb(); }
  if (!db.users.some(function (u) { return u.role === "admin"; })) {
    var salt = randomToken();
    db.users.push({ id: "u_admin", name: "System Administrator", email: "admin@carcare.demo", salt: salt,
      passwordHash: hashPassword(salt, "Admin@2026"), role: "admin", active: true, failed: 0, lockUntil: 0, created: Date.now() });
  }
  saveDb();
}

function saveDb() { storeSet("localStorage", DB_KEY, JSON.stringify(db)); }

function currentUser() {
  var id = storeGet("sessionStorage", SESSION_KEY) || storeGet("localStorage", SESSION_KEY);
  if (!id) { return null; }
  var u = db.users.filter(function (x) { return x.id === id; })[0];
  return (u && u.active) ? u : null;
}
function setSession(id, remember) {
  storeRemove("sessionStorage", SESSION_KEY);
  storeRemove("localStorage", SESSION_KEY);
  if (id) { storeSet(remember ? "localStorage" : "sessionStorage", SESSION_KEY, id); }
}
function findUserByEmail(email) {
  var e = email.trim().toLowerCase();
  return db.users.filter(function (u) { return u.email === e; })[0];
}
function myVehicles() {
  var u = currentUser();
  return u ? db.vehicles.filter(function (v) { return v.userId === u.id; }) : [];
}
function getVehicle(id) { return db.vehicles.filter(function (v) { return v.id === id; })[0]; }
function serviceType(id) { return db.kb.services.filter(function (s) { return s.id === id; })[0]; }

// Notification service: emails land in the demo inbox.
function sendEmail(to, subject, body, link, linkText) {
  db.emails.push({ id: uid("m"), to: to, subject: subject, body: body, link: link || "", linkText: linkText || "", created: Date.now() });
  saveDb();
}

/* =========================================================
   5. Navigation
   ========================================================= */
var PUBLIC_PAGES = ["login", "register", "forgot", "reset", "inbox", "share"];
var currentPage = "login";
var previousPage = "login";

function showPage(name) {
  var user = currentUser();
  if (PUBLIC_PAGES.indexOf(name) === -1 && !user) { name = "login"; }
  if (name === "admin" && (!user || user.role !== "admin")) { name = "dashboard"; }
  if ((name === "login" || name === "register") && user) { name = "dashboard"; }
  if (name !== currentPage) {
    previousPage = currentPage;
    ["recordMsg", "vehicleMsg", "evalMsg", "causeMsg", "tsMsg", "deleteMsg", "regMsg", "forgotMsg"].forEach(function (id) { msg(id, "", ""); });
  }
  currentPage = name;
  var pages = document.querySelectorAll(".page");
  for (var i = 0; i < pages.length; i++) { pages[i].className = "page"; }
  $("page-" + name).className = "page active";
  var links = document.querySelectorAll("#nav a");
  for (var j = 0; j < links.length; j++) {
    links[j].className = links[j].getAttribute("data-page") === name ? "current" : (links[j].id === "navAdmin" && (!user || user.role !== "admin") ? "hidden" : "");
  }
  updateHeader();
  var renderers = {
    dashboard: renderDashboard, vehicles: renderVehicles, maintenance: renderMaintenance, troubleshoot: renderTroubleshoot,
    evaluate: renderEvaluate, reports: renderReports, account: renderAccount, admin: renderAdmin, inbox: renderInbox
  };
  if (renderers[name]) { renderers[name](); }
  window.scrollTo(0, 0);
}

function updateHeader() {
  var user = currentUser();
  $("nav").className = user ? "" : "hidden";
  $("whoami").textContent = user ? ("Signed in as " + user.name) : "";
}

function wireNavigation() {
  document.addEventListener("click", function (e) {
    var t = e.target;
    if (t.getAttribute && t.getAttribute("data-page")) {
      e.preventDefault();
      if (location.hash) { clearHash(); }
      showPage(t.getAttribute("data-page"));
    } else if (t.getAttribute && t.getAttribute("data-goto")) {
      showPage(t.getAttribute("data-goto"));
    }
  });
  $("logoutLink").addEventListener("click", function (e) {
    e.preventDefault();
    setSession(null);
    msg("loginMsg", "ok", "You have been logged out.");
    showPage("login");
  });
  $("inboxBack").addEventListener("click", function (e) {
    e.preventDefault();
    showPage(previousPage && previousPage !== "inbox" ? previousPage : "login");
  });
}

function clearHash() {
  try { history.replaceState(null, "", location.pathname + location.search); } catch (e) { location.hash = ""; }
}

function handleHash() {
  var h = location.hash || "";
  if (h.indexOf("#share=") === 0) { renderShare(h.substring(7)); return true; }
  if (h.indexOf("#reset=") === 0) { resetToken = h.substring(7); msg("resetMsg", "", ""); showPage("reset"); return true; }
  return false;
}

/* =========================================================
   6. Accounts (FR-1.1 to FR-1.4, NFR-2.1, NFR-2.3)
   ========================================================= */
var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function passwordProblem(pw) {
  if (pw.length < 8) { return "Password must be at least 8 characters."; }
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) { return "Password must contain at least one letter and one number."; }
  return "";
}

function onRegister(e) {
  e.preventDefault();
  var name = $("regName").value.trim(), email = $("regEmail").value.trim().toLowerCase();
  var pw = $("regPassword").value, confirm = $("regConfirm").value;
  if (name.length < 2) { return msg("regMsg", "err", "Please enter your full name."); }
  if (!EMAIL_RE.test(email)) { return msg("regMsg", "err", "Please enter a valid email address."); }
  var problem = passwordProblem(pw);
  if (problem) { return msg("regMsg", "err", problem); }
  if (pw !== confirm) { return msg("regMsg", "err", "The two passwords do not match."); }
  if (findUserByEmail(email)) { return msg("regMsg", "err", "An account with this email already exists. Log in or reset your password instead."); }
  var salt = randomToken();
  var user = { id: uid("u_"), name: name, email: email, salt: salt, passwordHash: hashPassword(salt, pw), role: "owner",
    active: true, failed: 0, lockUntil: 0, created: Date.now() };
  db.users.push(user);
  saveDb();
  $("registerForm").reset();
  msg("regMsg", "", "");
  setSession(user.id, false);
  showPage("vehicles");
  msg("vehicleMsg", "ok", "Account created. Welcome, " + name + "! Add your first vehicle to get started.");
}

function onLogin(e) {
  e.preventDefault();
  var email = $("loginEmail").value, pw = $("loginPassword").value;
  if (!email.trim() || !pw) { return msg("loginMsg", "err", "Enter your email address and password."); }
  var user = findUserByEmail(email);
  if (!user) { return msg("loginMsg", "err", "Email or password is incorrect."); }
  if (!user.active) { return msg("loginMsg", "err", "This account has been deactivated. Please contact support."); }
  var now = Date.now();
  if (user.lockUntil && user.lockUntil > now) {
    var mins = Math.ceil((user.lockUntil - now) / 60000);
    return msg("loginMsg", "err", "This account is locked after 5 failed attempts. Try again in " + mins + " minute" + (mins === 1 ? "" : "s") + ".");
  }
  if (hashPassword(user.salt, pw) === user.passwordHash) {
    user.failed = 0; user.lockUntil = 0;
    saveDb();
    setSession(user.id, $("loginRemember").checked);
    $("loginForm").reset();
    msg("loginMsg", "", "");
    runReminderCheck();
    showPage("dashboard");
    return;
  }
  user.failed = (user.failed || 0) + 1;
  if (user.failed >= 5) {
    user.failed = 0;
    user.lockUntil = now + 15 * 60000;
    saveDb();
    return msg("loginMsg", "err", "Too many failed attempts. This account is locked for 15 minutes.");
  }
  saveDb();
  var left = 5 - user.failed;
  msg("loginMsg", "err", "Email or password is incorrect. " + left + " attempt" + (left === 1 ? "" : "s") + " left before the account is locked.");
}

function onForgot(e) {
  e.preventDefault();
  var email = $("forgotEmail").value.trim().toLowerCase();
  if (!EMAIL_RE.test(email)) { return msg("forgotMsg", "err", "Please enter a valid email address."); }
  var user = findUserByEmail(email);
  if (user && user.active) {
    var tok = randomToken();
    db.resetTokens.push({ token: tok, userId: user.id, expires: Date.now() + 30 * 60000, used: false });
    saveDb();
    var link = location.href.split("#")[0] + "#reset=" + tok;
    sendEmail(user.email, "Reset your AI CarCare Advisor password",
      "Hi " + user.name + ", use the link below to choose a new password. It can be used once and expires in 30 minutes. If you did not ask for this, ignore this email.",
      link, "Reset my password");
  }
  msg("forgotMsg", "ok", "If an account exists for this email, a reset link has been sent. It works once and expires in 30 minutes.");
}

var resetToken = "";
function onReset(e) {
  e.preventDefault();
  var rec = db.resetTokens.filter(function (r) { return r.token === resetToken; })[0];
  if (!rec || rec.used) { return msg("resetMsg", "err", "This reset link is not valid or has already been used. Request a new one."); }
  if (rec.expires < Date.now()) { return msg("resetMsg", "err", "This reset link has expired. Request a new one."); }
  var pw = $("resetPassword").value, problem = passwordProblem(pw);
  if (problem) { return msg("resetMsg", "err", problem); }
  if (pw !== $("resetConfirm").value) { return msg("resetMsg", "err", "The two passwords do not match."); }
  var user = db.users.filter(function (u) { return u.id === rec.userId; })[0];
  if (!user) { return msg("resetMsg", "err", "Account not found."); }
  user.salt = randomToken();
  user.passwordHash = hashPassword(user.salt, pw);
  user.failed = 0; user.lockUntil = 0;
  rec.used = true;
  saveDb();
  $("resetForm").reset();
  clearHash();
  msg("loginMsg", "ok", "Password changed. You can log in with your new password.");
  showPage("login");
}

function deleteUserData(userId) {
  var vids = db.vehicles.filter(function (v) { return v.userId === userId; }).map(function (v) { return v.id; });
  db.vehicles = db.vehicles.filter(function (v) { return v.userId !== userId; });
  db.records = db.records.filter(function (r) { return vids.indexOf(r.vehicleId) === -1; });
  db.diagnoses = db.diagnoses.filter(function (d) { return d.userId !== userId; });
  db.evaluations = db.evaluations.filter(function (ev) { return ev.userId !== userId; });
  db.shares = db.shares.filter(function (s) { return s.userId !== userId; });
  db.resetTokens = db.resetTokens.filter(function (t) { return t.userId !== userId; });
  Object.keys(db.sentReminders).forEach(function (k) { if (vids.indexOf(k.split("|")[0]) !== -1) { delete db.sentReminders[k]; } });
  db.users = db.users.filter(function (u) { return u.id !== userId; });
  saveDb();
}

function onDelete(e) {
  e.preventDefault();
  var user = currentUser();
  if (!user) { return; }
  if (user.role === "admin") { return msg("deleteMsg", "err", "The administrator account cannot be deleted here."); }
  if (!$("delConfirm").checked) { return msg("deleteMsg", "err", "Tick the box to confirm that you want to delete everything."); }
  var email = user.email;
  deleteUserData(user.id);
  setSession(null);
  $("deleteForm").reset();
  msg("deleteMsg", "", "");
  showPage("login");
  msg("loginMsg", "ok", "The account " + email + " and all its vehicles, records and reports were deleted.");
}

function renderAccount() {
  var user = currentUser();
  var vehicles = myVehicles(), vids = vehicles.map(function (v) { return v.id; });
  var recs = db.records.filter(function (r) { return vids.indexOf(r.vehicleId) !== -1; }).length;
  var diags = db.diagnoses.filter(function (d) { return d.userId === user.id; }).length;
  var evals = db.evaluations.filter(function (x) { return x.userId === user.id; }).length;
  fill($("accountInfo"), [
    el("p", null, [el("b", { text: "Name: " }), user.name]),
    el("p", null, [el("b", { text: "Email: " }), user.email]),
    el("p", null, [el("b", { text: "Account type: " }), user.role === "admin" ? "Administrator" : "Car owner and buyer"]),
    el("p", null, [el("b", { text: "Member since: " }), fmtDate(isoDate(new Date(user.created)))]),
    el("p", null, [el("b", { text: "Stored data: " }), vehicles.length + " vehicle(s), " + recs + " maintenance record(s), " + diags + " diagnosis report(s), " + evals + " evaluation(s)"]),
    el("p", { cls: "hint", text: "Your password is stored only as a salted SHA-256 hash, never as plain text." })
  ]);
}

/* =========================================================
   7. Vehicles (FR-2.1, FR-2.2)
   ========================================================= */
var VIN_WMI = { "JT": "Toyota", "JN": "Nissan", "JHM": "Honda", "1HG": "Honda", "JA": "Mitsubishi", "KMH": "Hyundai", "KNA": "Kia",
  "JTH": "Lexus", "JM1": "Mazda", "1FA": "Ford", "1FM": "Ford", "1G1": "Chevrolet", "1GN": "Chevrolet", "WVW": "Volkswagen",
  "WVG": "Volkswagen", "WBA": "BMW", "WBS": "BMW", "WDD": "Mercedes-Benz", "WDB": "Mercedes-Benz", "WAU": "Audi", "VF3": "Peugeot" };
var VIN_YEAR = "ABCDEFGHJKLMNPRSTVWXY";

function fillMakeSelect(select, filter, includeOther) {
  clear(select);
  var f = (filter || "").toLowerCase();
  select.appendChild(el("option", { value: "", text: "Choose a make" }));
  Object.keys(MAKES).sort().forEach(function (m) {
    if (!f || m.toLowerCase().indexOf(f) !== -1) { select.appendChild(el("option", { value: m, text: m })); }
  });
  if (includeOther) {
    if (!f || "peugeot".indexOf(f) !== -1) { select.appendChild(el("option", { value: "Peugeot", text: "Peugeot" })); }
    select.appendChild(el("option", { value: "Other", text: "Other make" }));
  }
}
function fillModelSelect() {
  var sel = $("vModel"), make = $("vMake").value;
  clear(sel);
  sel.appendChild(el("option", { value: "", text: make ? "Choose a model" : "Choose a make first" }));
  (MAKES[make] || []).forEach(function (m) { sel.appendChild(el("option", { value: m, text: m })); });
}
function fillYearSelect(sel) {
  clear(sel);
  var y = new Date(Date.now()).getFullYear() + 1;
  for (var i = y; i >= 1985; i--) { sel.appendChild(el("option", { value: String(i), text: String(i) })); }
  sel.value = String(y - 1);
}
function fillVehicleSelect(sel, onChange) {
  var keep = sel.value;
  clear(sel);
  var list = myVehicles();
  if (!list.length) { sel.appendChild(el("option", { value: "", text: "No vehicles yet" })); }
  list.forEach(function (v) { sel.appendChild(el("option", { value: v.id, text: vehicleName(v) })); });
  if (selectedVehicleId && list.some(function (v) { return v.id === selectedVehicleId; })) { sel.value = selectedVehicleId; }
  else if (keep && list.some(function (v) { return v.id === keep; })) { sel.value = keep; }
  if (onChange && !sel.getAttribute("data-wired")) {
    sel.setAttribute("data-wired", "1");
    sel.addEventListener("change", function () { selectedVehicleId = sel.value; onChange(); });
  }
}
var selectedVehicleId = "";

function validVin(vin) { return /^[A-HJ-NPR-Z0-9]{17}$/.test(vin); }

function vinAutofill() {
  var vin = $("vVin").value.trim().toUpperCase();
  $("vVin").value = vin;
  if (!vin) { return; }
  if (!validVin(vin)) { return msg("vehicleMsg", "err", "A VIN has 17 letters and numbers and never uses I, O or Q."); }
  var make = VIN_WMI[vin.substring(0, 3)] || VIN_WMI[vin.substring(0, 2)];
  var yc = vin.charAt(9), year = null, idx = VIN_YEAR.indexOf(yc);
  if (idx !== -1) { year = 2010 + idx; } else if (/[1-9]/.test(yc)) { year = 2000 + parseInt(yc, 10); }
  var found = [];
  if (make && MAKES[make]) { $("vMakeSearch").value = ""; fillMakeSelect($("vMake"), "", false); $("vMake").value = make; fillModelSelect(); found.push(make); }
  else if (make) { $("vManual").checked = true; toggleManual(); $("vManualMake").value = make; found.push(make); }
  if (year && year <= new Date(Date.now()).getFullYear() + 1) { $("vYear").value = String(year); found.push(String(year)); }
  msg("vehicleMsg", found.length ? "ok" : "warn", found.length ? "Filled from VIN: " + found.join(", ") + ". Choose the model to finish." : "VIN format is valid, but the maker could not be identified. Please choose it from the list.");
}

function toggleManual() {
  var manual = $("vManual").checked;
  $("vManualRow").className = manual ? "" : "hidden";
  $("vModelRow").className = manual ? "hidden" : "";
}

function onAddVehicle(e) {
  e.preventDefault();
  var user = currentUser();
  var manual = $("vManual").checked;
  var make = manual ? $("vManualMake").value.trim() : $("vMake").value;
  var model = manual ? $("vManualModel").value.trim() : $("vModel").value;
  var year = parseInt($("vYear").value, 10);
  var mileage = toNum($("vMileage").value);
  var vin = $("vVin").value.trim().toUpperCase();
  var fuelInputs = document.getElementsByName("vFuel"), fuel = "Petrol";
  for (var i = 0; i < fuelInputs.length; i++) { if (fuelInputs[i].checked) { fuel = fuelInputs[i].value; } }
  if (!make || !model) { return msg("vehicleMsg", "err", "Please choose the make and model, or tick \"My model isn't listed\" and type them."); }
  if (isNaN(mileage) || mileage < 0 || mileage > 1500000) { return msg("vehicleMsg", "err", "Please enter the current mileage as a number of kilometres, for example 85000."); }
  if (vin && !validVin(vin)) { return msg("vehicleMsg", "err", "A VIN has 17 letters and numbers and never uses I, O or Q."); }
  var v = { id: uid("v_"), userId: user.id, make: make, model: model, year: year, vin: vin, fuel: fuel,
    mileage: Math.round(mileage), mileageUpdated: today(), addedDate: today(), addedMileage: Math.round(mileage), manual: manual, snoozes: {} };
  db.vehicles.push(v);
  if (manual) { db.reviewModels.push({ make: make, model: model, year: year, date: today() }); }
  saveDb();
  selectedVehicleId = v.id;
  $("vehicleForm").reset();
  $("vMakeSearch").value = "";
  fillMakeSelect($("vMake"), "", false); fillModelSelect(); fillYearSelect($("vYear")); toggleManual();
  msg("vehicleMsg", "ok", vehicleName(v) + " was added." + (manual ? " A general service schedule is used for now, and the model was sent to our team to add." : ""));
  renderVehicleList();
}

function updateMileage(v, input) {
  var km = toNum(input.value);
  if (isNaN(km)) { return msg("vehicleMsg", "err", "Enter the new mileage as a number."); }
  if (km < v.mileage) { return msg("vehicleMsg", "err", "The new reading (" + fmtKm(km) + ") is lower than the saved one (" + fmtKm(v.mileage) + "). Please check the odometer."); }
  v.mileage = Math.round(km);
  v.mileageUpdated = today();
  saveDb();
  runReminderCheck();
  msg("vehicleMsg", "ok", "Mileage for " + vehicleName(v) + " updated to " + fmtKm(v.mileage) + ". Service due dates were recalculated.");
  renderVehicleList();
}

function removeVehicle(v) {
  db.vehicles = db.vehicles.filter(function (x) { return x.id !== v.id; });
  db.records = db.records.filter(function (r) { return r.vehicleId !== v.id; });
  db.diagnoses = db.diagnoses.filter(function (d) { return d.vehicleId !== v.id; });
  db.shares = db.shares.filter(function (s) { return s.vehicleId !== v.id; });
  saveDb();
  msg("vehicleMsg", "ok", vehicleName(v) + " and its records were removed.");
  renderVehicleList();
}

function renderVehicleList() {
  var list = myVehicles(), box = $("vehicleList");
  if (!list.length) { fill(box, [el("p", { cls: "hint", text: "No vehicles yet. Use the form to add one. You can add more than one." })]); return; }
  fill(box, list.map(function (v) {
    var next = nextService(v);
    var input = el("input", { type: "text", cls: "field inline", placeholder: "New mileage", style: "width:130px" });
    var confirmBox = el("span", { cls: "hidden" }, [" Remove this vehicle and all its records? ",
      el("input", { type: "button", cls: "btn small danger", value: "Yes, remove", onclick: function () { removeVehicle(v); } })]);
    return el("div", { cls: "item vehicle-item" }, [
      el("b", { text: vehicleName(v) }), v.manual ? badge("Added manually", "neutral") : null, el("br"),
      el("span", { cls: "meta", text: fmtKm(v.mileage) + " | " + v.fuel + (v.vin ? " | VIN " + v.vin : "") + " | mileage updated " + fmtDate(v.mileageUpdated) }), el("br"),
      el("span", { cls: "meta", text: next ? "Next service: " + next.type.name + ", " + next.whenText : "" }),
      el("p", null, [input, el("input", { type: "button", cls: "btn small", value: "Update mileage", onclick: function () { updateMileage(v, input); } }),
        el("input", { type: "button", cls: "btn small", value: "Remove", onclick: function () { confirmBox.className = ""; } }), confirmBox])
    ]);
  }));
}

function renderVehicles() {
  if (!$("vMake").options.length) { fillMakeSelect($("vMake"), "", false); fillModelSelect(); fillYearSelect($("vYear")); }
  renderVehicleList();
}

/* =========================================================
   8. Maintenance records and reminders (FR-3.1 to FR-3.5)
   ========================================================= */
function servicesFor(v) {
  return db.kb.services.filter(function (s) {
    return !(v.fuel === "Electric" && ["oil", "sparkplugs", "airfilter", "transmission"].indexOf(s.id) !== -1);
  });
}

function vehicleRecords(vid) {
  return db.records.filter(function (r) { return r.vehicleId === vid; })
    .sort(function (a, b) { return a.date < b.date ? 1 : a.date > b.date ? -1 : b.created - a.created; });
}

// FR-3.3: next due date and mileage from the interval and the last record, whichever comes first.
function serviceStatus(v) {
  var recs = vehicleRecords(v.id);
  return servicesFor(v).map(function (t) {
    var last = recs.filter(function (r) { return r.type === t.id; })[0];
    var baseDate = last ? last.date : v.addedDate;
    var baseKm = last ? (isNaN(last.mileage) || last.mileage === null ? null : last.mileage) : v.addedMileage;
    var dueDate = addMonths(baseDate, t.months);
    var dueKm = (t.km && baseKm !== null) ? baseKm + t.km : null;
    var daysLeft = daysUntil(dueDate);
    var kmLeft = dueKm !== null ? dueKm - v.mileage : null;
    var state = "upcoming";
    if (daysLeft <= 0 || (kmLeft !== null && kmLeft <= 0)) { state = "overdue"; }
    else if (daysLeft <= 14 || (kmLeft !== null && kmLeft <= 500)) { state = "soon"; }
    var snoozeUntil = (v.snoozes || {})[t.id];
    var snoozed = state !== "upcoming" && snoozeUntil && snoozeUntil > today();
    var parts = [];
    if (kmLeft !== null) { parts.push(kmLeft > 0 ? "in " + fmtKm(kmLeft) + " (at " + fmtKm(dueKm) + ")" : fmtKm(-kmLeft) + " overdue (was due at " + fmtKm(dueKm) + ")"); }
    parts.push(daysLeft > 0 ? "by " + fmtDate(dueDate) : "date passed on " + fmtDate(dueDate));
    var firstBy = (kmLeft !== null && daysLeft > 0 && kmLeft / 50 < daysLeft) ? "mileage" : "date";
    return { type: t, last: last, dueDate: dueDate, dueKm: dueKm, daysLeft: daysLeft, kmLeft: kmLeft, state: state,
      snoozed: snoozed, snoozeUntil: snoozeUntil, firstBy: firstBy,
      whenText: (state === "overdue" ? "overdue: " : "due ") + parts.join(" or ") + (kmLeft !== null && state !== "overdue" ? ", whichever comes first" : ""),
      key: v.id + "|" + t.id + "|" + dueDate + "|" + dueKm };
  });
}

function nextService(v) {
  var st = serviceStatus(v).sort(function (a, b) { return rank(a) - rank(b); });
  return st[0];
}
function rank(s) {
  var kmDays = s.kmLeft !== null ? s.kmLeft / 50 : 99999;
  return Math.min(s.daysLeft, kmDays);
}

// UC-05: daily check. Sends one email per due point (in-app reminder + email).
function runReminderCheck() {
  var user = currentUser();
  if (!user) { return 0; }
  var sent = 0;
  myVehicles().forEach(function (v) {
    serviceStatus(v).forEach(function (s) {
      if (s.state === "upcoming" || s.snoozed || db.sentReminders[s.key]) { return; }
      db.sentReminders[s.key] = Date.now();
      sendEmail(user.email,
        (s.state === "overdue" ? "Overdue: " : "Reminder: ") + s.type.name + " for your " + vehicleName(v),
        "Hi " + user.name + ", your " + s.type.name.toLowerCase() + " is " + s.whenText + ". Current mileage: " + fmtKm(v.mileage) +
        ". It is safe to delay this by up to " + delayText(s.type) + " past the due point. Log in to mark it as done or snooze it for 7 days.");
      sent++;
    });
  });
  saveDb();
  return sent;
}
function delayText(t) {
  return (t.delayKm ? fmtKm(t.delayKm) + " or " : "") + t.delayDays + " days";
}

var reminderTab = "upcoming";

function renderMaintenance() {
  if (!$("rType").options.length) {
    db.kb.services.forEach(function (s) { $("rType").appendChild(el("option", { value: s.id, text: s.name })); });
    $("historyFilter").appendChild(el("option", { value: "", text: "All services" }));
    db.kb.services.forEach(function (s) { $("historyFilter").appendChild(el("option", { value: s.id, text: s.name })); });
  }
  if (!$("rDate").value) { $("rDate").value = today(); }
  fillVehicleSelect($("mVehicle"), renderMaintenance);
  selectedVehicleId = $("mVehicle").value;
  renderReminders();
  renderHistory();
}

function renderReminders() {
  var v = getVehicle($("mVehicle").value), box = $("reminderList");
  var tabs = document.querySelectorAll("#remTabs .tab");
  for (var i = 0; i < tabs.length; i++) { tabs[i].className = "tab" + (tabs[i].getAttribute("data-tab") === reminderTab ? " active" : ""); }
  if (!v) { fill(box, [el("p", { cls: "hint", text: "Add a vehicle first." })]); return; }
  if (reminderTab === "completed") {
    var done = vehicleRecords(v.id);
    fill(box, done.length ? done.slice(0, 15).map(function (r) {
      return el("div", { cls: "item" }, [el("b", { text: (serviceType(r.type) || { name: r.type }).name }), badge("Done", "done"), el("br"),
        el("span", { cls: "meta", text: fmtDate(r.date) + (isNaN(r.mileage) || r.mileage === null ? "" : " at " + fmtKm(r.mileage)) })]);
    }) : [el("p", { cls: "hint", text: "No completed services yet." })]);
    return;
  }
  var st = serviceStatus(v).filter(function (s) {
    return reminderTab === "overdue" ? s.state === "overdue" : s.state !== "overdue";
  }).sort(function (a, b) { return rank(a) - rank(b); });
  if (!st.length) { fill(box, [el("p", { cls: "hint", text: reminderTab === "overdue" ? "Nothing is past due. Well done." : "No upcoming services." })]); return; }
  fill(box, st.map(function (s) {
    var label = s.snoozed ? "Snoozed until " + fmtDate(s.snoozeUntil) : s.state === "overdue" ? "Past due" : s.state === "soon" ? "Due soon" : "Upcoming";
    var cls = s.snoozed ? "snoozed" : s.state;
    var actionable = s.state !== "upcoming";
    return el("div", { cls: "item reminder-item" + (s.state === "overdue" ? " overdue-item" : "") }, [
      el("b", { text: s.type.name }), badge(label, cls), el("br"),
      el("span", { text: "Due " + s.whenText.replace(/^due |^overdue: /, "") }), el("br"),
      el("span", { cls: "meta", text: "Last done: " + (s.last ? fmtDate(s.last.date) : "no record yet") + " | Safe delay: up to " + delayText(s.type) + " past due" }),
      actionable ? el("p", null, [
        el("input", { type: "button", cls: "btn small primary", value: "Mark as done", onclick: function () { startRecordFromReminder(v, s); } }),
        s.snoozed ? null : el("input", { type: "button", cls: "btn small", value: "Snooze 7 days", onclick: function () { snooze(v, s); } })
      ]) : null
    ]);
  }));
}

function snooze(v, s) {
  v.snoozes = v.snoozes || {};
  v.snoozes[s.type.id] = addDays(today(), 7);
  saveDb();
  msg("recordMsg", "ok", s.type.name + " reminder snoozed. It will come back on " + fmtDate(v.snoozes[s.type.id]) + ".");
  renderReminders();
}

// FR-3.5 / UC-05 step 6: open a pre-filled record.
function startRecordFromReminder(v, s) {
  $("rType").value = s.type.id;
  $("rDate").value = today();
  $("rMileage").value = String(v.mileage);
  $("rFromReminder").value = s.type.id;
  $("recordTitle").textContent = "Complete: " + s.type.name;
  var stale = daysUntil(v.mileageUpdated) < -30;
  $("staleMileage").className = stale ? "msg warn" : "msg warn hidden";
  $("staleMileage").textContent = stale ? "Your mileage was last updated on " + fmtDate(v.mileageUpdated) + ". Please check the odometer and correct the reading below before saving." : "";
  msg("recordMsg", "", "");
  $("rMileage").focus();
}

function onSaveRecord(e) {
  e.preventDefault();
  var v = getVehicle($("mVehicle").value);
  if (!v) { return msg("recordMsg", "err", "Add a vehicle before recording a service."); }
  var type = $("rType").value, date = $("rDate").value;
  var mileageRaw = $("rMileage").value.trim(), costRaw = $("rCost").value.trim();
  var mileage = mileageRaw ? toNum(mileageRaw) : null, cost = costRaw ? toNum(costRaw) : null;
  if (!type) { return msg("recordMsg", "err", "Choose the service type."); }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) { return msg("recordMsg", "err", "Choose the date of the service."); }
  if (date > today()) { return msg("recordMsg", "err", "The service date cannot be in the future."); }
  if (mileageRaw && (isNaN(mileage) || mileage < 0)) { return msg("recordMsg", "err", "Odometer must be a number of kilometres, or leave it empty."); }
  if (costRaw && (isNaN(cost) || cost < 0)) { return msg("recordMsg", "err", "Cost must be a number, or leave it empty."); }
  var rec = { id: uid("r_"), vehicleId: v.id, type: type, date: date, mileage: mileage === null ? null : Math.round(mileage), cost: cost,
    garage: $("rGarage").value.trim(), notes: $("rNotes").value.trim(), fromReminder: !!$("rFromReminder").value, created: Date.now() };
  db.records.push(rec);
  if (mileage !== null && mileage > v.mileage) { v.mileage = Math.round(mileage); }
  if (mileage !== null) { v.mileageUpdated = today(); }
  if (v.snoozes) { delete v.snoozes[type]; }
  saveDb();
  runReminderCheck();
  var st = serviceStatus(v).filter(function (s) { return s.type.id === type; })[0];
  $("recordForm").reset();
  $("rDate").value = today();
  $("rFromReminder").value = "";
  $("recordTitle").textContent = "Record a service";
  $("staleMileage").className = "msg warn hidden";
  msg("recordMsg", "ok", serviceType(type).name + " saved. Next " + serviceType(type).name.toLowerCase() + " is " + st.whenText + ".");
  renderReminders();
  renderHistory();
}

function renderHistory() {
  var v = getVehicle($("mVehicle").value), box = $("historyList");
  if (!v) { fill(box, [el("p", { cls: "hint", text: "Add a vehicle first." })]); return; }
  var filter = $("historyFilter").value;
  var recs = vehicleRecords(v.id).filter(function (r) { return !filter || r.type === filter; });
  if (!recs.length) { fill(box, [el("p", { cls: "hint", text: "No maintenance records" + (filter ? " of this type" : "") + " yet." })]); return; }
  fill(box, recs.map(function (r) {
    var info = [fmtDate(r.date)];
    if (r.mileage !== null && !isNaN(r.mileage)) { info.push(fmtKm(r.mileage)); }
    if (r.cost !== null && !isNaN(r.cost)) { info.push(fmtAed(r.cost)); }
    if (r.garage) { info.push(r.garage); }
    return el("div", { cls: "item history-item" }, [
      el("b", { text: (serviceType(r.type) || { name: r.type }).name }), el("br"),
      el("span", { cls: "meta", text: info.join(" | ") }),
      r.notes ? el("p", { text: r.notes }) : null
    ]);
  }));
}

/* =========================================================
   9. Dashboard (UI-2)
   ========================================================= */
function renderDashboard() {
  fillVehicleSelect($("dashVehicle"), renderDashboard);
  var v = getVehicle($("dashVehicle").value);
  if (!v) {
    fill($("dashSummary"), [el("p", { text: "You have not added a vehicle yet." }), el("input", { type: "button", cls: "btn primary", value: "Add a vehicle", "data-goto": "vehicles" })]);
    fill($("dashReminders"), [el("p", { cls: "hint", text: "Reminders will appear here." })]);
    fill($("dashDiagnosis"), [el("p", { cls: "hint", text: "No diagnoses yet." })]);
    return;
  }
  selectedVehicleId = v.id;
  var next = nextService(v);
  fill($("dashSummary"), [
    el("p", null, [el("b", { text: vehicleName(v) })]),
    el("p", null, ["Mileage: ", el("b", { text: fmtKm(v.mileage) })]),
    el("p", null, ["Fuel: " + v.fuel]),
    el("p", null, ["Next service: ", el("b", { text: next.type.name }), el("br"), el("span", { cls: "meta", text: next.whenText })])
  ]);
  var due = serviceStatus(v).filter(function (s) { return s.state !== "upcoming" && !s.snoozed; }).sort(function (a, b) { return rank(a) - rank(b); });
  var upcoming = serviceStatus(v).filter(function (s) { return s.state === "upcoming"; }).sort(function (a, b) { return rank(a) - rank(b); });
  var show = due.concat(upcoming).slice(0, 4);
  fill($("dashReminders"), show.map(function (s) {
    return el("div", { cls: "item" + (s.state === "overdue" ? " overdue-item" : "") }, [el("b", { text: s.type.name }),
      badge(s.state === "overdue" ? "Past due" : s.state === "soon" ? "Due soon" : "Upcoming", s.state), el("br"),
      el("span", { cls: "meta", text: s.whenText })]);
  }));
  var diags = db.diagnoses.filter(function (d) { return d.vehicleId === v.id; }).sort(function (a, b) { return b.created - a.created; });
  if (!diags.length) { fill($("dashDiagnosis"), [el("p", { cls: "hint", text: "No diagnoses for this vehicle yet." })]); }
  else {
    var d = diags[0];
    fill($("dashDiagnosis"), [
      el("p", null, [badge(d.urgency + " urgency", d.urgency.toLowerCase())]),
      el("p", null, [el("i", { text: "\"" + d.symptom + "\"" })]),
      el("p", null, ["Most likely: ", el("b", { text: d.causes.length ? d.causes[0].name : "Unknown cause" })]),
      el("p", { cls: "meta", text: fmtStamp(d.created) })
    ]);
  }
}

/* =========================================================
   10. AI troubleshooting (FR-4.1 to FR-4.7, NFR-07, NFR-11)
   The "AI service" here is a rule-based knowledge-base engine.
   ========================================================= */
var DAILY_LIMIT = 20;
var DISCLAIMER = "This result is a suggestion only. It is not a replacement for an inspection by a qualified mechanic. If you are unsure or feel unsafe, stop driving and get professional help.";
var tsState = null;

function renderTroubleshoot() {
  $("tsStep1").className = "card";
  $("tsStep2").className = "card hidden";
  $("tsLoading").className = "card hidden";
  $("tsResult").className = "hidden";
  fillVehicleSelect($("tsVehicle"));
  if (!$("tsLight").options.length) {
    $("tsLight").appendChild(el("option", { value: "", text: "No warning light" }));
    db.kb.lights.forEach(function (l) { $("tsLight").appendChild(el("option", { value: l.id, text: l.name })); });
  }
}

function keywordHit(text, kw) {
  if (kw.length <= 3) {
    var esc = kw.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");
    return new RegExp("(^|[^a-z])" + esc + "([^a-z]|$)").test(text);
  }
  return text.indexOf(kw) !== -1;
}

function matchSymptom(text, lightId) {
  var t = " " + text.toLowerCase() + " ";
  var light = db.kb.lights.filter(function (l) { return l.id === lightId; })[0];
  var best = null, bestScore = 0, bestHits = 0;
  db.kb.symptoms.forEach(function (s) {
    var hits = s.keywords.filter(function (k) { return keywordHit(t, k); }).length;
    var score = hits + (light && light.group === s.id ? 3 : 0);
    if (score > bestScore) { best = s; bestScore = score; bestHits = hits; }
  });
  return best ? { group: best, hits: bestHits, light: light } : null;
}

function onSymptomSubmit(e) {
  e.preventDefault();
  var user = currentUser();
  var v = getVehicle($("tsVehicle").value);
  var text = $("tsText").value.trim(), lightId = $("tsLight").value;
  if (!v) { return msg("tsMsg", "err", "Add a vehicle first so the advice can match your car."); }
  var words = text.split(/\s+/).filter(function (w) { return w; }).length;
  if (text.length < 10 || words < 3) { return msg("tsMsg", "err", "Please tell us a bit more (at least 3 words). For example: \"grinding noise when I brake\"."); }
  if (text.length > 500) { return msg("tsMsg", "err", "Please keep the description under 500 characters."); }
  var todayCount = db.diagnoses.filter(function (d) { return d.userId === user.id && isoDate(new Date(d.created)) === today(); }).length;
  if (todayCount >= DAILY_LIMIT) { return msg("tsMsg", "err", "You have reached the limit of " + DAILY_LIMIT + " diagnoses for today. Please try again tomorrow."); }
  msg("tsMsg", "", "");
  var match = matchSymptom(text, lightId);
  tsState = { vehicle: v, text: text, lightId: lightId, match: match };
  if (!match) { return runDiagnosis([]); }
  var qs = match.group.questions.slice(0, 5);
  fill($("tsQuestions"), qs.map(function (q, qi) {
    return el("div", { cls: "question" }, [el("b", { text: (qi + 1) + ". " + q.q }), el("br")].concat(q.o.map(function (opt, oi) {
      return el("span", { cls: "opt" }, [el("input", { type: "radio", name: "q" + qi, value: String(oi) }), " " + opt[0]]);
    })));
  }));
  $("tsStep1").className = "card hidden";
  $("tsStep2").className = "card";
  $("tsResult").className = "hidden";
  msg("tsQMsg", "", "");
}

function onAnswers(e) {
  e.preventDefault();
  var qs = tsState.match.group.questions.slice(0, 5), answers = [];
  for (var qi = 0; qi < qs.length; qi++) {
    var radios = document.getElementsByName("q" + qi), chosen = -1;
    for (var r = 0; r < radios.length; r++) { if (radios[r].checked) { chosen = parseInt(radios[r].value, 10); } }
    if (chosen === -1) { return msg("tsQMsg", "err", "Please answer every question. Choose \"Not sure\" if you don't know."); }
    answers.push(chosen);
  }
  runDiagnosis(answers);
}

function runDiagnosis(answers) {
  $("tsStep2").className = "card hidden";
  $("tsStep1").className = "card hidden";
  $("tsLoading").className = "card";
  var started = Date.now(), fillBar = $("tsProgress");
  fillBar.style.width = "0%";
  var timer = setInterval(function () {
    var pct = Math.min(100, (Date.now() - started) / 12);
    fillBar.style.width = pct + "%";
  }, 50);
  setTimeout(function () {
    clearInterval(timer);
    fillBar.style.width = "100%";
    var result = diagnose(tsState, answers);
    result.elapsed = Date.now() - started;
    $("tsLoading").className = "card hidden";
    showDiagnosis(result);
  }, 1200);
}

function diagnose(state, answers) {
  var v = state.vehicle, group = state.match ? state.match.group : null;
  var base = { id: uid("d_"), userId: v.userId, vehicleId: v.id, created: Date.now(), symptom: state.text,
    light: state.lightId ? db.kb.lights.filter(function (l) { return l.id === state.lightId; })[0].name : "", answers: [] };
  var lower = state.text.toLowerCase();
  var safetyWord = SAFETY_WORDS.some(function (w) { return lower.indexOf(w) !== -1; });
  if (!group) {
    base.groupName = "Unknown";
    base.causes = [];
    base.urgency = safetyWord ? "High" : "Medium";
    base.safety = safetyWord;
    base.confidence = 0;
    base.reason = "We could not match this description to a known problem.";
    base.action = "Take the car to a professional to check. Describe exactly what you noticed and when.";
    return base;
  }
  var scores = {}, escalate = false, unsure = 0;
  group.causes.forEach(function (c) { scores[c.id] = c.weight; });
  answers.forEach(function (oi, qi) {
    var q = group.questions[qi], opt = q.o[oi];
    base.answers.push({ q: q.q, a: opt[0] });
    if (/not sure|have not checked/i.test(opt[0])) { unsure++; }
    Object.keys(opt[1]).forEach(function (cid) { if (scores[cid] !== undefined) { scores[cid] += opt[1][cid]; } });
    if (opt[2] === "High") { escalate = true; }
  });
  // Use the vehicle's own history: overdue services make related causes more likely.
  var status = serviceStatus(v), notes = {};
  group.causes.forEach(function (c) {
    if (!c.service) { return; }
    var s = status.filter(function (x) { return x.type.id === c.service; })[0];
    if (s && s.state === "overdue") { scores[c.id] += 2; notes[c.id] = "Your records show the " + s.type.name.toLowerCase() + " is overdue, which makes this more likely."; }
    else if (s && !s.last) { scores[c.id] += 1; notes[c.id] = "There is no " + s.type.name.toLowerCase() + " record for this car yet."; }
  });
  var total = 0;
  Object.keys(scores).forEach(function (k) { total += Math.max(0, scores[k]); });
  var ranked = group.causes.map(function (c) {
    return { name: c.name, explain: c.explain, action: c.action, min: c.min, max: c.max, note: notes[c.id] || "",
      pct: total ? Math.round(Math.max(0, scores[c.id]) / total * 100) : 0 };
  }).sort(function (a, b) { return b.pct - a.pct; }).slice(0, 3);
  var hits = state.match.hits + (state.match.light && state.match.light.group === group.id ? 1 : 0);
  var conf = 35 + ranked[0].pct * 0.5 + Math.min(hits, 3) * 8 - unsure * 5 + (answers.length ? 5 : 0);
  conf = Math.max(20, Math.min(95, Math.round(conf)));
  var urgency = group.urgency;
  var safety = group.safety || safetyWord || escalate;
  if (safety) { urgency = "High"; }
  var reasons = {
    High: group.safety || safetyWord ? group.name + " affects the safety of the car (brakes, steering, overheating, loss of power or engine damage)." : "Your answers point to a problem that can quickly cause damage.",
    Medium: group.name + " needs attention soon, but is not usually an emergency.",
    Low: group.name + " is not a safety risk. It can wait for your next service."
  };
  var actions = {
    High: "Stop driving as soon as it is safe and contact a qualified mechanic or roadside recovery.",
    Medium: "Book a service within the next 7 days.",
    Low: "Check it at your next planned service."
  };
  base.groupName = group.name;
  base.causes = ranked;
  base.urgency = urgency;
  base.safety = safety;
  base.confidence = conf;
  base.reason = reasons[urgency];
  base.action = actions[urgency];
  return base;
}

function showDiagnosis(d) {
  db.diagnoses.push(d);
  saveDb();
  var v = getVehicle(d.vehicleId);
  var box = $("tsResult");
  var kids = [];
  kids.push(el("div", { cls: "urgency-box " + d.urgency, id: "urgencyBox" }, [
    el("h3", { text: d.urgency + " urgency: " + d.action }),
    el("span", { text: d.reason })
  ]));
  if (d.safety) {
    kids.push(el("div", { cls: "safety-warning", id: "safetyWarning" }, [
      el("b", { text: "Safety warning: stop driving when it is safe to do so." }), el("br"),
      "Pull over somewhere safe, turn on your hazard lights and switch off the engine. Contact a qualified mechanic or call your roadside recovery service. Do not keep driving to \"see if it gets better\"."
    ]));
  }
  var card = el("div", { cls: "card" });
  card.appendChild(el("p", null, [el("b", { text: "Vehicle: " }), vehicleName(v), el("br"), el("b", { text: "You said: " }), el("i", { text: "\"" + d.symptom + "\"" }),
    d.light ? el("span", { text: " (warning light: " + d.light + ")" }) : null]));
  if (d.causes.length) {
    card.appendChild(el("p", null, [el("b", { text: "Confidence: " + d.confidence + "%" })]));
    card.appendChild(el("div", { cls: "bar" }, [el("div", { style: "width:" + d.confidence + "%" })]));
    if (d.confidence < 60) {
      card.appendChild(el("div", { cls: "msg warn", text: "We are not sure about this result. Please have a professional check the car." }));
    }
    card.appendChild(el("h3", { text: "Likely causes" }));
    d.causes.forEach(function (c, i) {
      card.appendChild(el("div", { cls: "cause" }, [
        el("b", { text: (i + 1) + ". " + c.name + " (" + c.pct + "% likely)" }),
        el("div", { cls: "bar" }, [el("div", { style: "width:" + c.pct + "%" })]),
        el("span", { text: c.explain }), el("br"),
        el("b", { text: "What to do: " }), el("span", { text: c.action }), el("br"),
        el("span", { cls: "meta", text: "Estimated cost (parts and labour): " + (c.max === 0 ? "free" : fmtAed(c.min) + " to " + fmtAed(c.max)) }),
        c.note ? el("p", { cls: "meta", text: c.note }) : null
      ]));
    });
    card.appendChild(el("p", { cls: "hint", text: "Cost estimates are rough guides for an independent garage in the UAE (November 2026). Prices at dealers can be higher." }));
  } else {
    card.appendChild(el("div", { cls: "msg warn", text: "Unknown cause. We could not match your description to a known problem. You need to take the car to a professional to check it." }));
  }
  if (d.answers.length) {
    card.appendChild(el("p", null, [el("b", { text: "Your answers" })]));
    card.appendChild(el("ul", { cls: "clean" }, d.answers.map(function (a) { return el("li", { text: a.q + " " + a.a }); })));
  }
  card.appendChild(el("div", { cls: "disclaimer", id: "disclaimer" }, [el("b", { text: "Please note: " }), DISCLAIMER]));
  var recovery = el("div", { cls: "msg hidden" }, [el("div", { cls: "warn", text: "Call your roadside assistance number (often on your insurance card or registration). Stay away from traffic while you wait." })]);
  card.appendChild(el("p", null, [
    d.urgency === "High" ? el("input", { type: "button", cls: "btn danger", value: "Contact recovery", onclick: function () { recovery.className = "msg"; } }) : null,
    el("input", { type: "button", cls: "btn", value: "Log a repair", onclick: function () { showPage("maintenance"); $("rType").value = "inspection"; $("rNotes").value = "After diagnosis: " + (d.causes[0] ? d.causes[0].name : d.symptom); } }),
    el("input", { type: "button", cls: "btn primary", value: "Diagnose another problem", onclick: resetTroubleshoot })
  ]));
  card.appendChild(recovery);
  card.appendChild(el("p", { cls: "meta", id: "diagMeta", text: "Saved to the vehicle history on " + fmtStamp(d.created) + ". Result produced in " + (d.elapsed / 1000).toFixed(1) + " seconds." }));
  kids.push(card);
  fill(box, kids);
  box.className = "";
}

function resetTroubleshoot() {
  $("symptomForm").reset();
  $("tsCount").textContent = "0 / 500";
  $("tsLightInfo").textContent = "";
  msg("tsMsg", "", "");
  renderTroubleshoot();
}

/* =========================================================
   11. Used-car evaluation (FR-5.1, FR-5.2)
   ========================================================= */
var CHECKLIST = [
  "Engine starts from cold with no knocking or smoke",
  "Gearbox changes smoothly on a test drive",
  "No signs of chassis or frame repair",
  "Tyres have even tread and matching brands",
  "Brakes stop straight with no noise",
  "AC blows cold within 2 minutes",
  "All warning lights go off after starting",
  "Odometer matches the mileage in the car computer",
  "Service book or digital records match the mileage",
  "Professional pre-purchase inspection (PPI) done"
];

function renderEvaluate() {
  if (!$("eMake").options.length) { fillMakeSelect($("eMake"), "", true); fillYearSelect($("eYear")); }
  renderSavedEvaluations();
}

function radioValue(name) {
  var r = document.getElementsByName(name);
  for (var i = 0; i < r.length; i++) { if (r[i].checked) { return r[i].value; } }
  return "";
}

function onEvaluate(e) {
  e.preventDefault();
  var user = currentUser();
  var make = $("eMake").value, model = $("eModel").value.trim(), year = parseInt($("eYear").value, 10);
  var mileage = toNum($("eMileage").value), price = toNum($("ePrice").value);
  var ecuRaw = $("eEcuMileage").value.trim(), ecu = ecuRaw ? toNum(ecuRaw) : null;
  var thisYear = new Date(Date.now()).getFullYear();
  var errors = [];
  if (!make) { errors.push("choose the make"); }
  if (!model) { errors.push("enter the model"); }
  if (year > thisYear + 1) { errors.push("the year cannot be in the future"); }
  if (isNaN(mileage) || mileage < 0) { errors.push("enter the odometer reading as a positive number"); }
  if (isNaN(price) || price <= 0) { errors.push("enter the asking price in AED"); }
  if (ecuRaw && (isNaN(ecu) || ecu < 0)) { errors.push("the computer mileage must be a number"); }
  var files = $("eFiles").files || [], photos = [], report = [];
  for (var i = 0; i < files.length; i++) {
    var f = files[i], n = f.name.toLowerCase();
    if (f.size > 10 * 1024 * 1024) { errors.push(f.name + " is larger than 10 MB"); continue; }
    if (/\.(jpe?g|png)$/.test(n)) { photos.push(f.name); }
    else if (/\.pdf$/.test(n)) { report.push(f.name); }
    else { errors.push(f.name + " is not a JPG, PNG or PDF file"); }
  }
  if (photos.length > 10) { errors.push("you can upload up to 10 photos"); }
  if (report.length > 1) { errors.push("you can upload only 1 inspection report"); }
  if (errors.length) { return msg("evalMsg", "err", "Please fix the following: " + errors.join("; ") + "."); }
  msg("evalMsg", "", "");
  var ev = evaluateCar({ make: make, model: model, year: year, mileage: mileage, price: price, ecu: ecu,
    owners: parseInt($("eOwners").value, 10), service: radioValue("eService"), accident: radioValue("eAccident"), photos: photos, report: report[0] || "" });
  ev.id = uid("e_"); ev.userId = user.id; ev.created = Date.now();
  ev.checks = CHECKLIST.map(function () { return "unchecked"; });
  db.evaluations.push(ev);
  saveDb();
  showEvaluation(ev);
  renderSavedEvaluations();
}

function evaluateCar(c) {
  var thisYear = new Date(Date.now()).getFullYear();
  var age = Math.max(0, thisYear - c.year);
  var expectedKm = Math.max(1, age) * 20000;
  var base = BASE_PRICE[c.make] || BASE_PRICE.Other;
  var kmFactor = Math.max(0.6, Math.min(1.15, 1 - (c.mileage - expectedKm) / 300000));
  var typical = Math.round(base * Math.pow(0.86, age) * kmFactor / 500) * 500;
  var ratio = c.price / typical;
  var priceText = ratio < 0.9 ? "Below typical" : ratio > 1.1 ? "Above typical" : "Fair";
  var score = 100, flags = [];
  score -= Math.min(30, age * 2);
  if (c.mileage > expectedKm * 1.25) { score -= 10; flags.push("High mileage for its age (" + fmtKm(c.mileage) + " against about " + fmtKm(expectedKm) + " expected)."); }
  if (c.owners >= 3) { score -= 5 * (c.owners - 2); flags.push(c.owners >= 4 ? "Four or more previous owners." : "Three previous owners."); }
  if (c.service === "partial") { score -= 10; flags.push("Only partial service history."); }
  if (c.service === "none") { score -= 20; flags.push("No service history. Condition is hard to judge without records."); }
  if (c.accident === "minor") { score -= 10; flags.push("Minor accident reported. Check panel gaps and paint."); }
  if (c.accident === "major") { score -= 25; flags.push("Major accident reported. Ask for a frame check."); }
  var mismatch = false;
  if (c.ecu !== null && !isNaN(c.ecu) && Math.abs(c.ecu - c.mileage) > Math.max(5000, c.mileage * 0.05)) {
    mismatch = true; score -= 20;
    flags.push("Mileage mismatch: odometer shows " + fmtKm(c.mileage) + " but the car computer shows " + fmtKm(c.ecu) + ".");
  }
  if (priceText === "Below typical" && (c.accident !== "none" || c.service === "none")) { flags.push("Low price together with history gaps. Find out why it is cheap."); }
  if (priceText === "Above typical") { flags.push("Asking price is above the typical range. There may be room to negotiate."); }
  if (!c.photos.length && !c.report) { flags.push("No photos or inspection report uploaded."); }
  score = Math.max(0, Math.min(100, Math.round(score)));
  return { make: c.make, model: c.model, year: c.year, mileage: c.mileage, ecu: c.ecu, price: c.price, owners: c.owners,
    service: c.service, accident: c.accident, photos: c.photos, report: c.report, typical: typical, priceText: priceText,
    score: score, flags: flags, mismatch: mismatch,
    knownIssues: KNOWN_ISSUES[c.make] || KNOWN_ISSUES["default"] };
}

function showEvaluation(ev) {
  var box = $("evalResult");
  var checksBox = el("div");
  var progressFill = el("div", { cls: "progress-fill green" });
  var progressText = el("span", { cls: "meta" });
  function updateProgress() {
    var done = ev.checks.filter(function (s) { return s !== "unchecked"; }).length;
    var concerns = ev.checks.filter(function (s) { return s === "concern"; }).length;
    progressFill.style.width = Math.round(done / ev.checks.length * 100) + "%";
    progressText.textContent = done + " of " + ev.checks.length + " checks done" + (concerns ? ", " + concerns + " concern(s)" : "");
  }
  CHECKLIST.forEach(function (item, i) {
    var sel = el("select", { cls: "field inline", onchange: function () { ev.checks[i] = sel.value; saveDb(); updateProgress(); } }, [
      el("option", { value: "unchecked", text: "Unchecked" }), el("option", { value: "ok", text: "OK" }), el("option", { value: "concern", text: "Concern" })]);
    sel.value = ev.checks[i];
    checksBox.appendChild(el("div", { cls: "check-row" }, [sel, el("span", { text: item })]));
  });
  updateProgress();
  var verdict = ev.score >= 75 ? "Looks like a good candidate, subject to a PPI." : ev.score >= 50 ? "Some risks. Inspect carefully and negotiate." : "High risk. Consider walking away.";
  fill(box, [
    el("p", null, [el("b", { text: ev.year + " " + ev.make + " " + ev.model }), el("br"), el("span", { cls: "meta", text: fmtKm(ev.mileage) + " | asking " + fmtAed(ev.price) })]),
    ev.mismatch ? el("div", { cls: "msg err", id: "mismatchAlert", text: "Mileage mismatch alert: the odometer and the car computer do not agree. This can mean the odometer was changed." }) : null,
    el("p", null, ["Condition score", el("br"), el("span", { cls: "score", text: String(ev.score) }), " / 100"]),
    el("p", null, [el("b", { text: "Summary: " }), verdict]),
    el("p", null, [el("b", { text: "Price assessment: " }), badge(ev.priceText, ev.priceText === "Fair" ? "low" : ev.priceText === "Above typical" ? "high" : "medium"),
      el("br"), el("span", { cls: "meta", text: "Typical price for this age and mileage: about " + fmtAed(ev.typical * 0.9) + " to " + fmtAed(ev.typical * 1.1) + " (rough guide)." })]),
    el("h4", { text: "Risk flags" }),
    ev.flags.length ? el("ul", { cls: "clean" }, ev.flags.map(function (f) { return el("li", { text: f }); })) : el("p", { text: "No risk flags from the details given." }),
    el("h4", { text: "Known issues with this make" }),
    el("ul", { cls: "clean" }, ev.knownIssues.map(function (k) { return el("li", { text: k }); })),
    ev.photos.length || ev.report ? el("p", { cls: "meta", text: "Files attached: " + ev.photos.length + " photo(s)" + (ev.report ? ", report " + ev.report : "") }) : null,
    el("h4", { text: "Checklist before you buy" }),
    el("div", { cls: "progress" }, [progressFill]), progressText,
    checksBox,
    el("div", { cls: "disclaimer" }, [el("b", { text: "Please note: " }), "This evaluation is a suggestion only. It is not a replacement for a professional pre-purchase inspection."]),
    el("p", { cls: "meta", text: "Saved to your account on " + fmtStamp(ev.created) + "." })
  ]);
}

function renderSavedEvaluations() {
  var user = currentUser();
  var list = db.evaluations.filter(function (x) { return x.userId === user.id; }).sort(function (a, b) { return b.created - a.created; });
  fill($("evalSaved"), list.length ? list.map(function (ev) {
    return el("div", { cls: "item" }, [el("b", { text: ev.year + " " + ev.make + " " + ev.model }), " score " + ev.score + "/100, " + ev.priceText.toLowerCase() + " price ",
      el("span", { cls: "meta", text: "(" + fmtStamp(ev.created) + ") " }),
      el("input", { type: "button", cls: "btn small", value: "Open", onclick: function () { showEvaluation(ev); } }),
      el("input", { type: "button", cls: "btn small", value: "Delete", onclick: function () { db.evaluations = db.evaluations.filter(function (x) { return x.id !== ev.id; }); saveDb(); renderSavedEvaluations(); } })]);
  }) : [el("p", { cls: "hint", text: "No saved evaluations yet." })]);
}

/* =========================================================
   12. Service history report and sharing (UI-7, FR-6.1)
   ========================================================= */
function renderReports() {
  fillVehicleSelect($("repVehicle"), renderReports);
  var v = getVehicle($("repVehicle").value);
  fill($("shareOut"), []);
  if (!v) { fill($("reportBody"), [el("div", { cls: "card" }, [el("p", { cls: "hint", text: "Add a vehicle first." })])]); return; }
  selectedVehicleId = v.id;
  fill($("reportBody"), buildReport(v, $("repFrom").value, $("repTo").value, false));
}

function buildReport(v, from, to, readOnly) {
  var recs = vehicleRecords(v.id).filter(function (r) { return (!from || r.date >= from) && (!to || r.date <= to); });
  var costs = recs.filter(function (r) { return r.cost !== null && !isNaN(r.cost); });
  var total = costs.reduce(function (s, r) { return s + r.cost; }, 0);
  var mean = costs.length ? total / costs.length : 0;
  var byMonth = {};
  costs.forEach(function (r) { var k = r.date.substring(0, 7); byMonth[k] = (byMonth[k] || 0) + r.cost; });
  var months = Object.keys(byMonth).sort().slice(-10);
  var maxVal = months.reduce(function (m, k) { return Math.max(m, byMonth[k]); }, 0);
  var chart = el("div", { cls: "chart" }, months.map(function (k) {
    var h = maxVal ? Math.max(4, Math.round(byMonth[k] / maxVal * 130)) : 0;
    return el("div", { cls: "chart-col" }, [el("span", { cls: "chart-val", style: "bottom:" + (h + 2) + "px", text: fmtNum(byMonth[k]) }),
      el("div", { cls: "chart-bar", style: "height:" + h + "px" })]);
  }));
  var labels = el("div", { cls: "chart-labels" }, months.map(function (k) { return el("span", { text: MONTHS[+k.substring(5) - 1] + " " + k.substring(2, 4) }); }));
  var diags = db.diagnoses.filter(function (d) { return d.vehicleId === v.id; }).sort(function (a, b) { return b.created - a.created; });
  return [
    el("div", { cls: "card" }, [
      el("h3", { text: vehicleName(v) }),
      el("p", { cls: "meta", text: fmtKm(v.mileage) + " | " + v.fuel + (v.vin ? " | VIN " + v.vin : "") + " | report generated " + fmtDate(today()) }),
      el("div", { cls: "stats" }, [
        el("span", null, [el("b", { text: fmtAed(total) }), "Total spent"]),
        el("span", null, [el("b", { text: String(recs.length) }), "Services"]),
        el("span", null, [el("b", { text: fmtAed(mean) }), "Average price"])
      ])
    ]),
    el("div", { cls: "card" }, [el("h3", { text: "Money spent per month (AED)" }),
      months.length ? chart : el("p", { cls: "hint", text: "No costs recorded in this period." }), months.length ? labels : null]),
    el("div", { cls: "card" }, [el("h3", { text: "Services" }),
      recs.length ? el("ul", { cls: "clean" }, recs.map(function (r) {
        return el("li", null, [el("b", { text: fmtDate(r.date) + ": " + (serviceType(r.type) || { name: r.type }).name }),
          " | " + fmtKm(r.mileage) + " | " + (r.garage || "garage not recorded") + " | " + (r.cost !== null && !isNaN(r.cost) ? fmtAed(r.cost) : "no cost")]);
      })) : el("p", { cls: "hint", text: "No services in this period." })]),
    el("div", { cls: "card" }, [el("h3", { text: "Diagnosis reports" }),
      diags.length ? el("ul", { cls: "clean" }, diags.map(function (d) {
        return el("li", null, [el("b", { text: fmtStamp(d.created) + ": " }), "\"" + d.symptom + "\" ", badge(d.urgency, d.urgency.toLowerCase()),
          el("br"), el("span", { cls: "meta", text: d.causes.length ? "Likely causes: " + d.causes.map(function (c) { return c.name + " (" + c.pct + "%)"; }).join(", ") : "Unknown cause, professional check advised" })]);
      })) : el("p", { cls: "hint", text: "No diagnoses yet." })]),
    readOnly ? el("p", { cls: "hint", text: DISCLAIMER }) : null
  ];
}

function onShare() {
  var v = getVehicle($("repVehicle").value), user = currentUser();
  if (!v) { return; }
  var tok = randomToken();
  var share = { token: tok, vehicleId: v.id, userId: user.id, created: Date.now(), expires: Date.now() + 7 * 86400000 };
  db.shares.push(share);
  saveDb();
  var link = location.href.split("#")[0] + "#share=" + tok;
  fill($("shareOut"), [
    el("p", null, [el("b", { text: "Read-only link created." }), " It expires on " + fmtStamp(share.expires) + "."]),
    el("p", { cls: "share-link", id: "shareLinkText", text: link }),
    el("p", null, [el("a", { href: link, target: "_blank", text: "Open the shared view" })]),
    el("p", { cls: "hint", text: "In this browser-only prototype, the link opens on this computer. A hosted version would serve it to the technician's browser." })
  ]);
}

function renderShare(tok) {
  var share = db.shares.filter(function (s) { return s.token === tok; })[0];
  var box = $("shareView");
  if (!share) { fill(box, [el("div", { cls: "card" }, [el("h2", { text: "Link not valid" }), el("p", { text: "This shared report does not exist or was removed by the owner." })])]); }
  else if (share.expires < Date.now()) { fill(box, [el("div", { cls: "card" }, [el("h2", { text: "Link expired" }), el("p", { text: "This shared report expired on " + fmtStamp(share.expires) + ". Ask the owner for a new link." })])]); }
  else {
    var v = getVehicle(share.vehicleId);
    fill(box, [el("div", { cls: "msg warn", text: "Read-only vehicle report shared by the owner. This link expires on " + fmtStamp(share.expires) + "." })].concat(buildReport(v, "", "", true)));
  }
  var pages = document.querySelectorAll(".page");
  for (var i = 0; i < pages.length; i++) { pages[i].className = "page"; }
  $("page-share").className = "page active";
  currentPage = "share";
  updateHeader();
}

/* =========================================================
   13. Admin (FR-6.2, FR-6.3, NFR-10)
   ========================================================= */
function renderAdmin() {
  renderAdminUsers();
  fill($("adminIntervals"), db.kb.services.map(function (s) {
    var km = el("input", { type: "text", cls: "field inline", value: String(s.km), style: "width:90px" });
    var mo = el("input", { type: "text", cls: "field inline", value: String(s.months), style: "width:60px" });
    return el("div", { cls: "item" }, [el("b", { text: s.name }), el("br"), "Every ", km, " km (0 = time only) or ", mo, " months ",
      el("input", { type: "button", cls: "btn small", value: "Save", onclick: function () {
        var k = toNum(km.value), m = toNum(mo.value);
        if (isNaN(k) || isNaN(m) || m < 1) { return msg("causeMsg", "err", "Intervals must be numbers, with at least 1 month."); }
        s.km = Math.round(k); s.months = Math.round(m); saveDb();
        msg("causeMsg", "ok", s.name + " interval saved. It is used straight away for all reminders.");
      } })]);
  }));
  fill($("adminLights"), db.kb.lights.map(function (l) {
    var ta = el("textarea", { cls: "field", rows: "2" }); ta.value = l.info;
    return el("div", { cls: "item" }, [el("b", { text: l.name }), ta,
      el("input", { type: "button", cls: "btn small", value: "Save", onclick: function () { l.info = ta.value.trim(); saveDb(); msg("causeMsg", "ok", l.name + " definition saved."); } })]);
  }));
  fill($("adminCauses"), db.kb.symptoms.map(function (g) {
    return el("div", { cls: "item" }, [el("b", { text: g.name }), g.safety ? badge("Safety critical", "high") : badge(g.urgency, g.urgency.toLowerCase()),
      el("ul", { cls: "clean" }, g.causes.map(function (c) {
        return el("li", null, [c.name + " (weight " + c.weight + ") ",
          el("input", { type: "button", cls: "btn small", value: "Remove", onclick: function () {
            if (g.causes.length <= 1) { return msg("causeMsg", "err", "Each symptom group needs at least one cause."); }
            g.causes = g.causes.filter(function (x) { return x !== c; }); saveDb(); renderAdmin(); msg("causeMsg", "ok", "Cause removed.");
          } })]);
      }))]);
  }));
  var sel = $("cGroup");
  if (!sel.options.length) { db.kb.symptoms.forEach(function (g) { sel.appendChild(el("option", { value: g.id, text: g.name })); }); }
  var usageToday = db.diagnoses.filter(function (d) { return isoDate(new Date(d.created)) === today(); }).length;
  var review = db.reviewModels.length ? db.reviewModels.map(function (m) { return m.year + " " + m.make + " " + m.model; }).join(", ") : "none";
  $("adminUsers").appendChild(el("p", { cls: "meta", text: "AI diagnosis use: " + usageToday + " today, " + db.diagnoses.length + " in total. Models waiting to be added: " + review + "." }));
}

function renderAdminUsers() {
  var q = $("adminSearch").value.trim().toLowerCase(), me = currentUser();
  var list = db.users.filter(function (u) { return !q || u.name.toLowerCase().indexOf(q) !== -1 || u.email.indexOf(q) !== -1; });
  fill($("adminUsers"), list.map(function (u) {
    return el("div", { cls: "item user-item" }, [el("b", { text: u.name }), " ", el("span", { cls: "meta", text: u.email }),
      badge(u.role === "admin" ? "Admin" : "Owner", "neutral"), badge(u.active ? "Active" : "Deactivated", u.active ? "done" : "high"),
      u.id === me.id ? null : el("input", { type: "button", cls: "btn small", value: u.active ? "Deactivate" : "Reactivate", onclick: function () {
        u.active = !u.active; saveDb(); renderAdmin();
      } })]);
  }));
}

function onAddCause(e) {
  e.preventDefault();
  var g = db.kb.symptoms.filter(function (x) { return x.id === $("cGroup").value; })[0];
  var name = $("cName").value.trim(), w = toNum($("cWeight").value), min = toNum($("cMin").value), max = toNum($("cMax").value);
  if (!g || !name || !$("cExplain").value.trim() || !$("cAction").value.trim()) { return msg("causeMsg", "err", "Fill in the group, name, explanation and action."); }
  if (isNaN(w) || w < 1 || w > 10 || isNaN(min) || isNaN(max) || max < min) { return msg("causeMsg", "err", "Weight must be 1 to 10 and the cost range must be valid."); }
  g.causes.push({ id: uid("c"), name: name, weight: w, min: min, max: max, explain: $("cExplain").value.trim(), action: $("cAction").value.trim() });
  saveDb();
  $("causeForm").reset();
  renderAdmin();
  msg("causeMsg", "ok", "Cause added to " + g.name + ". It is used in the next diagnosis.");
}

/* =========================================================
   14. Demo inbox (notification service)
   ========================================================= */
function renderInbox() {
  var list = db.emails.slice().sort(function (a, b) { return b.created - a.created; });
  fill($("inboxList"), list.length ? list.map(function (m) {
    return el("div", { cls: "email" }, [
      el("b", { text: m.subject }), el("br"),
      el("span", { cls: "meta", text: "To: " + m.to + " | " + fmtStamp(m.created) }),
      el("p", { text: m.body }),
      m.link ? el("p", null, [el("a", { href: m.link, cls: "email-link", text: m.linkText || m.link })]) : null
    ]);
  }) : [el("p", { cls: "hint", text: "No emails yet." })]);
}

/* =========================================================
   15. Start-up
   ========================================================= */
function init() {
  loadDb();
  wireNavigation();
  $("registerForm").addEventListener("submit", onRegister);
  $("loginForm").addEventListener("submit", onLogin);
  $("forgotForm").addEventListener("submit", onForgot);
  $("resetForm").addEventListener("submit", onReset);
  $("deleteForm").addEventListener("submit", onDelete);
  $("vehicleForm").addEventListener("submit", onAddVehicle);
  $("vehicleForm").addEventListener("reset", function () { setTimeout(function () { fillModelSelect(); toggleManual(); }, 0); });
  $("vMakeSearch").addEventListener("input", function () { fillMakeSelect($("vMake"), $("vMakeSearch").value, false); fillModelSelect(); });
  $("vMake").addEventListener("change", fillModelSelect);
  $("vManual").addEventListener("change", toggleManual);
  $("vVin").addEventListener("change", vinAutofill);
  $("recordForm").addEventListener("submit", onSaveRecord);
  $("historyFilter").addEventListener("change", renderHistory);
  $("runCheckBtn").addEventListener("click", function () {
    var n = runReminderCheck();
    msg("recordMsg", "ok", "Daily check finished. " + n + " new reminder email" + (n === 1 ? "" : "s") + " sent.");
    renderReminders();
  });
  $("remTabs").addEventListener("click", function (e) {
    if (e.target.getAttribute("data-tab")) { reminderTab = e.target.getAttribute("data-tab"); renderReminders(); }
  });
  $("symptomForm").addEventListener("submit", onSymptomSubmit);
  $("questionForm").addEventListener("submit", onAnswers);
  $("tsRestart").addEventListener("click", resetTroubleshoot);
  $("tsText").addEventListener("input", function () { $("tsCount").textContent = $("tsText").value.length + " / 500"; });
  $("tsLight").addEventListener("change", function () {
    var l = db.kb.lights.filter(function (x) { return x.id === $("tsLight").value; })[0];
    $("tsLightInfo").textContent = l ? l.name + ": " + l.info : "";
  });
  var chips = document.querySelectorAll(".chip");
  for (var i = 0; i < chips.length; i++) {
    chips[i].addEventListener("click", function (e) { $("tsText").value = e.target.textContent; $("tsCount").textContent = $("tsText").value.length + " / 500"; });
  }
  $("evalForm").addEventListener("submit", onEvaluate);
  $("repFrom").addEventListener("change", renderReports);
  $("repTo").addEventListener("change", renderReports);
  $("repPrint").addEventListener("click", function () { window.print(); });
  $("repShare").addEventListener("click", onShare);
  $("adminSearch").addEventListener("input", renderAdmin);
  $("causeForm").addEventListener("submit", onAddCause);
  window.addEventListener("hashchange", handleHash);
  if (!handleHash()) {
    if (currentUser()) { runReminderCheck(); showPage("dashboard"); } else { showPage("login"); }
  }
}

init();
