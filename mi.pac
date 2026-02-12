// Helper function to check if a string is an IP address
function isIP(host) {
    var parts = host.split(".");
    if (parts.length !== 4) {
        return false;
    }
    for (var i = 0; i < 4; i++) {
        var num = parseInt(parts[i], 10);
        if (isNaN(num) || num < 0 || num > 255) {
            return false;
        }
    }
    return true;
}

// Helper function to check if IP is in private network range
function isPrivateIP(host) {
    if (!isIP(host)) {
        return false;
    }
    var parts = host.split(".");
    var first = parseInt(parts[0], 10);
    var second = parseInt(parts[1], 10);
    
    // 10.0.0.0/8
    if (first === 10) {
        return true;
    }
    // 172.16.0.0/12
    if (first === 172 && second >= 16 && second <= 31) {
        return true;
    }
    // 192.168.0.0/16
    if (first === 192 && second === 168) {
        return true;
    }
    // 127.0.0.0/8 (localhost)
    if (first === 127) {
        return true;
    }
    return false;
}

function FindProxyForURL(url, host) {
    // Enable logging (set to false to disable)
    var enableLog = true;
    
    // Log function for debugging using alert
    function log(message) {
        if (enableLog) {
            alert("PAC: " + message);
        }
    }
    
    log("Checking URL: " + url + ", Host: " + host);
    
    // Direct connect addresses and domains (whitelist)
    var direct_list = [
        "localhost",
        "*.cn", // All .cn domains direct connect (use with caution)
        "*.baidu.com",
        "*.qq.com",
        "*.taobao.com"
    ];

    // Proxy addresses and domains (proxy list)
    var proxy_list = [
        "google.com",
        "*.google.com",
        "*.youtube.com",
        "*.facebook.com",
        "*.twitter.com"
    ];

    // 1. Check if host is localhost or private IP, then direct connect
    if (host === "localhost" || host === "127.0.0.1" || isPrivateIP(host)) {
        log("Matched private/localhost IP: " + host + " -> DIRECT");
        return "DIRECT";
    }

    // 2. Check if host is in direct list (whitelist), then direct connect
    for (var i = 0; i < direct_list.length; i++) {
        if (shExpMatch(host, direct_list[i])) {
            log("Matched direct list pattern: " + direct_list[i] + " for " + host + " -> DIRECT");
            return "DIRECT";
        }
    }

    // 3. Check if host is in proxy list, then use proxy
    for (var i = 0; i < proxy_list.length; i++) {
        if (shExpMatch(host, proxy_list[i])) {
            log("Matched proxy list pattern: " + proxy_list[i] + " for " + host + " -> PROXY");
            return "SOCKS5 127.0.0.1:1088"; // This port should match your sslocal listening port
        }
    }

    // 4. Default rule: all other traffic direct connect
    log("No match found for " + host + " -> DIRECT (default)");
    return "DIRECT";
}