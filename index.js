const express = require('express')
const fs = require("fs");
const os = require('os');
const WebKingExpress = express()
const requestCounts = {};

var config = {
    port: 80,            // host port
    name: 'WebKing',     // response name if blocked
    protection: true,    // enable protection (recommed)
    client_ssl: false,   // request requires ssl
    max_packet: 100001,  // max packet size (bytes)
    domains: [],         // put in ./config/domains.txt
    ip_block: []         // put in ./config/ipblocks.txt
};

var protection_config = {
    rate_requests: 3,      // requests
    rate_requests_time: 1  // time
}

fs.readFile('./config/domains.txt', 'utf-8', (err, data) => {
    config.domains = data.split(os.EOL);
});
fs.readFile('./config/ipblocks.txt', 'utf-8', (err, data) => {
    config.ip_block = data.split(os.EOL);
});

WebKingExpress.use(express.json());

WebKingExpress.use((req, res, next) => {
    var remote_ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    var remote_packet = JSON.stringify(req.body).length;
    if(config.client_ssl == true) {
        if(!req.secure) {
            res.redirect(`https://${req.headers.host}${req.url}`);
        } else {
            next();
        }
    }
    if (config.protection !== true || !remote_packet) {
        next();
        return;
    }
    const currenttime = Date.now();
    requestCounts[remote_ip] = requestCounts[remote_ip] || [];
    requestCounts[remote_ip].push(currenttime);
    if (!config.domains.includes(req.headers.host) || remote_packet > config.max_packet || config.ip_block.includes(req.headers['x-forwarded-for'] || req.connection.remoteAddress) || requestCounts[remote_ip].filter(time => currentTime - time < protection_config.rate_requests_time * 1000).length >= protection_config.rate_requests) {
        return res.status(403).end(`Blocked at ${config.name}`);
    }
    next();
});

WebKingExpress.use(express.static("public"));

WebKingExpress.listen(config.port, () => {
    console.log(`WebKing listening on port ${config.port}`)
})