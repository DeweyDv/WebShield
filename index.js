const express = require('express')
const fs = require("fs");
const os = require('os');
const WebKingExpress = express()
const requestCounts = {};

var config = {
    port: 80,
    name: 'WebKing',
    protection: true,
    logs: false,
    domains: [], // put in domains.txt
    ip_block: [] // put in ipblocks.txt
};

var protection_config = {
    rate_requests: 5,
    rate_requests_time: 3
}

fs.readFile('./config/domains.txt', 'utf-8', (err, data) => {
    config.domains = data.split(os.EOL);
});
fs.readFile('./config/ipblocks.txt', 'utf-8', (err, data) => {
    config.ip_block = data.split(os.EOL);
});

WebKingExpress.use((req, res, next) => {
    console.log(config)
    var remote_ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    if(config.logs == true) {
        console.log('Logs disabled [Soon!]')
    }
    if (config.protection !== true) {
        next();
        return;
    }
    const currentTime = Date.now();
    requestCounts[remote_ip] = requestCounts[remote_ip] || [];
    requestCounts[remote_ip].push(currentTime);
    if (!config.domains.includes(req.headers.host) || config.ip_block.includes(req.headers['x-forwarded-for'] || req.connection.remoteAddress) || requestCounts[remote_ip].filter(time => currentTime - time < protection_config.rate_requests_time * 1000).length >= protection_config.rate_requests) {
        return res.status(403).end(`Blocked at ${config.name}`);
    }
    next();
});

WebKingExpress.use(express.static("public"));

WebKingExpress.listen(config.port, () => {
    console.log(`WebKing listening on port ${config.port}`)
})