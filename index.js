const cluster = require("cluster");
const numCPUs = require("os").cpus().length;
const express = require("express");
const fs = require("fs");
const os = require("os");

const WebKingExpress = express();
const requestCounts = {};

var config = {
    port: 80, // host port
    name: "WebKing Shield",
    protection: true,
    client_ssl: false,
    max_packet: 200,
    domains: [],
    ip_block: [],
};

var protection_config = {
    rate_requests: 8,
    rate_requests_time: 1,
};

fs.readFile("./config/domains.txt", "utf-8", (err, data) => {
    config.domains = data.split(os.EOL);
});
fs.readFile("./config/ipblocks.txt", "utf-8", (err, data) => {
    config.ip_block = data.split(os.EOL);
});

WebKingExpress.use(express.json());

WebKingExpress.use((req, res, next) => {
    var remote_ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
    var remote_packet = JSON.stringify(req.body).length;
    if (config.client_ssl == true) {
        if (!req.secure) {
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
    if (
        !config.domains.includes(req.headers.host) ||
        remote_packet > config.max_packet ||
        config.ip_block.includes(req.headers["x-forwarded-for"] || req.connection.remoteAddress) ||
        requestCounts[remote_ip].filter((time) => currenttime - time < protection_config.rate_requests_time * 1000).length >= protection_config.rate_requests
    ) {
        return res.status(403).end(`Blocked at ${config.name}`);
    }
    next();
});

WebKingExpress.use(express.static("public"));

if (cluster.isMaster) {
    console.log(`Master ${process.pid} is running`);
    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }
    cluster.on("exit", (worker, code, signal) => {
        console.log(`worker ${worker.process.pid} died`);
    });
} else {
    WebKingExpress.listen(config.port, () => {
        console.log(`Worker ${process.pid} started WebKing listening on port ${config.port}`);
    });
}
