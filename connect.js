"use strict";

// https://github.com/Rob--/memoryjs

// My Includes
const {HABBOPATH, LANG, PROTOCOL, MAX_TCP_SIZE} = require("./globals");
const Analyzer = require("./analyze");
// Node Includes
const Cap      = require("cap").Cap;
const Decoder  = require("cap").decoders;
//const Crypto   = require("crypto");
const Packet  = require("./packet");

const DNS = require("dns");

// TODO: Split both into their js file
/* WebPage Run */
const express = require("express");
const app = express();
app.use(express.static("public"));
app.set("port", process.env.PORT || 8000);

const server = app.listen(app.get("port"));
const io = require("socket.io").listen(server);

io.on("connection", socket => {

    const Main = new Analyzer(socket);

    /* Habbo Connection */
    DNS.lookup(HABBOPATH[LANG], function(err, addr, family){
        if(err !== null){ console.error(err); return; }

        console.log(`Connected to habbo with address: ${addr}`);
        // Enum
        const Capturer = new Cap();

        // Localhost
        const server = Cap.findDevice("192.168.1.90");

        // https://api.harble.net/messages/{Production}.json

        const buffer = Buffer.alloc(MAX_TCP_SIZE);

        const link = Capturer.open(
            server, 
            `tcp and (dst host ${addr} or src host ${addr})`,
            MAX_TCP_SIZE,
            buffer
        );

        // Force to although the buffer is not filled (bc: Windows)
        Capturer.setMinBytes && Capturer.setMinBytes(0);

        const ip_protocol = (packet_header, truncated) => {
            const new_packet = new Packet(Main);

            switch(packet_header.info.protocol){
                case PROTOCOL.IP.TCP: new_packet.tcp(buffer, packet_header); break;
                case PROTOCOL.IP.UDP: new_packet.udp(buffer, packet_header); break;
            }

            if(!new_packet.empty()){
                Main.analyze(new_packet);
            }
        };

        const ethernet_protocol = (protocol, truncated) => {
            switch(protocol.info.type){
                case PROTOCOL.ETHERNET.IPV4: ip_protocol(Decoder.IPV4(buffer, protocol.offset), truncated); break;
            }
        }


        Capturer.on("packet", function(bytes, truncated) {
            if(link !== 'ETHERNET') return;
            ethernet_protocol(Decoder.Ethernet(buffer), truncated);
        });

    });

});