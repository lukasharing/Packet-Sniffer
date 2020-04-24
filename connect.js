"use strict";

// My Includes
const {HABBOPATH, LANG, PROTOCOL, MAX_TCP_SIZE} = require("./globals");
const Analyzer = require("./analyze");
// Node Includes
const Cap      = require("cap").Cap;
const Decoder  = require("cap").decoders;
//const Crypto   = require("crypto");
const Packet  = require("./packet");


const Main = new Analyzer();




// Enum
const Capturer = new Cap();

// Localhost
const server = Cap.findDevice("192.168.1.90");

// Device List
// TODO: Check each ip and try to find who is connected to Habbo.es
//console.log(Cap.deviceList().map(r => r.addresses));

// https://api.harble.net/messages/{Production}.json

const buffer = Buffer.alloc(MAX_TCP_SIZE);

const link = Capturer.open(
    server, 
    `tcp and (dst host ${HABBOPATH[LANG].host} or src host ${HABBOPATH[LANG].host})`,
    MAX_TCP_SIZE,
    buffer
);

// Force to although the buffer is not filled (bc: Windows)
Capturer.setMinBytes && Capturer.setMinBytes(0);

const ip_protocol = (packet_header, truncated) => {
	const new_packet = new Packet();

    switch(packet_header.info.protocol){
        case PROTOCOL.IP.TCP: new_packet.tcp(buffer, packet_header); break;
        case PROTOCOL.IP.UDP: new_packet.udp(buffer, packet_header); break;
	}

	if(!new_packet.corrupted()){
		console.log(new_packet.toString());
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