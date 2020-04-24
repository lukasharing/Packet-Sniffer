"use strict";
// Includes
const {HABBOPATH, LANG, CACHE} = require("./globals");
const Decoder  = require("cap").decoders;

const SPECIAL = [
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
	20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
	30, 31,
	91, 93,
	123, 125, 127,
	161, 162, 163, 164, 165, 166, 167, 168, 169,
	170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
	180, 181, 182, 183, 184, 185, 186, 187, 188, 189,
	190, 191, 192, 193, 194, 195, 196, 197, 198, 199,
	200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
	210, 211, 212, 213, 214, 215, 216, 217, 218, 219,
	220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
	230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
	240, 241, 242, 243, 244, 245, 246, 247, 248, 249,
	250, 251, 252, 253, 254, 255
];

module.exports = class Packet{

	constructor(buffer = null){

		/* Port */
		this.src_port = -1;
		this.dst_port = -1;
		/* Host */
		this.src_host = -1;
		this.dst_host = -1;
		
		this.uint8_packet = buffer;
		this.length = buffer === null ? -1 : buffer.length;

    };
    
	corrupted(){ return (this.uint8_packet === null); };
    mine(){ return (this.dst_host === HABBOPATH[LANG].host); };
    header(){ return this.short(4); };

	// TCP uses BE, but I don't know the content
	boolean(i){ return (this.uint8_packet.readUInt8(i) != 0); };
	byte(i){ return this.uint8_packet.readUInt8(i); };
	short(i){ return this.uint8_packet.readUInt16BE(i); };
	integer(i){ return this.uint8_packet.readInt32BE(i); };
	long(i){ return this.uint8_packet.readUInt64BE(i);  };
	string(i, l){ return this.uint8_packet.subarray(i, i + l).toString("latin1"); };

	tcp(buffer, packet_received){
		
		// Packet Size - Header Size
		const tcp_body_size = packet_received.info.totallen - packet_received.hdrlen;
		
		// Host
		this.src_host = packet_received.info.srcaddr;
		this.dst_host = packet_received.info.dstaddr;

		// Decode with TCP algorithm
		const decoded = Decoder.TCP(buffer, packet_received.offset);

		// Port
		this.src_port = decoded.info.srcport;
		this.dst_port = decoded.info.dstport;

		this.length = tcp_body_size;
		
		// Encrypted
		this.is_encrypted = false;
		
		// If empty, just ignore it.
		if(tcp_body_size === 0) return;

		// Packet Buffer
		this.uint8_packet = buffer.subarray(
			packet_received.offset + decoded.hdrlen,
			packet_received.offset + tcp_body_size
		);

		this.decode();
	};

	// Not used
	udp(buffer, packet_received){};


	decode(){
		if(this.has_structure('s', 'b')){
			this.string()
		}
	};

	// Check if a package has a certain structure:
	// Example s,i,b
	// Types:
	// 1. 's' -> String
	// 2. 'i' -> Integer
	// 3. 'u' -> uShort
	// 4. 'b' -> byte
	has_structure(...types){

		let index = 6;
        types.forEach(type => {

			if(index >= this.length) return false;

			switch(type){
				case 's': index += this.short(index) + 2; break; // Read String (2 bytes, 1 byte for type and 1 byte for string length)
				case 'i': index += (4);                   break; // Read Integer (4 bytes, 1 for the type, 3 bytes for the integer)
				case 'u': index += (2);                   break; // Read uShort (Byte) (2 bytes)
				case 'b': index += (1);                   break; // Read boolean (1 Byte)
			}

		});
		
		// We reach the end, check if type is equal to the specified.
		return index == (this.length - 1);
    };
	


	toString(){
		return `${this.mine() ? "Outgoing" : "Incoming"}[${this.header()}] <- `+
			//`${Array.from(this.uint8_packet)}\n`+
			`${Array.from(this.uint8_packet).map(e => SPECIAL.indexOf(e) >= 0 ? `[${e}]` : Buffer.from([e]).toString("latin1")).join('')}`;
		;
	};

	toExpression(){
		let result = `{l}{u:${this.header()}}`;

		const mask = new Array(6).fill(true);

		for(let i = 6; i < this.length - 1; ++i){
			let string_len = this.short(i);
			let next = false;
			if(
				(string_len >= 0 && string_len < 3) ||
				(string_len > this.length - i - 2)
			){

				for(let j = i; j < string_len + i + 2 && !next; ++j){
					next = mask[j];
				}

				for(let j = i + 2; j < string_len + i + 2 && !next; ++j){
					next = (this.byte(j) >= 0 && this.byte(j) < 6);
				}

				if(
					!next &&
					i + 2 + string_len >= this.length - 3 ||
                    (this.byte(i + 2 + string_len) >= 0 && this.byte(i + 2 + string_len) < 6)
				){

					for(let j = i; j < i + 2 + string_len; ++j){
						mask[j] = true;
					}

					result += `{s:${this.string(i + 2, this.byte(i))}}`;

					i += (1 + string_len);
				}
			}
		}

		return result;
	};



}