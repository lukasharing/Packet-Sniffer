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

const SMAP = (new Array(0xFF)).fill(false);
SPECIAL.forEach(i => SMAP[i] = true);

module.exports = class Packet{

	constructor(parent, buffer = []){
		this.analyzer = parent;

		/* Port */
		this.src_port = -1;
		this.dst_port = -1;
		/* Host */
		this.src_host = -1;
		this.dst_host = -1;
		
		this.uint8_packet = Buffer.from(buffer);
		this.length = buffer.length;

    };

	merge(packet){
		const merged = new Packet(this.parent);
		// Source Information
		merged.src_port = packet.src_port;
		merged.dst_port = packet.dst_port;
		// Host Information
		merged.src_host = packet.src_host;
		merged.dst_host = packet.dst_host;
		// Data information
		merged.uint8_packet = this.uint8_packet.concat(packet.uint8_packet);
		merged.length = this.length + packet.length;
		return merged;
	}

	empty(){ return (this.length <= 0); };
    mine(){ return (this.dst_port === 30000); };
    header(){ return this.short(4); };
	information(){
		if(this.analyzer.hotel_version === "") return;

		return (this.mine() ? this.analyzer.outgoing_packet_id : this.analyzer.incoming_packet_id)[this.header()];
	};

	// TCP uses BE, but I don't know the content
	boolean(i){ return (this.uint8_packet.readUInt8(i) != 0); };
	byte(i){ return this.uint8_packet.readUInt8(i); };
	short(i){ return this.uint8_packet.readUInt16BE(i); };
	integer(i){ return this.uint8_packet.readInt32BE(i); };
	long(i){ return this.uint8_packet.readUInt64BE(i);  };
	string(i, l){ return this.uint8_packet.subarray(i, i + l).toString("latin1"); };

	tcp(buffer, packet_received){
		// Host
		this.src_host = packet_received.info.srcaddr;
		this.dst_host = packet_received.info.dstaddr;

		// Decode with TCP algorithm
		const tcp = Decoder.TCP(buffer, packet_received.offset);

		// Port
		this.src_port = tcp.info.srcport;
		this.dst_port = tcp.info.dstport;

		// Encrypted
		this.is_encrypted = false;

		// TCP Package Size (Total - Header1 - Header2)
		this.length = packet_received.info.totallen - packet_received.hdrlen - tcp.hdrlen;

		// Pointer to TCP Segment
		const start_offset = tcp.offset;
		const end_offset = tcp.offset + this.length;
		
		// Packet Buffer
		this.uint8_packet = buffer.subarray(start_offset, end_offset);
	};

	// Not used
	udp(buffer, packet_received){};

	// Check if a package has a certain structure:
	// 1. 's' -> String
	// 2. 'i' -> Integer
	// 3. 'u' -> uShort
	// 4. 'b' -> byte
	has_structure(...types){

		// We start at index 6 because: 
		// we know that it always starts with a packet id (Integer) + padding.
		let index = 6;

        types.forEach(type => {
			if(index >= this.length) return false;

			switch(type){
				// String: 2 bytes + Content, [length, length, content....]
				case 's':
					// Check If we can read the string Length
					if(index + 2 >= this.length) return false;
					index += 2 + this.short(index);
				break;
				// Integer: 4 bytes, [int, int, int, int]
				case 'i': index += 4;                         break;
				// Short: 2 bytes, [short, short]
				case 'u': index += 2;                         break;
				// Byte: 1 bytes, [Byte]
				case 'b': index += 1;                         break;
			}

		});
		
		// If the position if the pointer reached exactly the end of the packet.
		// There could be cases where this can give true but have a wrong structure.
		return index == this.length;
	};
	
	// Converts the package into array given a structure
	toArray(...types){
		if(!this.has_structure('s', 's', 'i', 'i')) return;

		// As before, ingnore the index of the package
		let index = 6;
		let result = new Array();
        types.forEach(type => {
			switch(type){
				// String: 2 bytes + Content, [length, length, content....]
				case 's':
					result.push(this.string(index + 2, this.short(index)));
					index += 2 + this.short(index);
				break;
				// Integer: 4 bytes, [int, int, int, int]
				case 'i':
					result.push(this.integer(index));
					index += 4;
				break;
				// Short: 2 bytes, [short, short]
				case 'u':
					result.push(this.short(index));
					index += 2;
				break;
				// Byte: 1 bytes, [Byte]
				case 'b':
					result.push(this.byte(index));
					index += 1;
				break;
			}
		});
		
		return result;
    };

	toString(){
		if(this.length < 6) return "Wrong Package Size";
		
		let result = "";

		const id = this.header();
		const info = this.information();

		result += this.mine() ? "Incoming" : "Outgoing";
		result += (info === undefined) ? `[${id}]` : `[${info.name}]{${info.hash}}`;
		
		//result += `\n${Array.from(this.uint8_packet)}`;
		result += `\n${Array.from(this.uint8_packet).map(e => SMAP[e] ? `[${e}]` : Buffer.from([e]).toString("latin1")).join('')}`;

		return result;
		
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