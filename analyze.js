// Includes
const {STEPS, QUEUE, CACHE} = require("./globals");
const Packet  = require("./packet");

const fetch = require("node-fetch");
const api_harble = version => `https://api.harble.net/messages/${version}.json`;

module.exports = class Analyzer{

    constructor(_socket){

        this.socket = _socket;

        this.hotel_version_regex = new RegExp("PRODUCTION-([0-9]{12})-([0-9]{9})");
        this.hotel_version = "PRODUCTION-202004202209-858580280"; // Dummy, remove it!
        
        // Id- Hash - Name -> Table
        this.incoming_packet_id = {};
        this.outgoing_packet_id = {};

        // Stack
        this.cache_queue = [];
        this.cache_status = CACHE.ENABLED;
        this.cache_max_size = 10;

        this.packets_queue = [];
        this.queue_mode = QUEUE.SKIP;

        // Current Step
        this.current_step = STEPS.KEY_DECRYPTION; //STEPS.HOTEL_VERSION;
        this.hotel_version = "";
    };

    // Work asynchronously so we keep tracking more packets
    async analyze_hotel_version_packet(packet){
        try{
            const structure = packet.toArray('s', 's', 'i', 'i');
            if(structure instanceof Array){
                // Check if the first string has the following content
                if(!/^PRODUCTION-[0-9]{12}-[0-9]{9}$/.test(structure[0])) return;

                this.hotel_version = structure[0];

                this.queue_mode = QUEUE.WAIT;
                const appi_path = api_harble(this.hotel_version);
                console.log(`Fetching Hash Table from: ${appi_path}`);
                await fetch(appi_path).then(async response => {
                    if(!response.ok) throw Error(response.statusText);
                    // Fetch Result to the table
                    await response.json().then(result => {
                        // Habbo Incoming Packet Information
                        result.Incoming.forEach(info => {
                            this.incoming_packet_id[info.Id] = {
                                name: info.Name,
                                hash: info.Hash
                            };
                        });
                        // Habbo Outgoing Packet Information
                        result.Outgoing.forEach(info => {
                            this.outgoing_packet_id[info.Id] = {
                                name: info.Name,
                                hash: info.Hash
                            };
                        });

                        // Next Step
                        this.current_step = STEPS.KEY_DECRYPTION;
                        // Start Analyzing
                        this.queue_mode = QUEUE.SKIP;

                        this.analyze(null);
                    });
                });
            }
        }catch(error) {
            console.error(`Version Fetch: ${error}`);
        }
    };

    analyze_key_decryption_packet(packet){
        return;
    };

    analyze(packet){
        // Ignore Case
        if(packet === null && this.packets_queue.length === 0) return;

        // If WAIT mode, keep adding elements, ignore the analysis
        if(this.queue_mode === QUEUE.WAIT){
            this.packets_queue.push(packet);
            return;
        }

        // If SKIP Mode, check if queue is not empty
        if(this.queue_mode === QUEUE.SKIP && this.packets_queue.length > 0){
            if(packet !== null){
                this.packets_queue.push(packet);
            }
            packet = this.packets_queue.shift();
        }
        
        switch(this.current_step){

            case STEPS.HOTEL_VERSION : this.analyze_hotel_version_packet(packet); break;
            //case STEPS.KEY_DECRYPTION: this.analyze_key_decryption_packet(packet); break;

        }

        if(this.current_step != STEPS.HOTEL_VERSION){
            this.emmit(packet);
        }

        // Cache Last Packet
        if(this.cache_status == CACHE.ENABLED){
            this.cache_queue.push(packet);
            // Just take out last element
            if(this.cache_queue.length >= this.cache_max_size){
                this.cache_queue.shift();
            }
        }

        // If there is still elements in the queue, keep analyzing
        if(this.packets_queue.length > 0){
            this.analyze(null);
        }

    };

    combine_until(packet_name){

        // Ignore Last
        const idx = this.cache_queue.length - 2;
        const to_merge = [];
        to_merge.unshift(this.cache_queue[idx]);

        let last_information = to_merge[0].information();
        while(last_information == null || (last_information != null && last_information.name != packet_name)){
            to_merge.unshift(this.cache_queue[idx]);
            last_information = to_merge[0].information();
        }
        this.cache_queue;

    };

    emmit(packet){
        if(packet === null) return;
        // 
        if(null){}

        console.log("------------------");
        if(packet.mine()){
        console.log(packet.toString());
        //if( a != -1 && b != -1 && ((a == (b + 1)) || (b == (a + 1)))){
            //console.log(packet.toString());
            //console.log(packet.mine() ? "Mine" : "Server", packet.length);

        //}
        
        //console.log("------------------");
        /*switch(packet_info.name){
            case "RoomUsers":

                console.log("Fetch");
        this.cache_queue = [];
                const packet = this.combine_until("RoomRelativeMap");
                console.log(packet.toString());
                //socket.emit("RoomRelativeMap", packet);

            break;
        };*/



    }

}

2056

4,67,225,99,60,216,210,121,168,32