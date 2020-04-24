// Includes
const {STEPS, QUEUE, CACHE} = require("./globals");
const Packet  = require("./packet");

const fetch = require("node-fetch");
const fetch_api_harble = version => fetch(`https://api.harble.net/messages/${version}.json`);

module.exports = class Analyzer{

    constructor(){

        this.hotel_version_regex = new RegExp("PRODUCTION-([0-9]{12})-([0-9]{9})");
        this.hotel_version = "PRODUCTION-202004202209-858580280"; // Dummy, remove it!
        this.tcp_translation_table = null;

        this.cache_queue = [];
        this.cache_status = CACHE.ENABLE;
        this.cache_max_size = 5;

        this.packets_queue = [];
        this.queue_mode = QUEUE.SKIP;

        // Current Step
        this.current_step = STEPS.HOTEL_VERSION;
    };

    analyze_hotel_version_packet(packet){

        //console.log(packet.toString());
        //console.log(packet.header());
        //console.log(packet.has_structure('s', 's', 'i', 'i'));
        
        if(false){
            const self = this;

            this.queue_mode = QUEUE.WAIT;

            dummy();
            // Work asynchronously so we keep tracking more packets
            async function dummy(){
                await fetch_api_harble(self.hotel_version).then(async response => {

                    if(!response.ok) throw Error(response.statusText);

                    // Fetch Result to the table
                    await response.json().then(result => {
                        self.tcp_translation_table = result;
                        // Next Step
                        self.current_step = STEPS.KEY_DECRYPTION;

                        // Start Analyzing
                        self.queue_mode = QUEUE.SKIP;
                        self.analyze(null);
                    });

                }).catch(error => console.error(`Version Fetch: ${error}`));
            }
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
            case STEPS.KEY_DECRYPTION: this.analyze_key_decryption_packet(packet); break;

        }

        // Cache Last Packet
        if(this.cache_status == CACHE.ENABLE){
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


}