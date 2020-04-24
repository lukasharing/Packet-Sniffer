const Decoder  = require("cap").decoders;

module.exports = {
    
    // Network Information
    MAX_TCP_SIZE: 67107840,
    PROTOCOL: Decoder.PROTOCOL,

    // Language
    LANG: "ES",
    HABBOPATH: {
        "ES": {
            host: ["52.5.80.70", "52.73.39.247"][1],
            port: 30000
        }
    },

    // Steps
    STEPS: {
        HOTEL_VERSION: 0,
        KEY_DECRYPTION: 1,
    },

    // Queue Reading
    QUEUE: {
        SKIP: 0,
        WAIT: 1
    },

    // Cache
    CACHE: {
        DISABLE: 0,
        ENABLE: 1
    }
};