const Decoder  = require("cap").decoders;

module.exports = {
    
    // Network Information
    MAX_TCP_SIZE: 67107840,
    PROTOCOL: Decoder.PROTOCOL,

    // Language
    LANG: "ES",
    HABBOPATH: {
        "ES": "game-es.habbo.com"
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
        DISABLED: 0,
        ENABLED: 1
    }
};