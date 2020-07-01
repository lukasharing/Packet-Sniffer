const socket = io();

const canvas = document.getElementById("habbo");
const size = canvas.width = canvas.height = Math.min(window.innerHeight, window.innerWidth) * 0.8;


socket.on("mapa", function(data){

    console.log(data);

});