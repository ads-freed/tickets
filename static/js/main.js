// Initialize SocketIO client for realtime notifications
var socket = io();

// Listen for ticket events (creation, reply, etc.)
socket.on('ticket_event', function(data) {
  // For example, show a notification popup or update notification icons
  console.log("Ticket Event:", data);
  // You could integrate a notification library here
});

// Listen for private messages notifications
socket.on('private_message', function(data) {
  console.log("Private Message:", data);
  // Update UI for private messages as needed
});
