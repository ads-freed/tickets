// Initialize Socket.IO client for realtime notifications
var socket = io();

// Notification counters
var ticketNotifCount = 0;
var privateNotifCount = 0;

// Configure Toastr options
toastr.options = {
  "positionClass": "toast-top-right",
  "timeOut": "5000",
  "progressBar": true
};

// Listen for ticket events (ticket creation, reply, etc.)
socket.on('ticket_event', function(data) {
  console.log("Ticket Event:", data);
  // Increase the notification count for ticket events
  ticketNotifCount++;
  updateNotificationBadge();

  // Display a toast notification for ticket events
  toastr.info(
    `Ticket ${data.ticket_number} ${data.action} at ${data.created_at || data.updated_at}`,
    'Ticket Update'
  );
});

// Listen for private message notifications
socket.on('private_message', function(data) {
  console.log("Private Message:", data);
  // Increase the notification count for private messages
  privateNotifCount++;
  updateNotificationBadge();

  // Display a toast notification for private messages
  toastr.success(
    `${data.sender} sent a new message at ${data.created_at}`,
    'New Private Message'
  );
});

// Update notification badge function
function updateNotificationBadge() {
  var totalNotifs = ticketNotifCount + privateNotifCount;
  if (totalNotifs > 0) {
    $('#notifBadge').text(totalNotifs).show();
  } else {
    $('#notifBadge').hide();
  }
}

// Optionally, reset notifications when the notification icon is clicked
$('#notifIcon').on('click', function() {
  ticketNotifCount = 0;
  privateNotifCount = 0;
  updateNotificationBadge();
});
