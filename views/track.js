const params = new URLSearchParams(window.location.search);
const truckNo = params.get("truck");

if (navigator.geolocation) {
  navigator.geolocation.getCurrentPosition(
    function (position) {
      let lat = position.coords.latitude;
      let lon = position.coords.longitude;

      document.getElementById("status").innerHTML =
        `Truck Number: <b>${truckNo}</b><br>
         Latitude: ${lat}<br>
         Longitude: ${lon}`;

      let map = document.getElementById("map");
      map.style.display = "block";
      map.src = `https://www.google.com/maps?q=${lat},${lon}&output=embed`;
    },
    function () {
      document.getElementById("status").innerHTML =
        "Location permission denied";
    }
  );
} else {
  document.getElementById("status").innerHTML =
    "Geolocation not supported";
}