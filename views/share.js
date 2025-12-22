function generateLink() {
  let truck = document.getElementById("truckNumber").value;
  if (!truck) {
    alert("Enter truck number");
    return;
  }

  let link = `${window.location.origin}/track.html?truck=${truck}`;
  document.getElementById("linkBox").innerHTML =
    `<a href="${link}" target="_blank">${link}</a>`;
}