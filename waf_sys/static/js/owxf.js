function openDeleteModal(clientName, clientId) {
    document.getElementById("deleteModal").classList.remove("hidden");
    document.getElementById("clientName").innerText = clientName;
    document.getElementById("deleteForm").action = `/customers/delete/${clientId}`;
}

function closeDeleteModal() {
    document.getElementById("deleteModal").classList.add("hidden");
}
