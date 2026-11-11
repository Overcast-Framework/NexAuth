window.showModal = (id) => {
    document.getElementById(id)?.showModal();
};

window.closeModal = (id) => {
    document.getElementById(id)?.close();
};