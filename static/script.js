function generatePassword() {
    // Generate a Fernet-compatible password using 32 random bytes (Base64-encoded) but this time in javascript since it's faster
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);
    const password = btoa(String.fromCharCode(...array)).slice(0, 44); // make it Fernet-safe length
    document.getElementById('password').value = password;
}

async function encrypt() {
    const text = document.getElementById('text').value;
    const password = document.getElementById('password').value.trim();

    if (!password) {
        alert("Please enter or generate a password first.");
        return;
    }

    const response = await fetch('/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, password })
    });

    const result = await response.json();
    document.getElementById('output').textContent = result.result || result.error;
}

async function decrypt() {
    const text = document.getElementById('text').value;
    const password = document.getElementById('password').value.trim();

    if (!password) {
        alert("Please enter or generate a password first.");
        return;
    }

    const response = await fetch('/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, password })
    });

    const result = await response.json();
    document.getElementById('output').textContent = result.result || result.error;
}

function copy(id) {
    var copyText = document.getElementById(id);

    copyText.select();
    copyText.setSelectionRange(0, 99999);

    navigator.clipboard.writeText(copyText.value);
}
