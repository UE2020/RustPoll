async function sha256(message) {
    // encode as UTF-8
    const msgBuffer = new TextEncoder().encode(message);

    // hash the message
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);

    // convert ArrayBuffer to Array
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    // convert bytes to hex string                  
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}


function sanitize(string) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        "/": '&#x2F;',
    };
    const reg = /[&<>"'/]/ig;
    return string.replace(reg, (match) => (map[match]));
}

function logout() {
    localStorage.removeItem('name');
    localStorage.removeItem('password_hash');
}

async function isLoggedIn() {
    let username = localStorage.getItem('name');
    let password = localStorage.getItem('password_hash');
    if (!username || !password) {
        return false;
    }
    return await fetch(`/api/login`, {
        method: "POST",
        headers: {
            "Content-type": "application/json",
            "accept": "application/json"
        },
        body: JSON.stringify({
            name: username,
            password_hash: password
        })
    }).then(r => {
        if (r.status != 200) {
            logout();
            return false;
        } else {
            return true;
        }
    });
}

function verify() {
    console.log('verifying credentials');
    let username = localStorage.getItem('name');
    let password = localStorage.getItem('password_hash');
    if (!username || !password) {
        console.log("No username or password");
        document.getElementById('logoutContainer').style.display = "none";
        logout();
        return;
    }
    fetch(`/api/login`, {
        method: "POST",
        headers: {
            "Content-type": "application/json",
            "accept": "application/json"
        },
        body: JSON.stringify({
            name: username,
            password_hash: password
        })
    }).then(r => {
        if (r.status != 200) {
            document.getElementById('logoutContainer').style.display = "none";
            logout();
        } else {
            document.getElementById('logoutContainer').style.display = "block";
            document.getElementById('logoutText').innerHTML += "Logout (logged in as " + sanitize(username) + ")";
        }
    });
}

function docReady(fn) {
    // see if DOM is already available
    if (document.readyState === "complete" || document.readyState === "interactive") {
        // call on next available tick
        setTimeout(fn, 1);
    } else {
        document.addEventListener("DOMContentLoaded", fn);
    }
}    


docReady(verify);