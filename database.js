/**
 * Fortress // Secure Database & Vault Simulator
 */

// Simulated In-Memory Database
let SIMULATED_DB = [];

document.addEventListener('DOMContentLoaded', () => {
    const registerBtn = document.getElementById('btn-vault-register');
    const usernameInput = document.getElementById('vault-username');
    const passwordInput = document.getElementById('vault-password');
    const dbTbody = document.getElementById('db-inspect-tbody');
    const dbEmptyRow = document.getElementById('db-empty-row');
    const historySection = document.getElementById('vault-user-history');
    const historyList = document.getElementById('vault-history-list');

    // Portal Actions
    registerBtn.addEventListener('click', async () => {
        const username = usernameInput.value.trim();
        const password = passwordInput.value;

        if (!username || !password) {
            showToast("Username and Password are required!");
            return;
        }

        // Check if user already exists
        let user = SIMULATED_DB.find(u => u.username.toLowerCase() === username.toLowerCase());

        if (!user) {
            // REGISTRATION FLOW (New User)
            const salt = generateRandomHexSalt(16);
            const saltedHash = await calculateSHA256(password + salt);
            
            const newUser = {
                username: username,
                salt: salt,
                hash: saltedHash,
                history: [
                    { salt: salt, hash: saltedHash }
                ]
            };

            SIMULATED_DB.push(newUser);
            showToast(`User '${username}' registered securely!`);
            
            // Clean inputs
            passwordInput.value = "";
            
            // Render updates
            renderDatabaseTable();
            renderHistoryView(newUser);

        } else {
            // CHANGE PASSWORD FLOW (Existing User)
            
            // 1. Reuse Prevention Check
            let isReused = false;
            
            for (let i = 0; i < user.history.length; i++) {
                const hist = user.history[i];
                const testHash = await calculateSHA256(password + hist.salt);
                if (testHash === hist.hash) {
                    isReused = true;
                    break;
                }
            }

            if (isReused) {
                showToast("Security Alert: Cannot reuse last 3 passwords!");
                
                // Visual feedback indicating error
                passwordInput.classList.add('failed');
                setTimeout(() => passwordInput.classList.remove('failed'), 1000);
                return;
            }

            // 2. Generate a new salt and hash for the new password
            const newSalt = generateRandomHexSalt(16);
            const newHash = await calculateSHA256(password + newSalt);

            // Update active state
            user.salt = newSalt;
            user.hash = newHash;
            
            // Add to the front of history array, maintaining cap of 3
            user.history.unshift({ salt: newSalt, hash: newHash });
            if (user.history.length > 3) {
                user.history = user.history.slice(0, 3);
            }

            showToast(`Password updated for '${username}'!`);
            
            // Clean inputs
            passwordInput.value = "";
            
            // Render updates
            renderDatabaseTable();
            renderHistoryView(user);
        }
    });

    // Helper to generate secure random salts
    function generateRandomHexSalt(length) {
        const arr = new Uint8Array(length / 2);
        window.crypto.getRandomValues(arr);
        return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Helper to calculate SHA-256 hashes using native subtle API
    async function calculateSHA256(text) {
        const msgBuffer = new TextEncoder().encode(text);
        const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Renders the simulated database inspection grid
    function renderDatabaseTable() {
        if (SIMULATED_DB.length === 0) {
            dbEmptyRow.style.display = "table-row";
            return;
        }

        dbEmptyRow.style.display = "none";
        
        // Remove existing custom rows
        const rows = dbTbody.querySelectorAll('.custom-db-row');
        rows.forEach(r => r.remove());

        SIMULATED_DB.forEach(user => {
            const tr = document.createElement('tr');
            tr.classList.add('custom-db-row');
            
            // Shorten hash representation for tabular elegance
            const shortHash = `${user.hash.substring(0, 16)}...${user.hash.substring(48)}`;

            tr.innerHTML = `
                <td style="font-weight: bold; color: var(--primary-light);">${escapeHTML(user.username)}</td>
                <td><code>${user.salt}</code></td>
                <td title="${user.hash}"><code>${shortHash}</code></td>
            `;
            dbTbody.appendChild(tr);
        });
    }

    // Render password history indicators for reuse policy explanation
    function renderHistoryView(user) {
        historySection.style.display = "block";
        historyList.innerHTML = "";

        user.history.forEach((hist, idx) => {
            const badge = document.createElement('div');
            badge.classList.add('history-badge');
            
            const position = idx === 0 ? "Active" : `Prev #${idx}`;
            const shortHash = `${hist.hash.substring(0, 8)}...${hist.hash.substring(56)}`;

            badge.innerHTML = `<strong>${position}:</strong> ${shortHash}`;
            historyList.appendChild(badge);
        });
    }

    // Secure HTML rendering
    function escapeHTML(str) {
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }
});
