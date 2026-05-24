/**
 * Fortress // Password Strength Analyzer Module
 */

const COMMON_DICTIONARY = [
    "password", "123456", "123456789", "qwerty", "12345", "12345678", "1234", "111111", 
    "letmein", "welcome", "admin", "login", "password123", "oracle", "secret", "love", 
    "monkey", "charlie", "football", "shadow", "superman", "trustnoone", "dragon", 
    "cheeseburger", "princess", "abc123", "password1", "master", "security", "hunter"
];

document.addEventListener('DOMContentLoaded', () => {
    const pwInput = document.getElementById('password-input');
    const toggleBtn = document.getElementById('toggle-pw-visibility');
    
    // Visibility toggle
    toggleBtn.addEventListener('click', () => {
        const type = pwInput.getAttribute('type') === 'password' ? 'text' : 'password';
        pwInput.setAttribute('type', type);
        
        // Swap eye SVG state
        if (type === 'text') {
            toggleBtn.innerHTML = `
                <svg class="eye-closed" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                    <line x1="1" y1="1" x2="23" y2="23"/>
                </svg>
            `;
        } else {
            toggleBtn.innerHTML = `
                <svg class="eye-open" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                    <circle cx="12" cy="12" r="3"/>
                </svg>
            `;
        }
    });

    // Real-time analysis trigger
    pwInput.addEventListener('input', () => {
        analyzePassword(pwInput.value);
    });
});

/**
 * Calculates strength score, entropy, crack time, and checks against requirements
 * @param {string} password - The user-entered password
 */
function analyzePassword(password) {
    const length = password.length;
    
    // UI Elements
    const segments = [
        document.getElementById('seg-0'),
        document.getElementById('seg-1'),
        document.getElementById('seg-2'),
        document.getElementById('seg-3'),
        document.getElementById('seg-4')
    ];
    const verdictLabel = document.getElementById('strength-verdict-label');
    const scoreLabel = document.getElementById('strength-score-label');
    const entropyBox = document.getElementById('metric-entropy');
    const crackBox = document.getElementById('metric-crack-offline');
    const patternBox = document.getElementById('metric-patterns');
    const dictBox = document.getElementById('metric-dictionary');
    const suggestionsBox = document.getElementById('suggestions-box');
    
    // Criteria Indicators
    const critLength = document.getElementById('crit-length');
    const critUpper = document.getElementById('crit-uppercase');
    const critLower = document.getElementById('crit-lowercase');
    const critNum = document.getElementById('crit-numbers');
    const critSym = document.getElementById('crit-symbols');

    if (length === 0) {
        // Reset Visuals
        resetMeter(segments, verdictLabel, scoreLabel, entropyBox, crackBox, patternBox, dictBox, suggestionsBox);
        resetCriteria([critLength, critUpper, critLower, critNum, critSym]);
        return;
    }

    // 1. Character Pools Check
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[^a-zA-Z0-9]/.test(password);

    // Update Checklist UI
    toggleCriteria(critLength, length >= 8);
    toggleCriteria(critUpper, hasUpper);
    toggleCriteria(critLower, hasLower);
    toggleCriteria(critNum, hasNumber);
    toggleCriteria(critSym, hasSymbol);

    // Calculate Pool Size (R)
    let poolSize = 0;
    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasNumber) poolSize += 10;
    if (hasSymbol) poolSize += 33; // Standard symbols count

    // 2. Shannon Entropy Calculation: E = L * log2(R)
    const entropy = length * Math.log2(poolSize || 1);
    entropyBox.textContent = `${entropy.toFixed(2)} bits`;

    // 3. Pattern / Weakness Detections
    let patternMsg = "None";
    let patternPenalty = 0;
    
    // Repeating characters (e.g., "aaaa")
    const repeatingMatch = /(.)\1{2,}/g.exec(password);
    if (repeatingMatch) {
        patternMsg = "Repeating characters";
        patternPenalty += 1;
    }
    
    // Sequential character strings (e.g. "1234", "abcd")
    if (detectSequence(password)) {
        patternMsg = "Sequential sequence";
        patternPenalty += 1;
    }

    patternBox.textContent = patternMsg;

    // 4. Dictionary Weakness Check
    const normalizedPw = password.toLowerCase();
    const matchesDictionary = COMMON_DICTIONARY.some(word => 
        normalizedPw === word || (word.length >= 5 && normalizedPw.includes(word))
    );
    
    if (matchesDictionary) {
        dictBox.textContent = "Fail (Common)";
        dictBox.style.color = "var(--strength-0)";
    } else {
        dictBox.textContent = "Pass";
        dictBox.style.color = "var(--strength-3)";
    }

    // 5. Estimated Crack Time (Offline fast hashing: 100 Billion / sec)
    const totalCombinations = Math.pow(poolSize, length);
    const offlineHashesPerSec = 100000000000; // 10^11
    const secondsToCrack = totalCombinations / (2 * offlineHashesPerSec);
    crackBox.textContent = formatCrackTime(secondsToCrack);

    // 6. Strength Scoring Logic
    let score = 0;
    if (entropy < 28) {
        score = 0; // Very Weak
    } else if (entropy >= 28 && entropy < 45) {
        score = 1; // Weak
    } else if (entropy >= 45 && entropy < 60) {
        score = 2; // Medium
    } else if (entropy >= 60 && entropy < 80) {
        score = 3; // Strong
    } else {
        score = 4; // Very Strong
    }

    // Apply penalties
    if (matchesDictionary) {
        score = Math.max(0, score - 2);
    }
    if (patternPenalty > 0) {
        score = Math.max(0, score - 1);
    }

    // Apply absolute rules (e.g., must be 8+ chars to get beyond "Weak" unless massive entropy)
    if (length < 8) {
        score = Math.min(1, score);
    }

    // Render Strength Bar and verdicts
    updateStrengthUI(score, segments, verdictLabel, scoreLabel);

    // 7. Suggestions Builder
    const suggestions = [];
    if (length < 12) {
        suggestions.push("Increase length to 12+ characters to block offline dictionary generators.");
    }
    if (!hasUpper || !hasLower) {
        suggestions.push("Mix UPPERCASE and lowercase letters to broaden character variance.");
    }
    if (!hasNumber) {
        suggestions.push("Inject numeric digits (0-9) to disrupt pattern analysis.");
    }
    if (!hasSymbol) {
        suggestions.push("Incorporate symbols (e.g., $, !, @, %) to make dictionary expansion harder.");
    }
    if (matchesDictionary) {
        suggestions.push("This password contains common dictionary terms. Choose unique, unpredictable words.");
    }
    if (repeatingMatch) {
        suggestions.push("Avoid repeated sequences (e.g., 'aaa'). Attackers optimize for these first.");
    }
    if (patternMsg === "Sequential sequence") {
        suggestions.push("Avoid standard alphabet/number progressions (e.g. '123' or 'abc').");
    }

    if (suggestions.length === 0) {
        suggestionsBox.innerHTML = `
            <div class="suggestion-item" style="color: var(--strength-4);">
                <span class="suggestion-bullet">✓</span>
                <span>Outstanding password! Your criteria and entropy metrics exceed standards.</span>
            </div>
        `;
    } else {
        suggestionsBox.innerHTML = suggestions.map(tip => `
            <div class="suggestion-item">
                <span class="suggestion-bullet">→</span>
                <span>${tip}</span>
            </div>
        `).join('');
    }
}

/**
 * Checks for contiguous alphabet, keyboard or numerical patterns
 */
function detectSequence(password) {
    const cleanStr = password.toLowerCase();
    for (let i = 0; i < cleanStr.length - 2; i++) {
        const char1 = cleanStr.charCodeAt(i);
        const char2 = cleanStr.charCodeAt(i + 1);
        const char3 = cleanStr.charCodeAt(i + 2);
        
        // Check standard numerical/alphabetic sequencing (forward & backward)
        if ((char2 === char1 + 1 && char3 === char2 + 1) || 
            (char2 === char1 - 1 && char3 === char2 - 1)) {
            return true;
        }
    }
    return false;
}

/**
 * Resets the meter to original placeholder state
 */
function resetMeter(segments, verdict, score, entropy, crack, pattern, dict, suggestions) {
    segments.forEach(seg => {
        seg.style.background = 'transparent';
        seg.style.boxShadow = 'none';
    });
    verdict.textContent = "Awaiting Input";
    verdict.style.color = "var(--text-dim)";
    score.textContent = "0 / 4";
    entropy.textContent = "0.00 bits";
    crack.textContent = "Instant";
    pattern.textContent = "None";
    dict.textContent = "Pass";
    dict.style.color = "var(--text-muted)";
    suggestions.innerHTML = `
        <div class="suggestion-item">
            <span class="suggestion-bullet">→</span>
            <span>Type a password to receive specific strengthening recommendations.</span>
        </div>
    `;
}

/**
 * Helper to toggle criteria status styling
 */
function toggleCriteria(element, isMet) {
    if (isMet) {
        element.classList.remove('failed');
        element.classList.add('met');
    } else {
        element.classList.remove('met');
        element.classList.add('failed');
    }
}

function resetCriteria(elements) {
    elements.forEach(el => {
        el.classList.remove('met', 'failed');
    });
}

/**
 * Maps crack times to human scale description
 */
function formatCrackTime(seconds) {
    if (seconds <= 0.1) return "Instant";
    if (seconds < 60) return `${Math.ceil(seconds)} seconds`;
    
    const minutes = seconds / 60;
    if (minutes < 60) return `${Math.ceil(minutes)} minutes`;
    
    const hours = minutes / 60;
    if (hours < 24) return `${Math.ceil(hours)} hours`;
    
    const days = hours / 24;
    if (days < 365) return `${Math.ceil(days)} days`;
    
    const years = days / 365;
    if (years < 1000) return `${Math.ceil(years)} years`;
    
    const centuries = years / 100;
    if (centuries < 1000) return `${Math.ceil(centuries)} centuries`;
    
    return "Millennia";
}

/**
 * Redraw strength meter bars and neon colors
 */
function updateStrengthUI(score, segments, verdict, scoreLabel) {
    const colors = [
        'var(--strength-0)', // 0: Very Weak
        'var(--strength-1)', // 1: Weak
        'var(--strength-2)', // 2: Medium
        'var(--strength-3)', // 3: Strong
        'var(--strength-4)'  // 4: Very Strong
    ];
    
    const glows = [
        'var(--strength-0-glow)',
        'var(--strength-1-glow)',
        'var(--strength-2-glow)',
        'var(--strength-3-glow)',
        'var(--strength-4-glow)'
    ];

    const verdicts = [
        "Very Weak (Vulnerable)",
        "Weak (Unsafe)",
        "Medium (Average)",
        "Strong (Secure)",
        "Very Strong (Excellent)"
    ];

    // Reset all segments
    segments.forEach(seg => {
        seg.style.background = 'transparent';
        seg.style.boxShadow = 'none';
    });

    // Fill segments up to score + 1
    const activeColor = colors[score];
    const activeGlow = glows[score];

    for (let i = 0; i <= score; i++) {
        segments[i].style.background = activeColor;
        segments[i].style.boxShadow = `0 0 10px ${activeGlow}`;
    }

    verdict.textContent = verdicts[score];
    verdict.style.color = activeColor;
    scoreLabel.textContent = `${score} / 4`;
}
