/**
 * Fortress // Password Generator Module
 */

const GENERATOR_WORDS = [
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", 
    "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango", 
    "uniform", "victor", "whiskey", "xray", "yankee", "zulu", "anchor", "beacon", "citadel", 
    "domain", "empire", "falcon", "glacier", "horizon", "island", "journey", "knight", "legend", 
    "monarch", "nebula", "oasis", "pinnacle", "quasar", "radar", "summit", "tempest", "vortex", 
    "wildfire", "zenith", "crystal", "shadow", "winter", "summer", "autumn", "spring", "galaxy", 
    "planet", "cosmic", "quantum", "stellar", "matrix", "aurora", "breeze", "canyon", "forest", 
    "harbor", "marble", "safari", "valley", "zephyr"
];

const CONSONANTS = "bcdfghjklmnpqrstvwxyz";
const VOWELS = "aeiou";

document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const typeButtons = document.querySelectorAll('.gen-type-btn');
    const lengthSlider = document.getElementById('gen-length-slider');
    const lengthVal = document.getElementById('gen-length-val');
    const sliderLabel = document.getElementById('slider-label-text');
    const charRulesGrid = document.getElementById('char-rules-grid');
    
    const uppercaseCheck = document.getElementById('gen-uppercase');
    const lowercaseCheck = document.getElementById('gen-lowercase');
    const numbersCheck = document.getElementById('gen-numbers');
    const symbolsCheck = document.getElementById('gen-symbols');
    
    const resultBox = document.getElementById('generated-password-value');
    const copyBtn = document.getElementById('btn-copy-gen');
    const generateBtn = document.getElementById('btn-trigger-generate');

    let generatorType = 'random'; // 'random', 'passphrase', 'pronounceable'

    // Configure slider based on selection
    function configureSlider(type) {
        if (type === 'random') {
            sliderLabel.textContent = "Length";
            lengthSlider.min = "6";
            lengthSlider.max = "64";
            lengthSlider.value = "16";
            lengthVal.textContent = "16";
            charRulesGrid.style.display = "grid";
        } else if (type === 'passphrase') {
            sliderLabel.textContent = "Number of Words";
            lengthSlider.min = "3";
            lengthSlider.max = "10";
            lengthSlider.value = "4";
            lengthVal.textContent = "4";
            charRulesGrid.style.display = "none"; // Checklist rules not applicable to words
        } else if (type === 'pronounceable') {
            sliderLabel.textContent = "Length";
            lengthSlider.min = "6";
            lengthSlider.max = "30";
            lengthSlider.value = "12";
            lengthVal.textContent = "12";
            charRulesGrid.style.display = "grid";
        }
    }

    // Toggle Generator Type
    typeButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            typeButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            generatorType = btn.getAttribute('data-type');
            configureSlider(generatorType);
            triggerGenerate();
        });
    });

    // Slider listener
    lengthSlider.addEventListener('input', () => {
        lengthVal.textContent = lengthSlider.value;
        triggerGenerate();
    });

    // Option checkboxes listeners
    [uppercaseCheck, lowercaseCheck, numbersCheck, symbolsCheck].forEach(chk => {
        chk.addEventListener('change', triggerGenerate);
    });

    // Generate CTA button
    generateBtn.addEventListener('click', triggerGenerate);

    // Copy to clipboard
    copyBtn.addEventListener('click', () => {
        const text = resultBox.textContent;
        if (text === "Generating..." || !text) return;
        
        navigator.clipboard.writeText(text).then(() => {
            showToast("Password copied to clipboard!");
        }).catch(err => {
            console.error("Failed to copy password: ", err);
        });
    });

    // Core Generation Director
    function triggerGenerate() {
        const length = parseInt(lengthSlider.value);
        let password = "";

        if (generatorType === 'random') {
            password = generateRandomPassword(length, {
                upper: uppercaseCheck.checked,
                lower: lowercaseCheck.checked,
                numbers: numbersCheck.checked,
                symbols: symbolsCheck.checked
            });
        } else if (generatorType === 'passphrase') {
            password = generatePassphrase(length);
        } else if (generatorType === 'pronounceable') {
            password = generatePronounceable(length, {
                upper: uppercaseCheck.checked,
                numbers: numbersCheck.checked
            });
        }

        resultBox.textContent = password || "(Choose at least one option)";
    }

    // Initial load generation
    triggerGenerate();
});

/**
 * Crypotgraphically secure index selection
 */
function secureRandomInt(max) {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    return array[0] % max;
}

/**
 * Custom complex generator
 */
function generateRandomPassword(length, rules) {
    const upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lowerChars = "abcdefghijklmnopqrstuvwxyz";
    const numberChars = "0123456789";
    const symbolChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    let pool = "";
    let guaranteed = [];

    if (rules.upper) {
        pool += upperChars;
        guaranteed.push(upperChars[secureRandomInt(upperChars.length)]);
    }
    if (rules.lower) {
        pool += lowerChars;
        guaranteed.push(lowerChars[secureRandomInt(lowerChars.length)]);
    }
    if (rules.numbers) {
        pool += numberChars;
        guaranteed.push(numberChars[secureRandomInt(numberChars.length)]);
    }
    if (rules.symbols) {
        pool += symbolChars;
        guaranteed.push(symbolChars[secureRandomInt(symbolChars.length)]);
    }

    if (pool.length === 0) return "";

    let password = [...guaranteed];
    const fillLength = length - guaranteed.length;

    for (let i = 0; i < fillLength; i++) {
        password.push(pool[secureRandomInt(pool.length)]);
    }

    // Shuffle password array cryptographically
    for (let i = password.length - 1; i > 0; i--) {
        const j = secureRandomInt(i + 1);
        [password[i], password[j]] = [password[j], password[i]];
    }

    return password.join('');
}

/**
 * Generate passphrase matching joined dictionary words
 */
function generatePassphrase(wordCount) {
    let words = [];
    for (let i = 0; i < wordCount; i++) {
        words.push(GENERATOR_WORDS[secureRandomInt(GENERATOR_WORDS.length)]);
    }
    return words.join('-');
}

/**
 * Pronounceable password generator alternating vowel/consonant syllables
 */
function generatePronounceable(length, rules) {
    let password = "";
    let useConsonant = secureRandomInt(2) === 0;

    for (let i = 0; i < length; i++) {
        if (useConsonant) {
            password += CONSONANTS[secureRandomInt(CONSONANTS.length)];
        } else {
            password += VOWELS[secureRandomInt(VOWELS.length)];
        }
        useConsonant = !useConsonant;
    }

    // Inject capitalization if uppercase checked
    if (rules.upper) {
        password = password.charAt(0).toUpperCase() + password.slice(1);
        // Randomly capitalize a middle letter to add complexity
        const midIdx = Math.floor(length / 2);
        password = password.slice(0, midIdx) + password.charAt(midIdx).toUpperCase() + password.slice(midIdx + 1);
    }

    // Append numerical digits if checked (e.g. replacing a character or adding suffix)
    if (rules.numbers) {
        const suffix = secureRandomInt(100).toString().padStart(2, '0');
        password = password.substring(0, length - 2) + suffix;
    }

    return password;
}
