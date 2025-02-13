let isDismissed = false;
let PROTECTED_WEBSITES = null;

const warningStyles = {
    overlay: {
        position: 'fixed',
        top: '0',
        left: '0',
        width: '100%',
        height: '100%',
        backdropFilter: 'blur(5px)',
        backgroundColor: 'rgba(0,0,0,0.7)',
        zIndex: '2147483646',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center'
    },
    modal: {
        color: 'white',
        borderRadius: '4px',
        boxShadow: '0 5px 30px rgba(0,0,0,0.4)',
        maxWidth: '600px',
        textAlign: 'center',
        position: 'relative',
        fontFamily: 'Open Sans, Arial, sans-serif'
    },
    modalHeader: {
        backgroundColor: 'black',
        height: '64px',
        borderRadius: '4px 4px 0 0',
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
        padding: '0 16px',
    },
    modalBody: {
        backgroundColor: '#B81641',
        color: 'white',
        padding: '32px',
        borderRadius: '0 0 4px 4px',
        boxShadow: '0 5px 30px rgba(0,0,0,0.4)',
        textAlign: 'center',
        position: 'relative'
    },
    warningText: {
        fontSize: '18px',
        lineHeight: '1.5',
        marginBottom: '16px'
    },
    redirectButton: {
        display: 'block',
        backgroundColor: '#1A9A4D',
        border: '1px solid rgba(255,255,255,0.3)',
        color: 'white',
        padding: '16px 32px',
        borderRadius: '4px',
        cursor: 'pointer',
        fontSize: '16px',
        fontWeight: '600',
        margin: '16px auto 0 auto',
        transition: 'background-color 0.2s'
    },
    dismissButton: {
        display: 'block',
        backgroundColor: 'inherit',
        border: '0',
        color: 'black',
        padding: '2px 4px',
        cursor: 'pointer',
        fontSize: '12px',
        margin: '16px auto 0 auto',
        transition: 'background-color 0.2s',
        textDecoration: 'underline'
    }};

function generatePhishingPatterns(domainConfig) {
    const patterns = [];
    for (const legit_host of domainConfig.known_legit) {
        const base = legit_host.replace('.', '\\.');

        patterns.push(
            new RegExp(`(${base.replace(/o/gi, '[0oø]')})`),
            new RegExp(`(${base.replace(/e/gi, '[3eé]')})`),
            new RegExp(`^${base.split('.').join('-')}\\.`),
            new RegExp(`${base}(-|_)login`),
            new RegExp(`^(www|secure|account)\\.?${base}`)
        );
    }
    return patterns;
}

function isPhishingUrl(hostname, domainConfig) {

    // remove www. prefix
    const susHost = hostname.toLowerCase().replace(/^www\./, '');

    // User has dismissed the warning for this domain
    if (domainConfig.suppress_warnings.includes(susHost) || domainConfig.known_legit.includes(susHost)) return 0;

    for (const known_scam of domainConfig.known_scams) {
        if (known_scam.includes(susHost)) return 2; // Known phishing domain
    }

    const patterns = generatePhishingPatterns(domainConfig);
    if (patterns.some(pattern => pattern.test(susHost))) return 1; // Suspicious domain

    // if the current website matches a known_legit in all but TLD it's likely a scam
    for (const legit_host of domainConfig.known_legit) {
        const legit_sld = legit_host.split('.').slice(0, -1).join('.');
        const sus_sld = susHost.split('.').slice(0, -1).join('.');
        if (legit_sld === sus_sld) return 1;
    }

    return 0; // Not a phishing domain
}

function showWarning(realDomain, phishingScore) {
    if (isDismissed || document.getElementById('phish-overlay')) return;

    // Create overlay
    // This is the div that will cover the entire page
    const overlay = document.createElement('div');
    overlay.id = 'phish-overlay';
    Object.assign(overlay.style, warningStyles.overlay);
    //

    // Create shadow root
    const shadowRoot = overlay.attachShadow({mode: 'open'});

    // Create modal
    const modal = document.createElement('div');
    Object.assign(modal.style, warningStyles.modal);
    shadowRoot.appendChild(modal);
    //

    // Create modalHeader
    const modalHeader = document.createElement('div');
    Object.assign(modalHeader.style, warningStyles.modalHeader);
    modal.appendChild(modalHeader);
    //

    // Create modalHeader imgs
    const modalHeaderLogo = document.createElement('img');
    modalHeaderLogo.src = chrome.runtime.getURL('img/OrangeFren Logo-11.webp');
    modalHeaderLogo.style.height = '32px';
    modalHeaderLogo.style.cursor = 'pointer';
    modalHeaderLogo.addEventListener('click', () => {
        window.location.href = "https://orangefren.com";
    })
    modalHeader.appendChild(modalHeaderLogo);

    const modalHeaderLogoText = document.createElement('img');
    modalHeaderLogoText.src = chrome.runtime.getURL('img/OrangeFren Logo-13.webp');
    modalHeaderLogoText.style.height = '32px';
    modalHeaderLogoText.style.cursor = 'pointer';
    modalHeaderLogoText.addEventListener('click', () => {
        window.location.href = "https://orangefren.com";
    })
    modalHeader.appendChild(modalHeaderLogoText);
    //

    // Create modalBody
    const modalBody = document.createElement('div');
    Object.assign(modalBody.style, warningStyles.modalBody);
    modal.appendChild(modalBody);
    //

    // Create warning text
    const warningText = document.createElement('div');
    Object.assign(warningText.style, warningStyles.warningText);

    if (phishingScore === 2) {
        warningText.innerHTML = `🚨 <strong>PHISHING WARNING</strong> 🚨<br>
            This website is a known impersonation of ${realDomain}`;
    } else if (phishingScore === 1) {
        warningText.innerHTML = `🚨 <strong>PHISHING SUSPECTED</strong> 🚨<br>
            This site may be impersonating ${realDomain}`;
    }
    modalBody.appendChild(warningText);
    //

    // Create redirect button
    const redirectButton = document.createElement('button');
    redirectButton.textContent = `Go to ${realDomain}`;
    Object.assign(redirectButton.style, warningStyles.redirectButton);

    redirectButton.addEventListener('mouseenter', () => {
        redirectButton.style.backgroundColor = 'rgb(18, 109, 55)';
    });
    redirectButton.addEventListener('mouseleave', () => {
        redirectButton.style.backgroundColor = warningStyles.redirectButton.backgroundColor;
    });

    redirectButton.addEventListener('click', () => {
        window.location.href = PROTECTED_WEBSITES.find(site => site.known_legit.includes(realDomain)).link;
    })
    modalBody.appendChild(redirectButton);
    //

    // Create dismiss button
    const dismissButton = document.createElement('button');
    dismissButton.textContent = 'I understand the risks - Proceed anyway';
    Object.assign(dismissButton.style, warningStyles.dismissButton);

    dismissButton.addEventListener('click', () => {
        overlay.remove();
        isDismissed = true;
        document.body.style.overflow = '';
    });
    modalBody.appendChild(dismissButton);
    //

    if (phishingScore === 1) {
        const alwaysDismissButton = document.createElement('button');
        alwaysDismissButton.textContent = '⚠️ Always suppress on this domain ⚠️';
        Object.assign(alwaysDismissButton.style, warningStyles.dismissButton);
        alwaysDismissButton.addEventListener('click', () => {
            // add to suppress_warnings
            let susHost = new URL(window.location.href).hostname;
            // remove www. prefix
            susHost = susHost.toLowerCase().replace(/^www\./, '');

            // User has dismissed the warning for this domain
            PROTECTED_WEBSITES.find(site => site.known_legit.includes(realDomain)).suppress_warnings.push(susHost);
            chrome.storage.local.set({PROTECTED_WEBSITES: PROTECTED_WEBSITES});

            overlay.remove();
            isDismissed = true;
            document.body.style.overflow = '';
        })
        modalBody.appendChild(alwaysDismissButton)
    }

    // Attach overlay to the body
    document.body.appendChild(overlay);

    // Prevent scrolling
    document.body.style.overflow = 'hidden';
}

async function checkAllUrls() {

    if (isDismissed) return;

    // get PROTECTED_WEBSITES from storage
    try {
        PROTECTED_WEBSITES = await new Promise((resolve) => {
            chrome.storage.local.get('PROTECTED_WEBSITES', (result) => {
                resolve(result.PROTECTED_WEBSITES);
            });
        });
        if (!PROTECTED_WEBSITES) {
            console.error('PROTECTED_WEBSITES not found in storage');
            return;
        }
    } catch (e) {
        console.error('Error getting PROTECTED_WEBSITES:', e);
    }


    try {
        const currentHost = new URL(window.location.href).hostname;

        for (const site of PROTECTED_WEBSITES) {
            let phishing_score = isPhishingUrl(currentHost, site);

            if (phishing_score) {
                showWarning(site.known_legit[0], phishing_score);
                break;
            }
        }
    } catch (e) {
        console.error('Phishing check error:', e);
    }
}

let lastUrl = location.href;
const observer = new MutationObserver(() => {
    if (location.href !== lastUrl) {
        lastUrl = location.href;
        isDismissed = false;
        document.body.style.overflow = ''; // Restore scrolling on URL change

        // Remove any existing overlay
        const existingOverlay = document.getElementById('phish-overlay');
        if (existingOverlay) existingOverlay.remove();
    }

    if (!document.getElementById('phish-overlay')) {
        checkAllUrls();
    }
});

// Initial check when page loads
document.addEventListener('DOMContentLoaded', checkAllUrls);

// Start observing DOM changes
observer.observe(document, {
    childList: true,
    subtree: true,
    attributes: false,
    characterData: false
});

// Handle back/forward navigation
window.addEventListener('popstate', () => {
    isDismissed = false;
    document.body.style.overflow = ''; // Restore scrolling

    // Force check on history state changes
    setTimeout(checkAllUrls, 100);
});

// Periodically check for URL changes (for SPAs that might not trigger mutations)
setInterval(() => {
    if (window.location.href !== lastUrl) {
        observer.takeRecords(); // Force mutation check
    }
}, 1000);