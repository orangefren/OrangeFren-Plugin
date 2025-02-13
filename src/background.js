async function updateProtectedWebsites() {
    // Fetch updated phishing domain lists from a remote server (if available)
    const response = await fetch("https://orangefren.com/api/get_phishing_data");
    if (!response.ok){
        console.warn("Failed to fetch phishing data")
        return;
    }

    const updatedData = await response.json();
    if(updatedData.version != "1"){
        console.error("Unsupported phishing data version:", updatedData.version);
        console.error("Please update the plugin!");
        throw new Error("Unsupported phishing data version! Please update the plugin!");
    }

    // Copy the previous suppress_warnings field to the new data
    const previousData = await chrome.storage.local.get("PROTECTED_WEBSITES");

    for (let site of updatedData.data) {

        site.suppress_warnings = [];

        if (previousData.PROTECTED_WEBSITES) {
            const previousSite = previousData.PROTECTED_WEBSITES.find((prevSite) => prevSite.name === site.name)
            if (previousSite && previousSite.suppress_warnings) {
                site.suppress_warnings = previousSite.suppress_warnings;
            }
        }
    }

    // Update the local storage with the latest phishing list
    await chrome.storage.local.set({ PROTECTED_WEBSITES: updatedData.data });
    console.log("Phishing domain list updated:", updatedData.data);
}

// Run update immediately when the extension starts
updateProtectedWebsites();

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
    if (reason !== 'install') {
        return;
    }

    // Create an alarm so we have something to look at in the demo
    await chrome.alarms.create('updatePhishingData', {
        periodInMinutes: 60
    });
});

chrome.alarms.onAlarm.addListener((alarm) => {
    console.log('Alarm triggered:', alarm);
    if (alarm.name === "updatePhishingData") {
        updateProtectedWebsites();
    }
});
