/**
 * Provides interactive features for the application.
 * Includes confirmation dialogs, unread post notifications,
 * dynamic content updates, AJAX form handling, and DOM updates.
 */

// -----------------------------------------------------------------------------
// Confirmation for potentially destructive actions
// -----------------------------------------------------------------------------

/**
 * Shows a confirmation dialog before submitting a form with a data-confirm attribute.
 */
function confirmSubmit(event) {
    if (!confirm("Are you sure?")) {
        event.preventDefault();
        event.stopImmediatePropagation();
    }
}

/**
 * Adds confirmation handlers to forms with a data-confirm attribute.
 */
function addSubmitConfirmations(event) {
    event.target.querySelectorAll("form[data-confirm]").forEach((form) => {
        form.addEventListener("submit", confirmSubmit);
    });
}

// -----------------------------------------------------------------------------
// Notification system for new items when tab is not active
// -----------------------------------------------------------------------------

let originalTitle;
let unseenItems = 0;

/**
 * Increments the unseen items counter in the page title if the document is not focused.
 */
function incrementUnseenItems() {
    if (!document.hasFocus() || document.visibilityState !== "visible") {
        unseenItems++;
        document.title = `(${unseenItems}) ${originalTitle}`;
    }
}

/**
 * Resets the unseen items counter and restores the original title when the window regains focus.
 */
function restoreTitle() {
    unseenItems = 0;
    document.title = originalTitle;
}

/**
 * Initializes the unseen items notification system and sets up the focus event listener.
 */
function initUnseenItems() {
    originalTitle = document.title;
    window.addEventListener("focus", restoreTitle);
    document.addEventListener("visibilitychange", (event) => {
        if (event.target.visibilityState === "visible") {
            restoreTitle();
        }
    });
}

// -----------------------------------------------------------------------------
// Dynamic DOM updates
// -----------------------------------------------------------------------------

let template;
let postsDiv;
let spinner;
let nav;
let pendingList;

/**
 * Initializes DOM element references and event listeners for dynamic post updates.
 */
function initDomElements() {
    postsDiv = document.querySelector("div#posts");
    spinner = document.querySelector("div#spinner");
    template = document.createElement("template");
    template.content.addEventListener("templateUpdated", addSubmitConfirmations);
    template.content.addEventListener("templateUpdated", addFetchToForms);
    template.content.addEventListener("templateUpdated", addPostHidingButtons);
    navElement = document.querySelector("nav");
    pendingList = document.querySelector("ul#pending-accounts");
}

/**
 * Updates or adds a post in the DOM using server data.
 */
function updatePost(key, html) {
    const post = document.querySelector(`div#post-${key}`);
    template.innerHTML = html;
    const event = new Event("templateUpdated");
    template.content.dispatchEvent(event);
    if (post) {
        post.replaceWith(template.content);
    } else {
        postsDiv.prepend(template.content);
        incrementUnseenItems();
    }
    fixChromiumVideoPosters(key);
}

/**
 * Fixes a Chromium bug with dynamically added video poster attributes.
 */
function fixChromiumVideoPosters(key) {
    if (navigator.userAgent.includes("Chrome")) {
        document.querySelectorAll(`#post-${key} video[poster]`).forEach((video) => {
            video.poster = video.poster;
        });
    }
}

/**
 * Add post hiding functionality to remove posts.
 */
function addPostHidingButtons(event) {
    event.target.querySelectorAll("button.hide-post").forEach((button) => {
        button.addEventListener("click", (event) => {
            event.target.parentElement.remove();
        });
    });
}

/**
 * Update the active username in the nav.
 */
function updateActiveUsername(username) {
    if (username === undefined) {
        navElement.innerHTML = '<a href="/login">[rejected]</a>';
    } else {
        navElement.innerHTML = `<a href="/user/${username}">${username}</a>`;
    }
}

/**
 * Update admin pending usernames list.
 */
function updatePendingUsernames(username, html) {
    const accountItem = document.querySelector(`li#account-${username}`);
    if (accountItem) {
        accountItem.remove();
        if (pendingList.children.length === 0) {
            pendingList.classList.add("hidden");
        }
    } else {
        template.innerHTML = html;
        pendingList.appendChild(template.content);
        if (pendingList.classList.contains("hidden")) {
            pendingList.classList.remove("hidden");
        }
        incrementUnseenItems();
    }
}

// -----------------------------------------------------------------------------
// Fetch missed posts after tab becomes active or reconnection
// -----------------------------------------------------------------------------

/**
 * Returns the key of the most recent visible approved post, or null if none exist.
 */
function latestPostKey() {
    const post = document.querySelector("div.post.approved");
    return post ? post.id.replace("post-", "") : null;
}

/**
 * Fetches posts created since the most recent visible post, used after reconnecting or resuming.
 */
function checkInterim() {
    const key = latestPostKey();
    if (key === null) {
        return;
    }
    fetch(`/interim/${key}`).then((response) => {
        // This must be 200 instead of "ok", as it will return 204 if there are no posts.
        if (response.status === 200) {
            response.json().then((json) => {
                for (const post of json.posts) {
                    updatePost(post.key, post.html);
                }
                if (json.posts.length > 0) {
                    console.log(`Updated ${json.posts.length} posts since key ${key}.`);
                }
            });
        }
    });
}

// -----------------------------------------------------------------------------
// WebSocket connection management
// -----------------------------------------------------------------------------

const webSocketProtocol = location.protocol === "https:" ? "wss:" : "ws:";
const MIN_RECONNECT_DURATION = 2_000;
const MAX_RECONNECT_DURATION = 60_000;
let webSocket;
let reconnectDuration;
let reconnectTimeout = null;
let heartbeatInterval = null;
let lastPingTimestamp;

/**
 * Processes incoming WebSocket messages containing post and account updates.
 */
function handleWebSocketMessage(event) {
    // Detect zero-byte binary ping from server for Safari heartbeat.
    if (event.data instanceof Blob) {
        event.data.arrayBuffer().then((buffer) => {
            if (buffer.byteLength === 0) {
                lastPingTimestamp = Date.now();
                return;
            }
        });
        return;
    }
    try {
        const json = JSON.parse(event.data);
        switch (json.type) {
            case "post":
                console.log(`WebSocket: Received post update for ${json.key}.`);
                updatePost(json.key, json.html);
                break;
            case "account":
                switch (json.reason) {
                    case "owner":
                        console.log("WebSocket: Received update for your account.");
                        updateActiveUsername(json.username);
                        break;
                    case "admin":
                        console.log(`WebSocket: Received account update for ${json.username}.`);
                        updatePendingUsernames(json.username, json.html);
                        break;
                    default:
                        throw (`unknown account update reason: ${json.reason}`);
                }
                break;
            default:
                throw (`unknown message type: ${json.type}`);
        }
    } catch (err) {
        console.error("Failed to process WebSocket message:", err);
    }
}

/**
 * Handles WebSocket connection closure and attempts to reconnect if needed.
 */
function handleWebSocketClosed(event) {
    if (!event.wasClean) {
        if (reconnectTimeout === null) {
            console.warn("WebSocket connection closed, attempting to reconnect...");
            reconnectDuration = MIN_RECONNECT_DURATION;
        } else if (reconnectDuration < MAX_RECONNECT_DURATION) {
            reconnectDuration = Math.min(reconnectDuration * 2, MAX_RECONNECT_DURATION);
        }
        reconnectTimeout = setTimeout(initWebSocket, reconnectDuration);
    }
}

/**
 * Safari fails to disconnect WebSockets upon sleep, so we need to check for pings.
 */
function initSafariHeartbeatCheck() {
    const ua = navigator.userAgent;
    if (ua.includes("Safari") && !ua.includes("Chrome") && heartbeatInterval === null) {
        const CHECK_HEARTBEAT_PERIOD = 2_000;
        const PING_TIMEOUT = 5_000;

        lastPingTimestamp = Date.now();

        heartbeatInterval = setInterval(() => {
            if (webSocket && webSocket.readyState === WebSocket.OPEN) {
                // If no ping received in PING_TIMEOUT, close and reconnect
                if (Date.now() - lastPingTimestamp > PING_TIMEOUT) {
                    console.warn("No ping received from server, closing WebSocket...");
                    webSocket.close();
                }
            } else {
                clearInterval(heartbeatInterval);
                heartbeatInterval = null;
                console.log("WebSocket is not open, stopping heartbeat checks.");
            }
        }, CHECK_HEARTBEAT_PERIOD);
    }
}

/**
 * Handles successful WebSocket connection and checks for missed posts.
 */
function handleWebSocketOpened(_event) {
    clearTimeout(reconnectTimeout);
    reconnectTimeout = null;
    console.log("WebSocket connection established.");
    checkInterim();
    initSafariHeartbeatCheck();
}

/**
 * Establishes a WebSocket connection to the server and sets up event handlers.
 */
function initWebSocket() {
    // Prevent Firefox from opening multiple connections due to reconnect attempts.
    if (webSocket && webSocket.readyState !== WebSocket.CLOSED) {
        return;
    }
    webSocket = new WebSocket(`${webSocketProtocol}//${location.hostname}/web-socket`);
    webSocket.onmessage = handleWebSocketMessage;
    webSocket.onclose = handleWebSocketClosed;
    webSocket.onopen = handleWebSocketOpened;
}

// -----------------------------------------------------------------------------
// Form submission button management
// -----------------------------------------------------------------------------

/**
 * Disables all submit buttons during form processing, tracking which were already disabled.
 */
function disableSubmitButtons() {
    document.querySelectorAll("button[type=submit]").forEach((button) => {
        if (button.disabled) {
            button.dataset.keepDisabled = '';
        }
        button.disabled = true;
    });
}

/**
 * Restores submit buttons to their previous state after form processing.
 */
function restoreSubmitButtons() {
    document.querySelectorAll("button[type=submit]").forEach((button) => {
        if (button.dataset.keepDisabled === undefined) {
            button.disabled = false;
        } else {
            delete button.dataset.keepDisabled;
        }
    });
}

// -----------------------------------------------------------------------------
// Enhanced AJAX form submission handling
// -----------------------------------------------------------------------------

/**
 * Handles form submission using fetch API, showing a loading indicator and handling the response.
 */
function handleFormSubmit(event) {
    event.preventDefault();
    disableSubmitButtons();
    const formData = new FormData(this);
    let fetchBody;
    if (this.enctype === "multipart/form-data") {
        fetchBody = formData;
    } else {
        fetchBody = new URLSearchParams(formData);
    }
    spinner.style.display = "block";
    fetch(this.action, {
        method: "POST",
        body: fetchBody,
    }).then((response) => {
        if (response.ok) {
            console.log(`Form submission to ${this.action} succeeded.`);
            afterSuccessfulFetch(this);
        } else if ([400, 401, 403, 404, 500].includes(response.status)) {
            response.text().then((text) => {
                alert(text);
                console.warn(`Form submission to ${this.action} failed with status ${response.status}: ${text}`);
            });
        } else if (response.status === 413) {
            alert("File must be under 25MB");
            console.warn("Form submission failed: file too large (413)");
        } else if (response.status === 502) {
            alert("Server is currently unavailable. Please try again later.");
            console.error("Form submission failed: server unavailable (502)");
        } else {
            alert(`Unexpected error: ${response.status} ${response.statusText}`);
            console.error(`Unexpected error during form submission: ${response.status} ${response.statusText}`);
        }
    }).catch((err) => {
        alert("Network error: " + err.message);
        console.error("Network error during form submission:", err);
    }).finally(() => {
        restoreSubmitButtons();
        spinner.style.display = "none";
    });
}

/**
 * Remove an account reviewal list item from the DOM after fetch.
 */
function removeAccountReviewItem(element) {
    const li = element.parentElement;
    const ul = li.parentElement;
    li.remove();
    if (ul.children.length === 0) {
        ul.remove();
    }
}

/**
 * Performs post-submission actions based on the form's action URL.
 */
function afterSuccessfulFetch(form) {
    const actionUrl = new URL(form.action);
    switch (actionUrl.pathname) {
        case "/submit-post":
            form.reset();
            break;
        case "/hide-post":
            form.parentElement.remove();
            break;
        case "/review-account":
            removeAccountReviewItem(form);
            break;
    }
}

/**
 * Adds fetch API handlers to all forms in a container on page load and after template updates.
 */
function addFetchToForms(event) {
    const forms = event.target.querySelectorAll("form");
    for (const form of forms) {
        form.addEventListener("submit", handleFormSubmit);
    }
}

// -----------------------------------------------------------------------------
// Initialization based on current page
// -----------------------------------------------------------------------------

const url = new URL(window.location.href);

// Add submit confirmations on every page
document.addEventListener("DOMContentLoaded", addSubmitConfirmations);

// Only initialize WebSocket and dynamic content features on the homepage
if (url.pathname === "/") {
    for (const fn of [
        initDomElements,
        initUnseenItems,
        initWebSocket,
        addFetchToForms,
        addPostHidingButtons
    ]) {
        document.addEventListener("DOMContentLoaded", fn);
    }
}
