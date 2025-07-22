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
 * Runs when the DOM is loaded or templates are updated.
 */
function addSubmitConfirmations(event) {
    event.target.querySelectorAll("form[data-confirm]").forEach((form) => {
        form.addEventListener("submit", confirmSubmit);
    });
}

document.addEventListener("DOMContentLoaded", addSubmitConfirmations);

// -----------------------------------------------------------------------------
// Notification system for new posts when tab is not active
// -----------------------------------------------------------------------------

let originalTitle;
let unseenPosts = 0;

/**
 * Increments the unseen posts counter in the page title if the document is not focused.
 */
function incrementUnseenPosts() {
    if (!document.hasFocus()) {
        unseenPosts++;
        document.title = `(${unseenPosts}) ${originalTitle}`;
    }
}

/**
 * Resets the unseen posts counter and restores the original title when the window regains focus.
 */
function restoreTitle() {
    unseenPosts = 0;
    document.title = originalTitle;
}

/**
 * Initializes the unseen posts notification system and sets up the focus event listener.
 */
function initUnseenPosts() {
    originalTitle = document.title;
    window.addEventListener("focus", restoreTitle);
}

// -----------------------------------------------------------------------------
// Dynamic post updates via templates
// -----------------------------------------------------------------------------

let template;
let postsDiv;
let spinner;

/**
 * Initializes DOM element references and event listeners for dynamic post updates.
 */
function initDomElements() {
    template = document.createElement("template");
    postsDiv = document.querySelector("div#posts");
    spinner = document.querySelector("div#spinner");
    template.content.addEventListener("templateUpdated", addSubmitConfirmations);
    template.content.addEventListener("templateUpdated", addFetchToForms);
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
        incrementUnseenPosts();
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
 * Removes a post from the DOM after it has been hidden.
 */
function removeHiddenPost(element) {
    if (element.parentElement) {
        element.parentElement.remove();
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
let webSocket;
const MIN_RECONNECT_DURATION = 2_000;
const MAX_RECONNECT_DURATION = 60_000;
let reconnectDuration;
let reconnectTimeout = null;

/**
 * Processes incoming WebSocket messages containing post updates.
 */
function handleWebSocketMessage(event) {
    try {
        const json = JSON.parse(event.data);
        updatePost(json.key, json.html);
        console.log(`WebSocket: Received update for post ${json.key}.`);
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
 * Handles successful WebSocket connection and checks for missed posts.
 */
function handleWebSocketOpened(_event) {
    clearTimeout(reconnectTimeout);
    reconnectTimeout = null;
    console.log("WebSocket connection established.");
    checkInterim();
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
    document.querySelectorAll("input[type=submit]").forEach((input) => {
        if (input.disabled) {
            input.dataset.keepDisabled = '';
        }
        input.disabled = true;
    });
}

/**
 * Restores submit buttons to their previous state after form processing.
 */
function restoreSubmitButtons() {
    document.querySelectorAll("input[type=submit]").forEach((input) => {
        if (input.dataset.keepDisabled === undefined) {
            input.disabled = false;
        } else {
            delete input.dataset.keepDisabled;
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
            removeHiddenPost(form);
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

// Only initialize WebSocket and dynamic content features on the homepage
if (url.pathname === "/") {
    for (const fn of [initDomElements, initUnseenPosts, initWebSocket, addFetchToForms]) {
        document.addEventListener("DOMContentLoaded", fn);
    }
}
