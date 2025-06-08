/**
 * This file handles all interactive functionality for the application including:
 * - Form submission confirmation
 * - Unread post notifications
 * - Dynamic content updates via WebSockets
 * - Form handling with fetch API
 */

//-------------------------------------------------------------------------------------------------
// Confirmation for potentially destructive actions
//-------------------------------------------------------------------------------------------------

/**
 * Shows a confirmation dialog before submitting forms with data-confirm attribute
 * Prevents submission if the user cancels the confirmation
 *
 * @param {Event} event - The form submission event
 */
function confirmSubmit(event) {
    console.log("confirming submit");
    if (!confirm("Are you sure?")) {
        event.preventDefault();
        event.stopImmediatePropagation();
    }
}

/**
 * Adds confirmation handlers to forms with the data-confirm attribute
 * Called when DOM content loads and when templates are updated
 *
 * @param {Event} event - The DOMContentLoaded or templateUpdated event
 */
function addSubmitConfirmations(event) {
    event.target.querySelectorAll("form[data-confirm]").forEach((form) => {
        form.addEventListener("submit", confirmSubmit);
    });
}

document.addEventListener("DOMContentLoaded", addSubmitConfirmations);

//-------------------------------------------------------------------------------------------------
// Notification system for new posts when tab is not active
//-------------------------------------------------------------------------------------------------

// Track original page title and count of unseen posts
let originalTitle, unseenPosts = 0;

/**
 * Increments the unseen posts counter in the page title
 * Only updates if the document doesn't have focus
 */
function incrementUnseenPosts() {
    if (!document.hasFocus()) {
        unseenPosts++;
        document.title = `(${unseenPosts}) ${originalTitle}`;
    }
}

/**
 * Resets the unseen posts counter and restores original title
 * Called when the window regains focus
 */
function restoreTitle() {
    unseenPosts = 0;
    document.title = originalTitle;
}

/**
 * Initializes the unseen posts notification system
 * Stores the original title and adds focus event listener
 */
function initUnseenPosts() {
    originalTitle = document.title;
    window.addEventListener("focus", restoreTitle);
}

//-------------------------------------------------------------------------------------------------
// Dynamic post updates via templates
//-------------------------------------------------------------------------------------------------

// DOM elements for post manipulation
let template, postsDiv, spinner;

/**
 * Initializes DOM element references and event listeners
 * Called when the DOM content is loaded
 */
function initDomElements() {
    template = document.createElement("template");
    postsDiv = document.querySelector("div#posts");
    spinner = document.querySelector("div#spinner");
    template.content.addEventListener("templateUpdated", addSubmitConfirmations);
    template.content.addEventListener("templateUpdated", addFetchToForms);
}

/**
 * Updates or adds a post in the DOM based on server data
 *
 * @param {string} key - The unique identifier for the post
 * @param {string} html - The HTML content for the post
 */
function updatePost(key, html) {
    console.log("updating post", key);
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
    fixChromeVideoPosters(key);
}

/**
 * Fixes Chrome bug with dynamically added video poster attributes
 * Re-assigns poster attribute to force Chrome to display it correctly
 *
 * @param {string} key - The unique identifier for the post
 */
function fixChromeVideoPosters(key) {
    // Chrome currently has a bug where the poster attribute of video elements is not set correctly
    // when the video is dynamically added to the DOM. This function fixes that by re-assigning
    // the poster attribute.
    document.querySelectorAll(`#post-${key} video[poster]`).forEach((video) => {
        video.poster = video.poster;
    });
}

//-------------------------------------------------------------------------------------------------
// Fetch missed posts after tab becomes active or reconnection
//-------------------------------------------------------------------------------------------------

/**
 * Gets the key of the most recent visible approved post
 *
 * @returns {string|null} The post key or null if no posts exist
 */
function latestPostKey() {
    const postOpt = document.querySelector("div.post.approved");
    if (postOpt === null) {
        return null;
    }
    const post = postOpt;
    return post.id.replace("post-", "");
}

/**
 * Fetches any posts created since the most recent visible post
 * Used when reconnecting or after device sleep/hibernation
 */
function checkInterim() {
    const keyOpt = latestPostKey();
    if (keyOpt === null) {
        return;
    }
    const key = keyOpt;
    console.log("fetching interim post data since", key);
    fetch(`/interim/${key}`).then((response) => {
        console.log("interim response", response);
        if (response.status === 200) {
            response.json().then((json) => {
                for (const post of json.posts) {
                    updatePost(post.key, post.html);
                }
            });
        }
    });
}

//-------------------------------------------------------------------------------------------------
// WebSocket connection management
//-------------------------------------------------------------------------------------------------

const webSocketProtocol = location.protocol === "https:" ? "wss:" : "ws:";
let webSocket, reconnectInterval;
let webSocketOpen = false; // Track connection state to prevent multiple reconnects

/**
 * Processes incoming WebSocket messages containing post updates
 *
 * @param {MessageEvent} event - WebSocket message event
 */
function handleWebSocketMessage(event) {
    console.log("websocket message received");
    const json = JSON.parse(event.data);
    updatePost(json.key, json.html);
}

/**
 * Handles WebSocket connection closure
 * Attempts to reconnect if the closure was unexpected
 *
 * @param {CloseEvent} event - WebSocket close event
 */
function handleWebSocketClosed(event) {
    if (!event.wasClean && webSocketOpen) {
        webSocketOpen = false;
        console.log("websocket unexpectedly closed, attempting to reconnect every ten seconds");
        reconnectInterval = setInterval(initWebSocket, 10_000);
    }
}

/**
 * Handles successful WebSocket connection
 * Clears reconnect timer and checks for missed posts
 *
 * @param {Event} _event - WebSocket open event
 */
function handleWebSocketOpened(_event) {
    webSocketOpen = true;
    clearInterval(reconnectInterval);
    console.log("websocket successfully connected");
    checkInterim();
}

/**
 * Establishes a WebSocket connection to the server
 * Sets up event handlers for messages, connection open/close
 */
function initWebSocket() {
    console.log("attempting to connect to websocket");
    webSocket = new WebSocket(`${webSocketProtocol}//${location.hostname}/web-socket`);
    webSocket.addEventListener("message", handleWebSocketMessage);
    webSocket.addEventListener("close", handleWebSocketClosed);
    webSocket.addEventListener("open", handleWebSocketOpened);
}

//-------------------------------------------------------------------------------------------------
// Form submission button management
//-------------------------------------------------------------------------------------------------

/**
 * Temporarily disables all submit buttons during form processing
 * Tracks which buttons were already disabled to restore correctly
 */
function disableSubmitButtons() {
    console.log("disabling submit buttons");
    document.querySelectorAll("input[type=submit]").forEach((input) => {
        if (input.disabled) {
            input.dataset.keepDisabled = '';
        }
        input.disabled = true;
    });
}

/**
 * Restores submit buttons to their previous state
 * Only re-enables buttons that weren't disabled initially
 */
function restoreSubmitButtons() {
    console.log("restoring submit buttons to previous state");
    document.querySelectorAll("input[type=submit]").forEach((input) => {
        if (input.dataset.keepDisabled === undefined) {
            input.disabled = false;
        } else {
            delete input.dataset.keepDisabled;
        }
    });
}

//-------------------------------------------------------------------------------------------------
// Enhanced AJAX form submission handling
//-------------------------------------------------------------------------------------------------

/**
 * Handles form submission via fetch API instead of traditional submission
 * Shows loading indicator and handles response appropriately
 *
 * @param {Event} event - Form submission event
 */
function handleFormSubmit(event) {
    event.preventDefault();
    disableSubmitButtons();
    console.log("fetching form", this);
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
        console.log("response", response);
        if (response.ok) {
            afterSuccessfulFetch(this);
        } else if ([400, 401, 403].includes(response.status)) {
            response.text().then((text) => {
                alert(text);
            });
        } else if (response.status === 413) {
            alert("File must be under 20MB");
        } else {
            alert(`${response.status} ${response.statusText}`);
        }
        restoreSubmitButtons();
        spinner.style.display = "none";
    });
}

/**
 * Performs post-submission actions based on the form's action URL
 * Handles specific behavior for different form types
 *
 * @param {HTMLFormElement} form - The submitted form element
 */
function afterSuccessfulFetch(form) {
    const actionUrl = new URL(form.action);
    switch (actionUrl.pathname) {
        case "/submit-post":
            console.log("reset post form");
            form.reset();
            break;
        case "/hide-post":
            removeHiddenPost(form);
            break;
    }
}

/**
 * Removes a post from the DOM after it's been hidden
 *
 * @param {HTMLElement} element - The element that triggered the removal
 */
function removeHiddenPost(element) {
    console.log("remove hidden post");
    element.parentElement.remove();
}

/**
 * Adds fetch API handlers to all forms in a container
 * Called on page load and after template updates
 *
 * @param {Event} event - DOMContentLoaded or templateUpdated event
 */
function addFetchToForms(event) {
    const forms = event.target.querySelectorAll("form");
    for (const form of forms) {
        console.log("adding fetch to form", form);
        form.addEventListener("submit", handleFormSubmit);
    }
}

//-------------------------------------------------------------------------------------------------
// Initialization based on current page
//-------------------------------------------------------------------------------------------------

const url = new URL(window.location.href);

// Only initialize WebSocket and dynamic content features on the homepage
if (url.pathname === "/") {
    for (fn of [initDomElements, initUnseenPosts, initWebSocket, addFetchToForms]) {
        document.addEventListener("DOMContentLoaded", fn);
    }
}
