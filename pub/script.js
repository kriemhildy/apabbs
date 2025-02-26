///////////////////////////////////////////////////////////////////////////////////////////////////
// scrollbar styling for non-mac webkit
///////////////////////////////////////////////////////////////////////////////////////////////////

function styleScrollbar() {
    if (!navigator.userAgent.includes("Macintosh") && navigator.userAgent.includes("WebKit")) {
        const primaryLink = document.querySelector("link[rel=stylesheet]");
        const scrollbarLink = document.createElement("link");
        scrollbarLink.rel = "stylesheet";
        scrollbarLink.href = "/scrollbar.css?3";
        console.log("non-mac webkit scrollbar");
        primaryLink.after(scrollbarLink);
    }
}

document.addEventListener("DOMContentLoaded", styleScrollbar);

///////////////////////////////////////////////////////////////////////////////////////////////////
// confirm potentially harmful form submissions
///////////////////////////////////////////////////////////////////////////////////////////////////

function confirmSubmit(event) {
    console.log("confirming submit");
    if (!confirm("Are you sure?")) {
        event.preventDefault();
        event.stopImmediatePropagation();
    }
}

function addSubmitConfirmations(_event, element = document) {
    element.querySelectorAll("form[data-confirm]").forEach((form) => {
        form.addEventListener("submit", confirmSubmit);
    });
}

document.addEventListener("DOMContentLoaded", addSubmitConfirmations);

///////////////////////////////////////////////////////////////////////////////////////////////////
// change title for unseen posts received via dynamic update
///////////////////////////////////////////////////////////////////////////////////////////////////

let originalTitle, unseenPosts = 0;

function incrementUnseenPosts() {
    if (document.visibilityState == "hidden" || !document.hasFocus()) {
        unseenPosts++;
        document.title = `(${unseenPosts}) ${originalTitle}`;
    }
}

function restoreTitle() {
    if (document.visibilityState == "visible") {
        unseenPosts = 0;
        document.title = originalTitle;
    }
}

function initUnseenPosts() {
    originalTitle = document.title;
    document.addEventListener("visibilitychange", restoreTitle);
    window.addEventListener("focus", restoreTitle);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// dynamically update posts
///////////////////////////////////////////////////////////////////////////////////////////////////

let template, postsDiv, spinner;

function initDomElements() {
    template = document.createElement("template");
    postsDiv = document.querySelector("div#posts");
    spinner = document.querySelector("div#spinner");
}

function updatePost(key, html) {
    console.log("updating post", key);
    const post = document.querySelector(`div#post-${key}`);
    template.innerHTML = html;
    addSubmitConfirmations(null, template.content);
    addFetchToForms(null, template.content);
    if (post) {
        post.replaceWith(template.content);
    } else {
        postsDiv.prepend(template.content);
        incrementUnseenPosts();
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// add missed posts after sleep
///////////////////////////////////////////////////////////////////////////////////////////////////

function latestPostKey() {
    const post = document.querySelector("div.post:not(.banned)");
    if (post !== null) {
        return post.id.replace("post-", "");
    } else {
        return null;
    }
}

function checkInterim() {
    const key = latestPostKey();
    console.log("fetching interim post data since", key);
    fetch(`/interim/${key}`).then((response) => {
        if (response.status == 200) {
            response.json().then((json) => {
                for (const post of json.posts) {
                    console.log("updating interim post", post.key);
                    updatePost(post.key, post.html);
                }
            });
        }
    });
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// init web socket
///////////////////////////////////////////////////////////////////////////////////////////////////

const webSocketProtocol = location.protocol == "https:" ? "wss:" : "ws:";
let webSocket, reconnectInterval;
let webSocketOpen = false; // necessary to prevent multiple reconnects

function handleWebSocketMessage(event) {
    console.log("websocket message received");
    const json = JSON.parse(event.data);
    updatePost(json.key, json.html);
}

function handleWebSocketClosed(event) {
    if (!event.wasClean && webSocketOpen) {
        webSocketOpen = false;
        console.log("websocket unexpectedly closed, attempting to reconnect every ten seconds");
        reconnectInterval = setInterval(initWebSocket, 10_000);
    }
}

function handleWebSocketOpened(_event) {
    webSocketOpen = true;
    clearInterval(reconnectInterval);
    console.log("websocket successfully connected");
    checkInterim();
}

function initWebSocket() {
    console.log("attempting to connect to websocket");
    webSocket = new WebSocket(`${webSocketProtocol}//${location.hostname}/web-socket`);
    webSocket.addEventListener("message", handleWebSocketMessage);
    webSocket.addEventListener("close", handleWebSocketClosed);
    webSocket.addEventListener("open", handleWebSocketOpened);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// temporarily disable submit buttons when fetching
///////////////////////////////////////////////////////////////////////////////////////////////////

let priorDisabledStatuses = {};

function disableSubmitButtons() {
    console.log("disabling submit buttons");
    document.querySelectorAll("input[type=submit]").forEach((input) => {
        if (!input.id) {
            alert("submit button is missing id");
        }
        priorDisabledStatuses[input.id] = input.disabled;
        input.disabled = true;
    });
}

function restoreSubmitButtons() {
    console.log("restoring submit buttons to previous state");
    for (const id of Object.keys(priorDisabledStatuses)) {
        let input = document.querySelector(`input#${id}`);
        if (input !== null) {
            input.disabled = priorDisabledStatuses[id];
        }
    }
    priorDisabledStatuses = {};
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// add fetch to forms
///////////////////////////////////////////////////////////////////////////////////////////////////

function handleFormSubmit(event) {
    event.preventDefault();
    disableSubmitButtons();
    console.log("fetching form", this);
    const formData = new FormData(this);
    let fetchBody;
    if (this.enctype == "multipart/form-data") {
        fetchBody = formData;
    } else {
        fetchBody = new URLSearchParams(formData);
    }
    spinner.style.display = "block";
    fetch(this.action, {
        method: this.dataset.fetch || "POST",
        body: fetchBody,
    }).then((response) => {
        console.log("response.status", response.status);
        let actionUrl = new URL(this.action);
        console.log("actionUrl.pathname", actionUrl.pathname);
        if ([200, 201, 204].includes(response.status)) {
            switch (actionUrl.pathname) {
                case "/submit-post":
                    this.reset();
                    break;
                case "/hide-post":
                    this.parentElement.remove();
                    break;
            }
        } else {
            response.text().then((text) => {
                alert(text);
            });
        }
        restoreSubmitButtons();
        spinner.style.display = "none";
    });
}

function addFetchToForms(_event, element = document) {
    const forms = element.querySelectorAll("form[data-fetch]");
    for (const form of forms) {
        console.log("adding fetch to form", form);
        form.addEventListener("submit", handleFormSubmit);
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// routing
///////////////////////////////////////////////////////////////////////////////////////////////////

const url = new URL(window.location.href);

if (url.pathname == "/") {
    for (fn of [initDomElements, initUnseenPosts, initWebSocket, addFetchToForms]) {
        document.addEventListener("DOMContentLoaded", fn);
    }
}
