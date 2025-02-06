///////////////////////////////////////////////////////////////////////////////////////////////////
// scrollbar styling for chrome on windows and linux
///////////////////////////////////////////////////////////////////////////////////////////////////

function styleScrollbar() {
    if (!navigator.userAgent.includes("Macintosh") && navigator.userAgent.includes("WebKit")) {
        const primaryLink = document.querySelector("link[rel=stylesheet]");
        const scrollbarLink = document.createElement("link");
        scrollbarLink.rel = "stylesheet";
        scrollbarLink.href = "/scrollbar.css";
        console.log("scrollbar");
        primaryLink.after(scrollbarLink);
    }
}

document.addEventListener("DOMContentLoaded", styleScrollbar);

///////////////////////////////////////////////////////////////////////////////////////////////////
// change title for unseen posts received via web socket
///////////////////////////////////////////////////////////////////////////////////////////////////

let originalTitle, unseenPosts = 0;

function incrementUnseenPosts() {
    if (document.visibilityState == "hidden") {
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
// init web socket
///////////////////////////////////////////////////////////////////////////////////////////////////

const webSocketProtocol = location.protocol == "https:" ? "wss:" : "ws:";
let webSocket, template, postsSection, reconnectInterval;
let webSocketOpen = false; // apparently necessary to avoid duplicate reconnects

function initDomElements() {
    template = document.createElement("template");
    postsSection = document.querySelector("div#posts");
}

function updatePost(uuid, html) {
    const post = document.querySelector(`div#post-${uuid}`);
    template.innerHTML = html;
    addFetchToForms(null, template.content);
    if (post) {
        post.replaceWith(template.content);
    } else {
        postsSection.prepend(template.content);
        incrementUnseenPosts();
    }
}

function handleWebSocketMessage(event) {
    const json = JSON.parse(event.data);
    console.log("updating websocket post: ", json.uuid);
    updatePost(json.uuid, json.html);
}

function handleWebSocketClosed() {
    if (webSocketOpen) {
        webSocketOpen = false;
        console.log("websocket closed, attempting to reconnect every ten seconds");
        reconnectInterval = setInterval(initWebSocket, 10_000);
    }
}

function handleWebSocketOpened() {
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
// update after sleep
///////////////////////////////////////////////////////////////////////////////////////////////////

function mostRecentUuid() {
    const post = document.querySelector("div.post:not(.banned)");
    if (post !== null) {
        return post.id.replace("post-", "");
    } else {
        return null;
    }
}

function checkInterim() {
    const uuid = mostRecentUuid();
    console.log(`fetching interim post data from ${uuid}`);
    fetch(`/interim/${uuid}`).then((response) => {
        if (response.status == 200) {
            response.json().then((json) => {
                for (const post of json.posts) {
                    console.log("updating interim post: ", post.uuid);
                    updatePost(post.uuid, post.html);
                }
            });
        }
    });
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// add fetch to forms
///////////////////////////////////////////////////////////////////////////////////////////////////

function handleFormSubmit(event) {
    event.preventDefault();
    disableSubmitButtons();
    const formData = new FormData(this);
    let fetchBody;
    if (this.enctype == "multipart/form-data") {
        fetchBody = formData;
    } else {
        fetchBody = new URLSearchParams(formData);
    }
    fetch(this.action, {
        method: "POST",
        body: fetchBody,
    }).then((response) => {
        console.log("response.status", response.status);
        let actionUrl = new URL(this.action);
        console.log("actionUrl.pathname: ", actionUrl.pathname);
        if ([200, 201, 204].includes(response.status)) {
            switch (actionUrl.pathname) {
                case "/submit-post":
                    this.reset();
                    break;
                case "/hide-rejected-post":
                    this.parentElement.remove();
                    break;
            }
        } else {
            response.text().then((text) => {
                alert(text);
            });
        }
        restoreSubmitButtons();
    });
}

function addFetchToForms(_event, element = document) {
    const forms = element.querySelectorAll("form[data-fetch]");
    for (const form of forms) {
        console.log("adding fetch to form: ", form);
        form.addEventListener("submit", handleFormSubmit);
    }
}

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
// routing
///////////////////////////////////////////////////////////////////////////////////////////////////

const url = new URL(window.location.href);

if (url.pathname == "/") {
    for (fn of [initDomElements, initUnseenPosts, initWebSocket, addFetchToForms]) {
        document.addEventListener("DOMContentLoaded", fn);
    }
}
