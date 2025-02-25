///////////////////////////////////////////////////////////////////////////////////////////////////
// change title for unseen posts received via web socket or interim check
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
// update after sleep
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
    console.log(`fetching interim post data from ${key}`);
    fetch(`/interim/${key}`).then((response) => {
        if (response.status == 200) {
            response.json().then((json) => {
                for (const post of json.posts) {
                    console.log("updating interim post: ", post.key);
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
let webSocket, template, postsDiv, reconnectInterval;
let webSocketOpen = false; // necessary to prevent multiple reconnects

function initDomElements() {
    template = document.createElement("template");
    postsDiv = document.querySelector("div#posts");
}

function updatePost(key, html) {
    const post = document.querySelector(`div#post-${key}`);
    template.innerHTML = html;
    addFetchToForms(null, template.content);
    if (post) {
        post.replaceWith(template.content);
    } else {
        postsDiv.prepend(template.content);
        incrementUnseenPosts();
    }
}

function handleWebSocketMessage(event) {
    const json = JSON.parse(event.data);
    console.log("updating websocket post: ", json.key);
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
// add fetch to forms
///////////////////////////////////////////////////////////////////////////////////////////////////

function handleFormSubmit(event) {
    event.preventDefault();
    disableSubmitButtons();
    console.log("this: ", this);
    const formData = new FormData(this);
    let fetchBody;
    if (this.enctype == "multipart/form-data") {
        fetchBody = formData;
    } else {
        fetchBody = new URLSearchParams(formData);
    }
    const spinner = document.querySelector("div#spinner");
    spinner.style.display = "block";
    fetch(this.action, {
        method: this.dataset.fetch || "POST",
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
        spinner.style.display = "none";
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
