///////////////////////////////////////////////////////////////////////////////////////////////////
// scrollbar styling for chrome on windows and linux
///////////////////////////////////////////////////////////////////////////////////////////////////

function styleScrollbar() {
    if (!navigator.userAgent.includes("Macintosh") && navigator.userAgent.includes("WebKit")) {
        const primaryLink = document.querySelector("link[rel=stylesheet]");
        const scrollbarLink = document.createElement("link");
        scrollbarLink.rel = "stylesheet";
        scrollbarLink.href = "/scrollbar.css";
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
let webSocketOpen = false;

function initDomElements() {
    template = document.createElement("template");
    postsSection = document.querySelector("section#posts");
}

function updatePost(uuid, html) {
    const post = document.querySelector(`article#post-${uuid}`);
    template.innerHTML = html;
    if (post) {
        post.replaceWith(template.content);
    } else {
        postsSection.prepend(template.content);
        incrementUnseenPosts();
    }
}

function initWebSocket() {
    console.log("attempting to connect to websocket");
    webSocket = new WebSocket(`${webSocketProtocol}//${location.hostname}/web-socket`);
    webSocket.addEventListener("message", function (event) {
        // message is going to have to activate admin review JS
        const json = JSON.parse(event.data);
        console.log("websocket message received for post uuid: ", json.uuid);
        updatePost(json.uuid, json.html);
    });
    webSocket.addEventListener("close", function () {
        if (webSocketOpen) {
            webSocketOpen = false;
            console.log("websocket closed, attempting to reconnect every second");
            reconnectInterval = setInterval(initWebSocket, 1_000);
        }
    });
    webSocket.addEventListener("open", function () {
        webSocketOpen = true;
        clearInterval(reconnectInterval);
        console.log("websocket successfully connected");
    });
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// routing
///////////////////////////////////////////////////////////////////////////////////////////////////

const url = new URL(window.location.href);

if (url.pathname == "/" && !url.searchParams.has("until")) {
    for (fn of [initDomElements, initUnseenPosts, initWebSocket]) {
        document.addEventListener("DOMContentLoaded", fn);
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// add fetch to forms
///////////////////////////////////////////////////////////////////////////////////////////////////

function addReviewFetch() {
    const reviewUrl = "/admin/review-post";
    const reviewForms = document.querySelectorAll(`form[action='${reviewUrl}']`);
    for (const reviewForm of reviewForms) {
        console.log("adding fetch to form: ", reviewForm);
        reviewForm.addEventListener("submit", function (event) {
            console.log("review form submit pressed");
            event.preventDefault();
            const formData = new FormData(reviewForm);
            const urlSearchParams = new URLSearchParams(formData);
            fetch(reviewUrl, {
                method: "POST",
                body: urlSearchParams
            }).then((response) => {
                console.log("response.status", response.status);
            });
        });
    }
}

document.addEventListener("DOMContentLoaded", addReviewFetch);
