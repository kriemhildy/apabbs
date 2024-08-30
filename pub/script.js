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
let webSocket, template, postsSection;

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
    webSocket = new WebSocket(`${webSocketProtocol}//${location.hostname}/web-socket`);
    webSocket.addEventListener("message", function (event) {
        const json = JSON.parse(event.data);
        updatePost(json.uuid, json.html);
    });
    webSocket.addEventListener("close", function() {
        setTimeout(initWebSocket, 3_000);
    });
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// routing
///////////////////////////////////////////////////////////////////////////////////////////////////

const url = new URL(window.location.href);

if (url.pathname == "/" && !url.searchParams.has('until')) {
    for (fn of [initDomElements, initUnseenPosts, initWebSocket]) {
        document.addEventListener("DOMContentLoaded", fn);
    }
}
