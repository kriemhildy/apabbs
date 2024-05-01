///////////////////////////////////////////////////////////////////////////////////////////////////
// scrollbar styling for chrome on windows and linux
///////////////////////////////////////////////////////////////////////////////////////////////////

function styleScrollar() {
    if (!navigator.userAgent.includes("Macintosh") && navigator.userAgent.includes("WebKit")) {
        const mainLink = document.querySelector("link[rel=stylesheet]");
        const scrollbarLink = document.createElement("link");
        scrollbarLink.rel = "stylesheet";
        scrollbarLink.href = "/scrollbar.css";
        mainLink.after(scrollbarLink);
    }
}

document.addEventListener("DOMContentLoaded", styleScrollar);

///////////////////////////////////////////////////////////////////////////////////////////////////
// init web socket
///////////////////////////////////////////////////////////////////////////////////////////////////

const protocol = location.protocol == "https:" ? "wss:" : "ws:";
const webSocket = new WebSocket(`${protocol}//${location.hostname}/web-socket`);

///////////////////////////////////////////////////////////////////////////////////////////////////
// change title for unseen posts received via socket
///////////////////////////////////////////////////////////////////////////////////////////////////

let unseenPosts = 0;
let originalTitle;

function setOriginalTitle() {
    originalTitle = document.title;
}

document.addEventListener("DOMContentLoaded", setOriginalTitle);

function incrementUnseenPosts() {
    if (document.visibilityState == "hidden") {
        unseenPosts++;
        document.title = `(${unseenPosts}) ${originalTitle}`;
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// restore original title when window becomes focused
///////////////////////////////////////////////////////////////////////////////////////////////////

function restoreTitle() {
    if (document.visibilityState == "visible") {
        unseenPosts = 0;
        document.title = originalTitle;
    }
}

document.addEventListener("visibilitychange", restoreTitle);
window.addEventListener("focus", restoreTitle);

///////////////////////////////////////////////////////////////////////////////////////////////////
// handle new messages to socket
// we wait for the DOM because these do DOM manipulations
///////////////////////////////////////////////////////////////////////////////////////////////////

function addMessageListener() {
    webSocket.addEventListener("message", function (event) {
        let json = JSON.parse(event.data);
        switch (json.action) {
            case "postSubmitted":
                handlePostSubmitted(json.html);
                break;
            case "postApproved":
                handlePostApproved(json.id, json.html);
                break;
            case "postRejected":
                handlePostRejected(json.id, json.html);
                break;
        }
    });
}

document.addEventListener("DOMContentLoaded", addMessageListener);

const template = document.createElement("template");

function prependPost(html) {
    let main = document.querySelector("main");
    template.innerHTML = html;
    main.prepend(template.content);
    incrementUnseenPosts();
}

// admins only
function handlePostSubmitted(html) {
    prependPost(html);
}

function handlePostApproved(id, html) {
    const post = document.querySelector(`div#post-${id}`);
    if (post) {
        template.innerHTML = html;
        post.replaceWith(template.content);
    } else {
        prependPost(html);
    }
}

function handlePostRejected(id, html) {
    const post = document.querySelector(`div#post-${id}`);
    if (post) {
        template.innerHTML = html;
        post.replaceWith(template.content);
    }
}
