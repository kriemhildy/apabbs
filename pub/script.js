///////////////////////////////////////////////////////////////////////////////////////////////////
// scrollbar styling for chrome on windows and linux
///////////////////////////////////////////////////////////////////////////////////////////////////

document.addEventListener("DOMContentLoaded", function () {
    if (!navigator.userAgent.includes("Macintosh") && navigator.userAgent.includes("WebKit")) {
        const mainLink = document.querySelector("link[rel=stylesheet]");
        const scrollbarLink = document.createElement("link");
        scrollbarLink.rel = "stylesheet";
        scrollbarLink.href = "/scrollbar.css";
        mainLink.after(scrollbarLink);
    }
});

///////////////////////////////////////////////////////////////////////////////////////////////////
// change title for unseen posts received via web socket
///////////////////////////////////////////////////////////////////////////////////////////////////

let unseenPosts = 0;
let originalTitle;

document.addEventListener("DOMContentLoaded", function () {
    originalTitle = document.title;
});

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
// functions to implement DOM changes from web socket messages
///////////////////////////////////////////////////////////////////////////////////////////////////

const template = document.createElement("template");

function prependPost(html) {
    let main = document.querySelector("main");
    template.innerHTML = html;
    main.prepend(template.content);
    incrementUnseenPosts();
}

// admins only
function handleSubmitted(html) {
    prependPost(html);
}

function handleApproved(id, html) {
    const post = document.querySelector(`div#post-${id}`);
    if (post) {
        template.innerHTML = html;
        post.replaceWith(template.content);
    } else {
        prependPost(html);
    }
}

function handleRejected(id, html) {
    const post = document.querySelector(`div#post-${id}`);
    if (post) {
        template.innerHTML = html;
        post.replaceWith(template.content);
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// init web socket
///////////////////////////////////////////////////////////////////////////////////////////////////

const protocol = location.protocol == "https:" ? "wss:" : "ws:";
const webSocket = new WebSocket(`${protocol}//${location.hostname}/web-socket`);

document.addEventListener("DOMContentLoaded", function () {
    webSocket.addEventListener("message", function (event) {
        let json = JSON.parse(event.data);
        switch (json.action) {
            case "postSubmitted":
                handleSubmitted(json.html);
                break;
            case "postApproved":
                handleApproved(json.id, json.html);
                break;
            case "postRejected":
                handleRejected(json.id, json.html);
                break;
        }
    });
});
