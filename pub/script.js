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
// init web socket
///////////////////////////////////////////////////////////////////////////////////////////////////

const protocol = location.protocol == "https:" ? "wss:" : "ws:";
const webSocket = new WebSocket(`${protocol}//${location.hostname}/web-socket`);
const template = document.createElement("template");

function updatePost(id, html) {
    const post = document.querySelector(`div#post-${id}`);
    template.innerHTML = html;
    if (post) {
        post.replaceWith(template.content);
    } else {
        const main = document.querySelector("main");
        main.prepend(template.content);
        incrementUnseenPosts();
    }
}

document.addEventListener("DOMContentLoaded", function () {
    webSocket.addEventListener("message", function (event) {
        const json = JSON.parse(event.data);
        updatePost(json.id, json.html);
    });
});
