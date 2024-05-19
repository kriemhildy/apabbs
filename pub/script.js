///////////////////////////////////////////////////////////////////////////////////////////////////
// init url for route switching
///////////////////////////////////////////////////////////////////////////////////////////////////

const url = new URL(window.location.href);

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

let originalTitle, unseenPosts = 0;

document.addEventListener("DOMContentLoaded", function () {
    if (url.pathname == "/") {
        originalTitle = document.title;
    }
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

document.addEventListener("DOMContentLoaded", function () {
    if (url.pathname == "/") {
        document.addEventListener("visibilitychange", restoreTitle);
        window.addEventListener("focus", restoreTitle);
    }
});

///////////////////////////////////////////////////////////////////////////////////////////////////
// init web socket
///////////////////////////////////////////////////////////////////////////////////////////////////

let template, main;

function updatePost(uuid, html) {
    const post = document.querySelector(`div#post-${uuid}`);
    template.innerHTML = html;
    if (post) {
        post.replaceWith(template.content);
    } else {
        main.prepend(template.content);
        incrementUnseenPosts();
    }
}

document.addEventListener("DOMContentLoaded", function () {
    if (url.pathname == "/") {
        const webSocketProtocol = location.protocol == "https:" ? "wss:" : "ws:";
        const webSocket = new WebSocket(`${webSocketProtocol}//${location.hostname}/web-socket`);
        webSocket.addEventListener("message", function (event) {
            const json = JSON.parse(event.data);
            updatePost(json.uuid, json.html);
        });
        template = document.createElement("template");
        main = document.querySelector("main");
    }
});
