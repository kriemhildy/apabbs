UPDATE posts
    SET body = regexp_replace(
        body,
        concat(
            '<a href="',
            'https?://(?:(?:www|m).youtube.com/watch?(?:\S*)v=([^&\s]+)|youtu.be/([^&\s]+))\S*"',
            ' target="_blank">\S+</a>'
        ),
        concat(
            '<iframe width="560" height="315" src="https://www.youtube.com/embed/\1\2" ',
            'title="YouTube video player" frameborder="0" ',
            'allow="accelerometer; autoplay; clipboard-write; encrypted-media; ',
            'gyroscope; picture-in-picture; web-share" ',
            'referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>'
        )
    );
