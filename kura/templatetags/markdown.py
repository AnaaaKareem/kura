import html
import nh3
from django import template
from django.utils.safestring import SafeString
from markdown_it import MarkdownIt


# Register this small tag so templates can render cleaned Markdown.
register = template.Library()


@register.simple_tag
def render_markdown(source):
    """
    Renders Markdown into sanitized HTML for display in templates,
    keeping raw HTML disabled and cleaning the output with nh3.
    """
    # Treat HTML typed by an author as text rather than executable markup.
    renderer = MarkdownIt("commonmark", {"html": False})
    # Stored source encodes angle brackets before cleaning; restore them as Markdown text.
    rendered_html = renderer.render(html.unescape(source or ""))

    # Only the cleaned output may be treated as HTML by Django's template engine.
    cleaned_html = nh3.clean(rendered_html)
    return SafeString(cleaned_html)
