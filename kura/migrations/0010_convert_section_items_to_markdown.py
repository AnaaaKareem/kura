"""Convert existing cleaned HTML items to readable Markdown without adding fields."""

import html
from html.parser import HTMLParser

import nh3
from django.db import migrations
from markdown_it import MarkdownIt


class MarkdownConverter(HTMLParser):
    """Convert the simple HTML used by old section items into Markdown text."""

    def __init__(self):
        # Keep the output, nested lists, links, and code-block state while parsing.
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.lists = []
        self.links = []
        self.in_pre = False

    def handle_starttag(self, tag, attributes):
        # Translate the old block and inline tags into readable Markdown markers.
        if tag in ("p", "blockquote", "tr"):
            self.parts.append("\n\n")
            if tag == "blockquote":
                self.parts.append("> ")
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self.parts.append("\n\n" + "#" * int(tag[1]) + " ")
        elif tag in ("strong", "b"):
            self.parts.append("**")
        elif tag in ("em", "i"):
            self.parts.append("*")
        elif tag == "pre":
            self.in_pre = True
            self.parts.append("\n\n```\n")
        elif tag == "code" and not self.in_pre:
            self.parts.append("`")
        elif tag in ("ul", "ol"):
            self.lists.append(tag)
            self.parts.append("\n")
        elif tag == "li":
            marker = "1. " if self.lists and self.lists[-1] == "ol" else "- "
            self.parts.append("\n" + "  " * max(len(self.lists) - 1, 0) + marker)
        elif tag == "a":
            href = dict(attributes).get("href") or ""
            self.links.append(href)
            self.parts.append("[")
        elif tag == "br":
            self.parts.append("  \n")
        elif tag == "hr":
            self.parts.append("\n\n---\n\n")
        elif tag in ("td", "th"):
            self.parts.append(" | ")

    def handle_endtag(self, tag):
        # Close formatting markers without discarding the content inside them.
        if tag in ("strong", "b"):
            self.parts.append("**")
        elif tag in ("em", "i"):
            self.parts.append("*")
        elif tag == "pre":
            self.parts.append("\n```\n\n")
            self.in_pre = False
        elif tag == "code" and not self.in_pre:
            self.parts.append("`")
        elif tag in ("ul", "ol") and self.lists:
            self.lists.pop()
            self.parts.append("\n")
        elif tag == "a" and self.links:
            self.parts.append("](" + self.links.pop().replace(")", "%29") + ")")
        elif tag in ("p", "blockquote", "tr", "h1", "h2", "h3", "h4", "h5", "h6"):
            self.parts.append("\n\n")

    def handle_data(self, data):
        # Escape Markdown punctuation from old plain text so it keeps its meaning.
        if not self.in_pre:
            for character in ("\\", "*", "_", "[", "]", "`", "<", ">"):
                data = data.replace(character, "\\" + character)
        self.parts.append(data)


def convert_items(apps, schema_editor):
    """Convert the old stored HTML to cleaned, encoded Markdown source."""
    # Use the historical model and the database selected for this migration.
    SectionItem = apps.get_model("kura", "SectionItem")
    database = schema_editor.connection.alias
    for item in SectionItem.objects.using(database).all().iterator():
        converter = MarkdownConverter()
        converter.feed(item.content_body or "")
        converter.close()
        markdown_source = "".join(converter.parts).strip()
        item.content_body = nh3.clean(html.escape(markdown_source), tags=set(), attributes={})
        item.save(using=database, update_fields=["content_body"])


def restore_html(apps, schema_editor):
    """Recreate cleaned HTML on rollback; exact original formatting may differ."""
    # Keep text and supported formatting readable if the old app is restored.
    SectionItem = apps.get_model("kura", "SectionItem")
    database = schema_editor.connection.alias
    renderer = MarkdownIt("commonmark", {"html": False})
    for item in SectionItem.objects.using(database).all().iterator():
        item.content_body = nh3.clean(renderer.render(html.unescape(item.content_body or "")))
        item.save(using=database, update_fields=["content_body"])


class Migration(migrations.Migration):
    dependencies = [("kura", "0009_admin_course_and_session_permissions")]

    operations = [migrations.RunPython(convert_items, restore_html)]
