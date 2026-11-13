"""Extract local NUI asset references without executing HTML or JavaScript."""
from __future__ import annotations
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        path = None
        if tag in {'script', 'img', 'audio', 'video', 'source', 'iframe'}:
            path = values.get('src')
        elif tag == 'link' and set((values.get('rel') or '').lower().split()) & {
                'stylesheet', 'icon', 'preload', 'modulepreload'}:
            path = values.get('href')
        if path:
            self.links.add(path.strip())

def referenced_files(html_source: str, ui_page: str) -> set[str]:
    parser = _Links()
    parser.feed(html_source)
    results: set[str] = set()
    parent = PurePosixPath(ui_page.replace('\\', '/')).parent
    for raw in parser.links:
        if raw.startswith('//'):
            continue
        parsed = urlsplit(raw)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        value = unquote(parsed.path).replace('\\', '/')
        path = value.lstrip('/') if value.startswith('/') else str(parent / value)
        segments: list[str] = []
        safe = True
        for segment in path.split('/'):
            if segment in ('', '.'):
                continue
            if segment == '..':
                if segments:
                    segments.pop()
                else:
                    safe = False
                    break
            else:
                segments.append(segment)
        if safe and segments:
            results.add('/'.join(segments))
    return results
