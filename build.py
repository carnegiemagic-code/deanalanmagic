#!/usr/bin/env python3
"""Builds the static deanalanmagic.com from the saved copy of the old WordPress site.

Why this exists: the GoDaddy hosting that ran the WordPress site was hacked (found 2026-10-12;
see BookingHQ/brain/SECURITY-godaddy-hack-2026-10-12.md). This rebuild takes ONLY the words,
photos, videos and Mago forms from each page and puts them in a clean template. No WordPress
code, plugins or PHP come across.

Every page keeps its old address, so Google listings, printed flyers and old emails still work.

Run:  python3 build.py        (downloads any missing images into img/, then writes every page)
Source pages live in ../deanalanmagic-src/raw/ (one saved HTML file per old page).
"""
import hashlib
import html
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlparse, unquote

from bs4 import BeautifulSoup, Comment, NavigableString

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "deanalanmagic-src")
RAW = os.path.join(SRC, "raw")
IMG = os.path.join(HERE, "img")
SITE = "https://deanalanmagic.com/"
PHONE = "703-404-8902"
PHONE_LINK = "tel:+17034048902"
EMAIL = "info@deanalanmagic.com"
CONTACT_FORM = "0aebb4a9-0d90-4159-8959-4056ae7e6776"

NAV = [("", "Home"), ("shows/", "Shows"), ("reading/", "Reading Shows"),
       ("after-school/", "After-School"), ("category/blog-da/", "Blog"),
       ("reviews/", "Reviews"), ("book/", "Contact")]

# pages that should not be in Google (thank-you, opt-out, a test page)
NOINDEX = {"thanks/", "newsletter-opt-out/", "marketing/", "posters/"}

ALLOWED = {"p", "br", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "b", "em", "i", "u", "a", "ul", "ol", "li",
           "blockquote", "cite", "img", "figure", "figcaption", "table", "thead", "tbody", "tr", "td", "th",
           "hr", "iframe", "div", "span", "section", "sup", "sub", "small"}


def slug_of(url):
    p = urlparse(url).path.strip("/")
    return (p + "/") if p else ""


def fix_dashes(text):
    # house rule: no em dashes in Dean's copy
    text = re.sub(r"\s*—\s*", ", ", text)
    return text.replace("–", "-")


_img_cache_file = os.path.join(SRC, "img-map.json")
IMG_MAP = json.load(open(_img_cache_file)) if os.path.exists(_img_cache_file) else {}


def local_image(src):
    """Download a wp-content image once and return its local path under img/."""
    src = src.split("?")[0]
    if src.startswith("//"):
        src = "https:" + src
    if src in IMG_MAP and os.path.exists(os.path.join(HERE, IMG_MAP[src])):
        return IMG_MAP[src]
    name = unquote(os.path.basename(urlparse(src).path)).replace(" ", "-")
    name = re.sub(r"[^A-Za-z0-9._-]", "", name) or "image"
    stem, ext = os.path.splitext(name)
    if ext.lower() not in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".pdf"):
        return None
    name = f"{stem}-{hashlib.md5(src.encode()).hexdigest()[:6]}{ext.lower()}"
    os.makedirs(IMG, exist_ok=True)
    dest = os.path.join(IMG, name)
    if not os.path.exists(dest):
        r = subprocess.run(["curl", "-sfL", "-m", "40", "-A", "Mozilla/5.0 Chrome/130", "-o", dest, src])
        if r.returncode != 0 or os.path.getsize(dest) < 200:
            if os.path.exists(dest):
                os.remove(dest)
            print("  ! image failed:", src, file=sys.stderr)
            return None
    IMG_MAP[src] = "img/" + name
    return IMG_MAP[src]


def best_src(img):
    """Pick the largest srcset entry up to 1600px wide, else src."""
    best, best_w = img.get("src") or img.get("data-src") or "", 0
    for part in (img.get("srcset") or img.get("data-srcset") or "").split(","):
        bits = part.strip().split()
        if len(bits) == 2 and bits[1].endswith("w"):
            w = int(bits[1][:-1])
            if best_w < w <= 1600:
                best, best_w = bits[0], w
    return best


def cf_decode(hexstr):
    """Undo Cloudflare's email scrambling (data-cfemail / #hex)."""
    key = int(hexstr[:2], 16)
    return "".join(chr(int(hexstr[i:i + 2], 16) ^ key) for i in range(2, len(hexstr), 2))


def preprocess(raw):
    """Turn old theme shortcodes into plain HTML before parsing."""
    raw = re.sub(r"\[ez_youtube[^\]]*?(?:youtu\.be/|v=|embed/)([A-Za-z0-9_-]{11})[^\]]*\]",
                 r'<iframe src="https://www.youtube.com/embed/\1"></iframe>', raw)
    raw = re.sub(r"\[/?ez_[a-z_]+\]", "", raw)
    return raw


def clean(node, root, attachment_targets):
    for el in node.select("[data-cfemail]"):
        el.replace_with(cf_decode(el["data-cfemail"]))
    for a in node.find_all("a", href=re.compile(r"email-protection#")):
        addr = cf_decode(a["href"].split("#", 1)[1])
        a["href"] = "mailto:" + addr
        if "protected" in a.get_text():
            a.string = addr
    for bad in node.find_all(["script", "style", "noscript", "form", "input", "button", "svg", "link", "meta"]):
        bad.decompose()
    for c in node.find_all(string=lambda s: isinstance(s, Comment)):
        c.extract()
    for el in list(node.find_all(True)):
        if el.decomposed if hasattr(el, "decomposed") else False:
            continue
        if el.name not in ALLOWED:
            el.unwrap()
            continue
        if el.name == "iframe":
            src = el.get("src") or el.get("data-src") or ""
            m = re.search(r"youtube(?:-nocookie)?\.com/embed/([A-Za-z0-9_-]{6,})", src)
            if not m:
                el.decompose()
                continue
            wrap = BeautifulSoup(
                f'<div class="video"><iframe src="https://www.youtube-nocookie.com/embed/{m.group(1)}" '
                f'title="Video" loading="lazy" allow="accelerometer; encrypted-media; picture-in-picture" '
                f'allowfullscreen></iframe></div>', "lxml").div
            el.replace_with(wrap)
            continue
        if el.name == "img":
            src = best_src(el)
            if "wp-content/uploads" not in src:
                el.decompose()
                continue
            local = local_image(src)
            if not local:
                el.decompose()
                continue
            alt = el.get("alt") or ""
            el.attrs = {"src": root + local, "alt": alt, "loading": "lazy"}
            continue
        if el.name == "a":
            href = (el.get("href") or "").strip()
            if href.startswith(("http://deanalanmagic.com", "https://deanalanmagic.com",
                                "http://www.deanalanmagic.com", "https://www.deanalanmagic.com")) or href.startswith("/"):
                if "wp-content/uploads" in href:
                    local = local_image(href)
                    href = (root + local) if local else ""
                else:
                    s = slug_of(href)
                    s = attachment_targets.get(s, s)
                    href = root + s if s else (root or "./")
            if href.startswith("mailto:"):
                el.attrs = {"href": href}
                continue
            if not href or href.startswith(("javascript:",)):
                el.unwrap()
                continue
            keep = {"href": href}
            if href.startswith("http"):
                keep["rel"] = "noopener"
            el.attrs = keep
            continue
        el.attrs = {k: v for k, v in el.attrs.items() if k in ("colspan", "rowspan")}
    # drop empty wrappers left behind
    for el in node.find_all(["div", "span", "p", "section", "figure"]):
        if not el.get_text(strip=True) and not el.find(["img", "iframe"]):
            el.decompose()
    for t in node.find_all(string=True):
        if isinstance(t, NavigableString) and ("—" in t or "–" in t):
            t.replace_with(fix_dashes(str(t)))
    return node


def mago(form_id):
    return f"""<div class="form-box">
<script src="https://mago.co/Scripts/form.js"></script>
<script>
  var magoForm = new MagoForm();
  magoForm.initialize({{'formId':'{form_id}','autoResize':true,'ssl':true}});
  magoForm.display();
</script>
</div>"""


def shell(slug, title, description, body, image=None, noindex=False, extra_head=""):
    root = "../" * slug.count("/")
    nav ="".join(f'<a href="{(root + s) if s else (root or "./")}"'
                  + (' aria-current="page"' if s == slug else "") + f">{label}</a>" for s, label in NAV)
    og = image or "img/" + "dean-alan-og.jpg"
    robots = '<meta name="robots" content="noindex, follow">\n' if noindex else ""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(description)}">
{robots}<link rel="canonical" href="{SITE}{slug}">
<link rel="icon" href="{root}img/favicon.png">
<meta property="og:title" content="{html.escape(title)}">
<meta property="og:description" content="{html.escape(description)}">
<meta property="og:image" content="{SITE}{og}">
<meta property="og:url" content="{SITE}{slug}">
<meta property="og:type" content="website">
{extra_head}<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fredoka:wght@500;600;700&family=Nunito:wght@400;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="{root}style.css">
</head>
<body>
<header class="site-head">
  <div class="wrap head-row">
    <a class="brand" href="{root or './'}">Dean Alan<small>The Amazing Magician</small></a>
    <a class="head-phone" href="{PHONE_LINK}">{PHONE}</a>
  </div>
  <nav class="wrap site-nav" aria-label="Main">{nav}</nav>
</header>
<main>
{body}
</main>
<footer class="site-foot">
  <div class="wrap foot-row">
    <div><strong>Dean Alan, the Amazing Magician</strong><br>Educational magic shows for schools, libraries, daycares and camps<br>Nashville, Tennessee and Northern Virginia</div>
    <div><a href="{PHONE_LINK}">{PHONE}</a><br><a href="mailto:{EMAIL}">{EMAIL}</a><br><a href="https://wizardofreading.com/">The Wizard of Reading</a></div>
  </div>
  <p class="wrap fine">&copy; Dean Alan. All rights reserved.</p>
</footer>
</body>
</html>
"""


def write(slug, text):
    folder = os.path.join(HERE, slug)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "index.html"), "w", encoding="utf-8") as f:
        f.write(text)


def meta(soup, **kw):
    t = soup.find("meta", attrs=kw)
    return t.get("content", "") if t else ""


def main():
    dropped = set(open(os.path.join(SRC, "drop.txt")).read().split())  # retired/outdated pages, forwarded instead
    pages = [s for s in (slug_of(u) for u in open(os.path.join(SRC, "page-urls.txt")).read().split()) if s not in dropped]
    posts = [s for s in (slug_of(u) for u in open(os.path.join(SRC, "post-urls.txt")).read().split()) if s not in dropped]
    attachment_targets = json.load(open(os.path.join(SRC, "attachments.json")))  # attachment page -> parent page
    sitemap, blog = [], []
    for slug in pages + posts:
        fname = (slug.strip("/").replace("/", "__") or "index") + ".html"
        soup = BeautifulSoup(preprocess(open(os.path.join(RAW, fname), errors="ignore").read()), "lxml")
        root = "../" * slug.count("/")
        title = fix_dashes(html.unescape(soup.title.get_text().strip())) if soup.title else "Dean Alan"
        desc = fix_dashes(meta(soup, name="description") or meta(soup, property="og:description"))
        h1 = soup.select_one("main .entry-title, main h1")
        h1_text = fix_dashes(h1.get_text(" ", strip=True)) if h1 else ""
        ec = soup.select_one("main .entry-content")
        if ec is None:
            print("  ! no content:", slug, file=sys.stderr)
            continue
        forms = re.findall(r"'formId':'([0-9a-f-]{36})'", str(ec))
        clean(ec, root, attachment_targets)
        inner = ec.decode_contents().strip()
        if forms:
            inner += "\n" + mago(forms[0])
        og_img = meta(soup, property="og:image")
        og_local = local_image(og_img) if "wp-content/uploads" in og_img else None
        is_post = slug in posts
        date = meta(soup, property="article:published_time")[:10]
        head = f'<h1>{html.escape(h1_text)}</h1>' if h1_text and slug else ""
        if is_post and date:
            head += f'<p class="date">{date}</p>'
            blog.append((date, slug, h1_text or title))
        cls = "home" if not slug else ("post" if is_post else "page")
        body = f'<article class="wrap prose {cls}">{head}\n{inner}\n</article>'
        if not forms and slug not in NOINDEX:
            body += (f'<section class="cta-band"><div class="wrap center"><h2>Book a show</h2>'
                     f'<p>Call <a href="{PHONE_LINK}">{PHONE}</a> or use the contact form.</p>'
                     f'<a class="btn" href="{root}book/">Contact Dean Alan</a></div></section>')
        write(slug, shell(slug, title, desc, body, og_local, slug in NOINDEX))
        if slug not in NOINDEX:
            sitemap.append(slug)

    # blog index (old WordPress category page)
    blog.sort(reverse=True)
    items = "".join(f'<li><a href="../../{s}">{html.escape(t)}</a> <span class="date">{d}</span></li>' for d, s, t in blog)
    write("category/blog-da/", shell("category/blog-da/", "Blog - Dean Alan", "News and stories from Dean Alan, the Amazing Magician.",
                                     f'<article class="wrap prose page"><h1>Blog</h1><ul class="post-list">{items}</ul></article>'))
    sitemap.append("category/blog-da/")

    # old attachment, tag and photo URLs -> forward to the page they belonged to
    for old, target in attachment_targets.items():
        if os.path.exists(os.path.join(HERE, old, "index.html")) and old in sitemap:
            continue
        root = "../" * old.count("/")
        dest = (root + target) if target else (root or "./")
        write(old, f'<!doctype html><meta charset="utf-8"><title>Dean Alan</title>'
                   f'<meta name="robots" content="noindex"><link rel="canonical" href="{SITE}{target}">'
                   f'<meta http-equiv="refresh" content="0; url={dest}"><a href="{dest}">Continue</a>')

    with open(os.path.join(HERE, "sitemap.xml"), "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
        f.write("".join(f"<url><loc>{SITE}{s}</loc></url>\n" for s in sitemap))
        f.write("</urlset>\n")
    json.dump(IMG_MAP, open(_img_cache_file, "w"), indent=0)
    print(f"built {len(sitemap)} pages, {len(attachment_targets)} forwards, {len(IMG_MAP)} images")


if __name__ == "__main__":
    main()
