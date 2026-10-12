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

NAV = [("", "Home"), ("shows/", "Shows"), ("https://wizardofreading.com/", "Reading Shows"),
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
    text = re.sub(r",\s*,", ",", text)
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
    # these blanks were filled with the visitor's name/email by the Amazing System plugin (needs WordPress)
    raw = raw.replace("<p>Thank you !</p>", "<p>Thank you!</p>").replace("confirmation email to you at .", "confirmation email to you.")
    raw = raw.replace("<p>This information has also been sent to <strong></strong></p>", "")
    raw = re.sub(r"<p>Hello\s*(?=<p>)", "<p>Hello!</p>\n", raw)
    raw = raw.replace("This information has also been sent to [ez_date] Hello &nbsp; ", "")
    # Dean, Oct 12 2026: virtual shows are no longer offered, take every mention out
    raw = re.sub(r"<h3>VIRTUAL MAGIC SHOWS</h3>.*?(?=<h4>)", "", raw, flags=re.S)
    raw = raw.replace(" and can be presented either LIVE in person or Virtually.", ".")
    return raw


BUILT = set()


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
            if re.search(r"(?i)dabutton", local):  # the round Dean Alan logo: keep it small
                el["class"] = "logo"
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
                    if el.find("img") is not None and s not in attachment_targets and s not in BUILT:
                        el.unwrap()
                        continue
                    s = attachment_targets.get(s, s)
                    if s.startswith("http"):
                        href = s
                    else:
                        href = root + s if s else (root or "./")
            if not el.get_text(strip=True) and el.find("img") is None:  # empty leftover link
                el.unwrap()
                continue
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
    # drop leftover captions that are just a file name (e.g. "cropped-2016DAbutton_edited-1aa.png")
    for t in node.find_all(string=re.compile(r"^\s*[\w.-]+\.(png|jpe?g|gif|webp)\s*$", re.I)):
        t.extract()
    for img in node.find_all("img"):
        sib = img.find_next_sibling()
        if sib is not None and sib.name == "span" and sib.get_text(strip=True) == (img.get("alt") or "").strip():
            sib.decompose()
    # drop empty wrappers left behind
    for el in node.find_all(["div", "span", "p", "section", "figure"]):
        if not el.get_text(strip=True) and not el.find(["img", "iframe"]):
            el.decompose()
    for t in node.find_all(string=True):
        if isinstance(t, NavigableString) and ("—" in t or "–" in t):
            t.replace_with(fix_dashes(str(t)))
    return node


def two_columns(ec, text_start, image_name):
    """Home page: put the seasonal-shows text beside its flyer (text left, flyer right)."""
    first = next((p for p in ec.find_all("p") if text_start in p.get_text()), None)
    img = next((i for i in ec.find_all("img") if image_name in i.get("src", "")), None)
    if not first or not img:
        print("  ! two_columns: anchor not found", file=sys.stderr)
        return
    block = img
    while block.parent is not ec:
        block = block.parent
    soup = BeautifulSoup('<div class="cols"><div class="col-text"></div><div class="col-img"></div></div>', "lxml")
    cols = soup.find("div", class_="cols")
    first.insert_before(cols)
    left = cols.find("div", class_="col-text")
    node = cols.next_sibling
    while node is not None and node is not block:
        nxt = node.next_sibling
        left.append(node.extract())
        node = nxt
    cols.find("div", class_="col-img").append(img.extract())
    block.decompose()


def photo_row(ec, names):
    """Home page: show these photos side by side (three columns), keeping any caption."""
    found = []
    for name in names:
        img = next((i for i in ec.find_all("img") if name in i.get("src", "")), None)
        if img is None:
            print("  ! photo_row: missing", name, file=sys.stderr)
            return
        a = img.parent if img.parent.name == "a" else None
        if a is not None and a.get("href", "").startswith("img/"):
            img["src"] = a["href"]  # the full-size photo, sharper in a column
        block = img
        while block.parent is not ec:
            block = block.parent
        cap = block.find("figcaption")
        found.append((img, cap.get_text(strip=True) if cap else "", block))
    soup = BeautifulSoup('<div class="row3"></div>', "lxml")
    row = soup.find("div", class_="row3")
    found[0][2].insert_before(row)
    for img, cap, block in found:
        fig = soup.new_tag("figure")
        fig.append(img.extract())
        if cap:
            fc = soup.new_tag("figcaption")
            fc.string = cap
            fig.append(fc)
        row.append(fig)
        block.decompose()


def list_columns(ec, first_heading):
    """Home page: the Daycares / Elementary Schools / Other Events lists, side by side.
    In the old page the next heading was stuck inside a list item ("and many more<br><strong>Other Events</strong>")."""
    head = next((p for p in ec.find_all("p") if p.get_text(strip=True) == first_heading), None)
    if head is None:
        print("  ! list_columns: heading not found", file=sys.stderr)
        return
    lists = []
    node = head.find_next_sibling()
    while node is not None and node.name == "ul":
        lists.append(node)
        node = node.find_next_sibling()
    groups = [[first_heading, []]]
    for ul in lists:
        for li in ul.find_all("li", recursive=False):
            strong = li.find("strong")
            if strong is not None:
                new_title = strong.get_text(strip=True)
                strong.decompose()
                for br in li.find_all("br"):
                    br.decompose()
                if li.get_text(strip=True):
                    groups[-1][1].append(li.decode_contents().strip())
                groups.append([new_title, []])
            else:
                groups[-1][1].append(li.decode_contents().strip())
        ul.decompose()
    cols = "".join(f"<div><h3>{html.escape(t)}</h3><ul>" + "".join(f"<li>{x}</li>" for x in items) + "</ul></div>"
                   for t, items in groups if items)
    head.replace_with(BeautifulSoup(f'<div class="cols3">{cols}</div>', "lxml").find("div"))


def flyer_grid(ec, heading_start, drop=(), drop_text=()):
    """E-promo kit: the season flyers, as same-size thumbnails in a grid, each with its label.
    The old page used little two-column tables (images in one row, labels in the next)."""
    head = next((h for h in ec.find_all(["h2", "h3"]) if h.get_text(strip=True).startswith(heading_start)), None)
    if head is None:
        print("  ! flyer_grid: heading not found", file=sys.stderr)
        return
    cards = []
    node = head.find_next_sibling()
    while node is not None and node.name == "table":
        rows = node.find_all("tr")
        imgs, labels = rows[0].find_all("td"), (rows[1].find_all("td") if len(rows) > 1 else [])
        for k, cell in enumerate(imgs):
            img = cell.find("img")
            if img is None:
                continue
            a = cell.find("a")
            href = a["href"] if a is not None and "e-promo-kit" not in a["href"] else img["src"]
            label = labels[k].get_text(" ", strip=True) if k < len(labels) else ""
            src = img["src"]
            if "FAll2024" in src:  # 2024 flyer shows the retired Thankfully Fun show: use the 2025 flyers, one per show
                base = src.rsplit("/", 1)[0] + "/"
                pages = "../"
                cards += [(pages + "the-fall-o-ween-magic-show/", base + "falloweenflyer2026.jpg", "The Fall-o-Ween Magic Show", "OCTOBER"),
                          (base + "TurkeyKadabraFlyer2025.jpg", base + "TurkeyKadabraFlyer2025.jpg", "Turkey-Kadabra", "NOVEMBER"),
                          (pages + "the-very-merry-magic-show/", base + "flyer-very-merry-2025.jpg", "A Very Merry Magic Show", "DECEMBER")]
                continue
            cards.append((href, src, img.get("alt", ""), label))
        nxt = node.find_next_sibling()
        node.decompose()
        node = nxt
    for name in drop:  # flyers Dean asked to take off
        for img in ec.find_all("img"):
            if name in img.get("src", ""):
                block = img
                while block.parent is not ec:
                    block = block.parent
                block.decompose()
    for t in drop_text:
        for p in ec.find_all("p"):
            if p.get_text(strip=True) == t:
                p.decompose()
    grid = "".join(
        f'<a class="flyer" href="{h}"><img src="{src}" alt="{html.escape(alt or label)}" loading="lazy">'
        f'<span>{html.escape(label)}</span></a>' for h, src, alt, label in cards)
    head.insert_after(BeautifulSoup(f'<div class="flyers">{grid}</div>', "lxml").find("div"))
    head.string = "Click a flyer to find out more about the show"  # one click now (the old page needed two)


def form_beside(ec, text_start, form_html):
    """Home page: the 'To Get More Detailed Information' text on the left, the sign-up form on the right."""
    first = next((p for p in ec.find_all("p") if p.get_text(strip=True).startswith(text_start)), None)
    if first is None:
        print("  ! form_beside: text not found", file=sys.stderr)
        return False
    second = first.find_next_sibling("p")
    soup = BeautifulSoup(f'<div class="cols form-cols"><div class="col-text"></div><div class="col-form">{form_html}</div></div>', "lxml")
    cols = soup.find("div", class_="cols")
    first.insert_before(cols)
    left = cols.find("div", class_="col-text")
    left.append(first.extract())
    if second is not None:
        left.append(second.extract())
    return True


def move_after(ec, image_name, target_class):
    """Move the block holding an image so it sits right after the element with target_class."""
    img = next((i for i in ec.find_all("img") if image_name in i.get("src", "")), None)
    target = ec.find(class_=target_class)
    if img is None or target is None:
        print("  ! move_after: not found", image_name, file=sys.stderr)
        return
    block = img
    while block.parent is not ec:
        block = block.parent
    target.insert_after(block.extract())


def photo_left(ec, image_name):
    """Float a photo to the left of the paragraph it sits in, so the text wraps beside it."""
    img = next((i for i in ec.find_all("img") if image_name in i.get("src", "")), None)
    if img is None:
        print("  ! photo_left: not found", image_name, file=sys.stderr)
        return
    a = img.parent if img.parent.name == "a" else None
    if a is not None and a.get("href", "").startswith("img/"):
        img["src"] = a["href"]
    img["class"] = "float-left"
    p = img.find_parent("p")
    if p is not None:
        first_br = img.find_next_sibling("br") or (a.find_next_sibling("br") if a is not None else None)
        if first_br is not None:
            first_br.decompose()


def mago(form_id):
    return f"""<div class="form-box">
<script src="https://mago.co/Scripts/form.js"></script>
<script>
  var magoForm = new MagoForm();
  magoForm.initialize({{'formId':'{form_id}','autoResize':true,'ssl':true}});
  magoForm.display();
</script>
</div>"""


CSS_VERSION = hashlib.md5(open(os.path.join(HERE, "style.css"), "rb").read()).hexdigest()[:8]


def shell(slug, title, description, body, image=None, noindex=False, extra_head=""):
    root = "../" * slug.count("/")
    nav = "".join(f'<a href="{s if s.startswith("http") else ((root + s) if s else (root or "./"))}"'
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
<link rel="stylesheet" href="{root}style.css?v={CSS_VERSION}">
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
    global BUILT
    dropped = set(open(os.path.join(SRC, "drop.txt")).read().split())  # retired/outdated pages, forwarded instead
    pages = [s for s in (slug_of(u) for u in open(os.path.join(SRC, "page-urls.txt")).read().split()) if s not in dropped]
    posts = [s for s in (slug_of(u) for u in open(os.path.join(SRC, "post-urls.txt")).read().split()) if s not in dropped]
    attachment_targets = json.load(open(os.path.join(SRC, "attachments.json")))  # attachment page -> parent page
    BUILT = set(pages + posts) | {""}
    sitemap, blog = [], []
    for slug in pages + posts:
        fname = (slug.strip("/").replace("/", "__") or "index") + ".html"
        soup = BeautifulSoup(preprocess(open(os.path.join(RAW, fname), errors="ignore").read()), "lxml")
        root = "../" * slug.count("/")
        title = fix_dashes(html.unescape(soup.title.get_text().strip())) if soup.title else "Dean Alan"
        desc = fix_dashes(meta(soup, name="description") or meta(soup, property="og:description"))
        desc = re.split(r"<|&lt;", desc)[0].strip()
        desc = re.sub(r"^This information has also been sent to\s+Hello\s+", "", desc.replace("\u00a0", " "))
        h1 = soup.select_one("main .entry-title, main h1")
        h1_text = fix_dashes(h1.get_text(" ", strip=True)) if h1 else ""
        ec = soup.select_one("main .entry-content")
        if ec is None:
            print("  ! no content:", slug, file=sys.stderr)
            continue
        forms = re.findall(r"'formId':'([0-9a-f-]{36})'", str(ec))
        clean(ec, root, attachment_targets)
        if slug == "e-promo-kit/":
            flyer_grid(ec, "CLICK AN IMAGE", drop=["SummerCamp2026"], drop_text=["Summer 2026"])
        if not slug:
            two_columns(ec, "Your students deserve", "fallmailing")
            photo_row(ec, ["Christmas-Magic-Show", "000_1009", "Cat-In-The-Hat-Magic"])
            list_columns(ec, "Daycares")
            move_after(ec, "daycarelist2025", "cols3")  # Dean: daycare logos graphic goes under the three lists
            photo_left(ec, "newseussbook")  # Dean: Who Is Dean Alan photo to the left of the text
            for p in ec.find_all("p"):  # Dean, Oct 12 2026: take these off the home page
                t = p.get_text(" ", strip=True)
                if t.startswith("For Daycares, each month") or t.startswith("You’ll get a Coloring Page"):
                    p.decompose()
            for t in ec.find_all(string=re.compile("Plus, just for signing up for the e-promo-kit")):
                t.replace_with(re.sub(r"\s*Plus, just for signing up for the e-promo-kit, we will hook you up with some fun activity pages\.", "", str(t)))
            if forms and form_beside(ec, "To Get More Detailed Information", mago(forms[0])):
                forms = []  # the form now sits in the right-hand column instead of at the bottom
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
        canon = target if target.startswith("http") else SITE + target
        dest = target if target.startswith("http") else ((root + target) if target else (root or "./"))
        write(old, f'<!doctype html><meta charset="utf-8"><title>Dean Alan</title>'
                   f'<meta name="robots" content="noindex"><link rel="canonical" href="{canon}">'
                   f'<meta http-equiv="refresh" content="0; url={dest}"><a href="{dest}">Continue</a>')

    with open(os.path.join(HERE, "sitemap.xml"), "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
        f.write("".join(f"<url><loc>{SITE}{s}</loc></url>\n" for s in sitemap))
        f.write("</urlset>\n")
    json.dump(IMG_MAP, open(_img_cache_file, "w"), indent=0)
    print(f"built {len(sitemap)} pages, {len(attachment_targets)} forwards, {len(IMG_MAP)} images")


if __name__ == "__main__":
    main()
