#!/usr/bin/env python3

import glob
import os
import re
import sys
import tempfile
import pyinotify
import argparse
import shutil

from subprocess import Popen, PIPE
from time import gmtime, strftime, time

ROOT     = os.path.dirname(__file__)
PDFDIR   = os.path.join(ROOT, "out-pdf")
OUTMD    = os.path.join(PDFDIR, "out.md")
OUTPDF   = os.path.join(PDFDIR, "out.pdf")
TEMPLATE = os.path.join(ROOT, "refs/pandoc-latex-template/eisvogel.tex")
CONFIG   = os.path.join(ROOT, "config")
TODAY    = strftime("%Y-%m-%d", gmtime())
AUTHORS  = os.path.join(ROOT, "AUTHORS")
MDBOOK   = os.path.join(ROOT, "bin/mdbook.sh")

NOTES = [
    "src/stack-ovfl.md",
    "src/heap-ovfl.md",
    "src/int-ovfl.md",
    "src/infoleak.md",
    "src/side-channel.md",
    "src/bpf.md",
    "src/rop.md",
    "src/compiler.md",
    "src/misc.md"
]

KCONFIGS = {
    "arch-5.1.8"         : "A",
    "arch-harden-5.1.11" : "A+",
    "fedora-5.1.8"       : "F",
    "ubuntu-5.0.0"       : "U",
    "ubuntu-lte-4.15.0"  : "U+"
}

def gen_kconfig(kconfig, mode):
    out = ["\n"]

    len_config = 40
    len_dist = 12
    
    def _to_header(pn):
        pn = os.path.basename(pn)[:-7]
        assert pn in KCONFIGS
        return KCONFIGS[pn].ljust(len_dist-1)

    def _to_realname(pn):
        pn = os.path.basename(pn)[:-7]
        assert pn in KCONFIGS
        pn = pn.replace("-", " ")
        pn = pn.title()
        pn = pn.replace("Lte", "LTE")
        return pn
        
    def _to_yes_no(pn, c, mode):
        for l in open(pn):
            if ("%s=y" % c) in l:
                return "\\Y" if mode == "pdf" else "<b>Y</b>"
        return "\\N" if mode == "pdf" else "N"

    # TODO. prettify the table
    allconfig = sorted(glob.glob(CONFIG + "/*.config"))
    nheader = len(allconfig)
    rule = "-" * (len_config + len_dist * nheader - 1)

    crule = "-" * (len_config-1) + " "
    crule += " ".join("-"*(len_dist-1) for _ in allconfig)

    out.append(rule)
    out.append("Kconfig".ljust(len_config) + " ".join(_to_header(c) for c in allconfig))
    out.append(crule)

    for c in kconfig:
        rows = [c[len("CONFIG_"):]]
        for pn in allconfig:
            rows.append(_to_yes_no(pn, c, mode))
        out.append(rows[0].ljust(len_config) + " ".join(r.ljust(len_dist-1) for r in rows[1:]))
        out.append("\n")

    out.append(rule)
    out.append("\n")

    legend = []
    for c in allconfig:
        if mode == "pdf":
            legend.append("\\textbf{%s}: %s" % (_to_header(c).strip(), _to_realname(c)))
        else:
            legend.append("__%s__: %s" % (_to_header(c).strip(), _to_realname(c)))

    if mode == "pdf":
        out.append("\\vspace{-20px}\\hspace*{\\fill} \\scriptsize %s \\normalsize\n\n" % ", ".join(legend))
    elif mode == "html":
        out.append("<center><small><p>%s</p></small></center>" % ",".join(legend))
    
    out = "\n".join(out)

    if mode == "html":
        p = Popen(["pandoc"], stdin=PIPE, stdout=PIPE, universal_newlines=True)
        html, _ = p.communicate(out)
        out = "<br/>%s<br/>\n\n" % html

    return out

def gen_toc():
    toc = []
    for n in NOTES:
        _, sec = get_section(n)
        link = os.path.basename(n)
        toc.append("- [%s](%s)" % (sec, link))

    return "\n".join(toc)

def gen_sidebar():
    sidebar = ['<div class="sidebar-scrollbox"><ol class="chapter">']

    nsec = 0
    for n in NOTES:
        nsec += 1
        sec, _ = get_section(n)
        link = os.path.basename(n)
        href = link.replace(".md", ".html")
        sidebar.append('<li><a href="%s"><strong aria-hidden="true">%d.&nbsp;</strong>%s</a></li>' \
                       % (href, nsec, sec))

        subsections = get_subsection(n)
        if len(subsections) == 0:
            continue

        nsubsec = 0
        sidebar.append('  <li><ol class="section">')
        for (nickname, subsection) in get_subsection(n):
            nsubsec += 1
            
            hashtag = subsection.lower().replace(" ", "-")
            hashtag = hashtag.replace("`", "")
            hashtag = hashtag.replace("(", "")
            hashtag = hashtag.replace(")", "")
            hashtag = hashtag.replace("/", "")

            href = link.replace(".md", ".html")
            sidebar.append('<li><a href="%s#%s"><strong aria-hidden="true">%d.%d.&nbsp;</strong>%s</a></li>' \
                           % (href, hashtag, nsec, nsubsec, nickname))
        sidebar.append('  </li></ol>')

    sidebar.append('<li class="spacer"></li><li class="affix">')
    sidebar.append('<a href="authors.html">Contributors</a></li>')
    sidebar.append('</ol></div>')

    return "\n".join(sidebar)

def patch_sidebar(pn, sidebar):
    html = open(pn).readlines()

    beg = -1
    end = -1
    for i, l in enumerate(html):
        if '<div class="sidebar-scrollbox">' in l:
            beg = i + 1
            continue
        if beg != -1 and "</div>" in l:
            end = i
            break
    assert beg != -1 and end != -1

    html[beg] = sidebar
    for j in range(beg + 1, end + 1):
        html[j] = "\n"

    with open(pn, "w") as fd:
        fd.write("".join(html))

def dump_authors():
    return open(AUTHORS).read().strip().splitlines()    

def preprocess(pn, mode):
    assert mode in ["html", "pdf"]
    note = []
    kconfig = []

    for l in open(pn):
        # mode-specific transformation
        if mode == "html":
            # ~~~~{.N} -> ```N
            if l.startswith("~~~"):
                m = re.search(r"\{\.(\w+)\}", l)
                if m:
                    l = "```%s\n" % m[1]
                else:
                    l = "```\n"
                
        if l.startswith("@kconfig("):
            kconfig.append(l.strip()[9:-1])
        elif l.startswith("@authors("):
            note.append("author: [%s]\n" % ",".join(dump_authors()))
        elif l.startswith("@assign("):
            note.append("\\textbf{\\textcolor{red}{Assigned to %s}}\n" % (l.strip()[8:-1]))
        elif l.startswith("@todo("):
            note.append("\\textbf{\\textcolor{red}{TODO: %s}}\n" % (l.strip()[6::-1]))
        elif l.startswith("@toc"):
            note.append(gen_toc())
        elif l.startswith("@sidebar"):
            l = ""
        else:
            note.append(l)
    note.append("\n")

    # insret the kconfig table
    if len(kconfig) != 0:
        note = [gen_kconfig(kconfig, mode)] + note

    return "".join(note)

def build():
    def _to_filename(pn):
        return os.path.basename(pn)[:-3]
    def _save_to(data, md, mode):
        root = os.path.join(ROOT, "src-%s" % mode)
        if not os.path.exists(root):
            os.mkdir(root)
        pn = os.path.join(root, os.path.basename(md))
        with open(pn, "w") as fd:
            fd.write(data)

    for n in glob.glob(os.path.join(ROOT, "src/*.md")):
        _save_to(preprocess(n, "pdf"), n, "pdf")
        _save_to(preprocess(n, "html"), n, "html")

    with open(os.path.join(ROOT, "src-html/sidebar.html"), "w") as fd:
        fd.write(gen_sidebar())

def build_pdf():
    build()
    
    out = []
    for n in ["src/header.md"] + NOTES:
        pn = os.path.join(ROOT, "src-pdf/%s" % os.path.basename(n))
        out.append(open(pn).read())

    if not os.path.exists(PDFDIR):
        os.mkdir(PDFDIR)

    with open(OUTMD, "w+") as fd:
        fd.write("\n".join(out))

    os.system(f"pandoc --template '{TEMPLATE}' \
    --metadata date={TODAY} \
    --from markdown \
    --listings \
    -o '{OUTPDF}' '{OUTMD}'")

def watch_pdf():
    class OnWriteHandler(pyinotify.ProcessEvent):
        def __init__(self):
            self.last_run = time()

        def process_IN_MODIFY(self, event):
            if time() - self.last_run > 10:
                if os.path.relpath(event.pathname, ROOT) in NOTES:
                    self.last_run = time()
                    print("[!] building: %s" % event.pathname)
                    build_pdf()

    wm = pyinotify.WatchManager()
    notifier = pyinotify.Notifier(wm, default_proc_fun=OnWriteHandler())
    wm.add_watch(ROOT, pyinotify.ALL_EVENTS, rec=True)
    notifier.loop()

def get_section(pn):
    p = None
    for l in open(pn):
        if l.startswith("# "):
            title = l[2:].strip()
            nickname = title
            if p and p.startswith("@sidebar"):
                nickname = p[9:-2].strip()
            return (nickname, title)
        p = l
    raise "Failed to find the title"

def get_subsection(pn):
    out = []

    p = None
    for l in open(pn):
        if l.startswith("## "):
            if not p.startswith("@sidebar("):
                continue
            title = l[3:].strip()
            nickname = p[9:-2].strip()
            out.append((nickname, title))
        p = l
    return out

def gen_summary():
    print("# Summary\n")
    for n in NOTES:
        print("- [%s](%s)" % (get_section(n), os.path.basename(n)))

def build_html():
    build()
    os.system("%s build" % MDBOOK)

    sidebar = open(os.path.join(ROOT, "src-html/sidebar.html")).read()
    for pn in glob.glob(os.path.join(ROOT, "out-html/*.html")):
        patch_sidebar(pn, sidebar)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build the book for pdf/html')
    parser.add_argument('--watch',   action="store_true", help='watch and build pdf')
    parser.add_argument('--html',    action="store_true", help='build html')
    parser.add_argument('--serve',   action="store_true", help='watch and build html')
    parser.add_argument('--summary', action="store_true", help='build html')

    args = parser.parse_args()

    if args.watch:
        build_pdf()
        watch_pdf()
    elif args.summary:
        gen_summary()
    elif args.html:
        build_html()
    elif args.serve:
        build_pdf()
        os.system("cd out-html; python2 -mSimpleHTTPServer")
    else:
        build_pdf()
        build_html()
    
