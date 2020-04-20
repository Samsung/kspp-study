# install packages

    (e.g., ubuntu)
    $ sudo apt install pandoc texlive-full python3-pyinotify
  
# build

    $ ./build.py
    $ evince out-pdf/out.pdf

    (e.g., watching file modification and building)
    $ ./build.py -w

    $ ./build.py --html
    $ ./build.py --serve
    $ firefox localhost:8000

# document

    src/header.md
    src/[topic].md
