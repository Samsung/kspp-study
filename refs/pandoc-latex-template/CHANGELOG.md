# Changelog

All notable changes to this project are documented in this file. On the [releases page](https://github.com/Wandmalfarbe/pandoc-latex-template/releases/) you can see all released versions of the Eisvogel template and download the [latest version](https://github.com/Wandmalfarbe/pandoc-latex-template/releases/latest).

## [1.2.4] - 2019-06-16

- Fixed: The template now compiles with the output format `beamer` (#99). The styling for the generated slides is currently not customized.

## [1.2.3] - 2019-06-12

- Fixed: Code blocks were too close to the text above.
- Fixed: The default float placement of figures can be changed with the variable `float-placement-figure`.
- Changed: Merged changes from the pandoc default LaTeX template.
- Added: A changelog is available as `CHANGELOG.md`.
- Changed: Updated installation instructions in the README with new XDG support (#89, Andrew Zhou).

## [1.2.2] - 2019-04-09

- Merged changes from the pandoc default LaTeX template.
- Fixed: Support custom values for `secnumdepth` and `toc-depth` (#87, Juan Grigera).

## [1.2.1] - 2019-03-10

- Removed double inclusion of package `xcolor` and cleaned up some comments.
- Removed unused `\captionsetup[longtable]`.
- Moved listing colors to the listings block in the template.
- Changed the top and bottom spacing of listings.
- Merged changes from the pandoc default LaTeX template.
- Changed the release script to also create a `tar.gz` archive.

## [1.2.0] - 2019-03-03

- Fixed curly quotes in code listings under XeTeX engine (#79, Andrew Hodgkinson).
- Merged changes from the pandoc default LaTeX template `default.latex`.
- Updated the installation instructions in the README and moved the release script to the `tools` folder.

## [1.1.0] - 2019-02-17

- Defined a default pagestyle to make it easier to change the pagestyle on certain pages or define a custom one (#77).
- Add support for `first-chapter` variable in case it's desirable for a book not to begin with chapter 1 (#74, umanovskis).

## [1.0.0] - 2018-12-07

- First release of the template as a ZIP file with the examples.

[1.2.4]: https://github.com/Wandmalfarbe/pandoc-latex-template/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/Wandmalfarbe/pandoc-latex-template/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/Wandmalfarbe/pandoc-latex-template/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/Wandmalfarbe/pandoc-latex-template/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/Wandmalfarbe/pandoc-latex-template/compare/1.1.0...v1.2.0
[1.1.0]: https://github.com/Wandmalfarbe/pandoc-latex-template/compare/v1.0.0...1.1.0
[1.0.0]: https://github.com/Wandmalfarbe/pandoc-latex-template/releases/tag/v1.0.0