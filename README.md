# BigFix Community Content Repository
See important notices regarding HCL Terms of Use at [TERMS](TERMS).  These terms are adapted from the original legal terms created for the original bigfix.me site, and may reflect some features (such as confidential areas and NDA agreements) that may not be relevant to this repository.

## Purpose

This repository is intended to foster sharing and collaboration between BigFix customers, partners, and enthusiasts.  This is a modernized replacement for the BigFix.Me site that has operated from October 2012 to the present day.  The purpose of this repository is to continue the legacy of BigFix.Me and carry forward the collaboration using the modern conveniences and standardized tooling supplied by github.

## Organization

The repository structure should follow standard BigFix Endpoint Manager (BES) Support site propagation conventions. Site content is organized as follows.

- **`Fixlets/`**: Stores Fixlet content in standard BigFix `.bes` files.
    - Compilation: Each top-level directory within `Fixlets/` is compiled into a single `.fxf` file containing all nested content (e.g., `Fixlets/Security/` compiles into `Security.fxf`).
    - Subfolders: Nested folders are optional; their contents are automatically included in the parent folder's `.fxf` file.
- **`NonClientFiles/`**: Stores server-side assets, scripts, and metadata not deployed to endpoints.
- **`OtherFiles/`**: Stores additional non-client site artifacts.

SiteContent/
├── Fixlets/
│   ├── BigFix Management/
│   │   ├── 1- Task1.bes
│   │   └── 12- Fixlet1.bes
│   │   
│   └── Mac Software/
│   │   └── 3- RebootTask.bes
│   │
│   └── Windows Software/
│       └── 4- RebootTask.bes
│   
├── NonClientFiles/
│   └── server_script.sh
└── OthersFiles/
    └── documentation.pdf

BigFix Inventory Signatures/react-server-dom CVE-2025-55182,AFFECTED.xml
BigFix Inventory Signatures/react-server-dom CVE-2025-55182,SAFE.xml

AI Skills/Relevance-Generator-Skill.md
AI Skills/Product-Release-Detector-Skill.md
AI Skills/Fixlet-Generator-Skill.md
AI Skills/BigFix-Operator-Skill.md
```

## Attribution
For authorship attribution, if desired please include frontmatter in the content (for example, XML comments or Markdown frontmatter) embedded in the content itself; and/or, MIME fields in .bes content, provided that such tags are schema-conformant and do not interfere with the ability to import/export such content into a BigFix deployment.


## LEGAL AND LICENSE TERMS
Submissions migrated from https://bigfix.me are generally licensed under the terms of the [Creative Commons Attribute-ShareAlike 3.0 license](https://creativecommons.org/licenses/by-sa/3.0/legalcode.txt).  Modifications or submissions updated in this repository after the initial port are updated to the [Creative Commons Attribute-ShareAlike 4.0 license](https://creativecommons.org/licenses/by-sa/4.0/legalcode.txt) as defined at [LICENSE](LICENSE)


