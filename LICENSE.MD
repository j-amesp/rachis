# Licence

**RACHIS** — thesis, reference implementation, source-side connector, diagrams and demo.

This project is released under two permissive licences, one for the written work and one for
the software. Both permit commercial use, modification, redistribution and forking.

---

## Scope

| Component | Licence |
|---|---|
| **Written work** — the thesis *Disclosure Without Surrender*, all `.md` documentation, the threat model, the architecture diagram and its accompanying text | **CC BY 4.0** |
| **Software** — `rachis-reference/`, `connector/`, the diagram generator, the demo UI, all example configuration and test code | **MIT** |

Where a file could reasonably be read as both (for example a documentation file containing
code samples), the code samples are MIT and the prose is CC BY 4.0.

---

## Written work — Creative Commons Attribution 4.0 International (CC BY 4.0)

You are free to **share** (copy and redistribute in any medium or format) and **adapt**
(remix, transform and build upon the material) for any purpose, including commercially.

Under the following term:

**Attribution** — You must give appropriate credit, provide a link to the licence, and
indicate if changes were made. You may do so in any reasonable manner, but not in any way
that suggests the licensor endorses you or your use.

No additional restrictions — you may not apply legal terms or technological measures that
legally restrict others from doing anything the licence permits.

Full text: https://creativecommons.org/licenses/by/4.0/legalcode

Suggested attribution:

> Based on *Disclosure Without Surrender: integration authority, and federated information
> exchange as public infrastructure* (Copyright (c) 2026 James Patrick CITP MBCS), licensed CC BY 4.0.

---

## Software — MIT Licence

Copyright (c) 2026 James Patrick CITP MBCS

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Why permissive

This is not an incidental licensing decision. It is the argument.

RACHIS holds that the federated exchange layer should be **public infrastructure**: a
published contract that any party may implement, verify, fork, and take to their own
accreditation — rather than a proprietary artefact that binds a customer to one supplier. A
restrictive licence on this work would reproduce, at the level of the specification, exactly
the dependency the thesis exists to dissolve.

So: implement it. Compete with it. Build a better front end, a stronger connector, the
platform side that is not yet written. Take it to a standards body. Use it commercially and
keep the proceeds. The intended outcome is suppliers competing *above* the federation layer
rather than constituting it.

The only thing asked in return is attribution on the written work, so that the argument can be
traced, checked, and — where it is wrong — corrected in public.

---

## What this licence is not

It is not a security accreditation. It is not a warranty of fitness for handling classified,
protectively marked, personal or otherwise regulated information. It is not a representation
that any deployment built from this work is safe, lawful, or compliant in any jurisdiction.

The reference implementation and connector are built to production engineering standards and
are written to be *taken to* accreditation. They have not undergone independent security
testing, and security tests written and run by the authors against their own code do not
constitute independent assurance. Known limitations — including the software key-store
stand-in, classical rather than post-quantum signatures, the unresolved correlation-key
mechanism, and unimplemented hardware attestation — are documented in
`connector/docs/THREAT_MODEL.md` and in the thesis.

Anyone deploying this work against real regulated information is responsible for their own
threat modelling, independent security testing, and accreditation.

All data in the examples, tests and demonstration interface is synthetic.

---

## Authorship

Written and built in a personal capacity, on personal time and equipment. The views expressed
in the written work are the author's own and are not those of any employer or organisation
with which the author is associated.
