# Third-party notices

## PCAP-Hunter DNS heuristic formulas

The bounded DNS DGA/tunneling heuristics in `backend/app/dns_analysis.py` adapt scoring ideas from `ninedter/pcap-hunter`, specifically `app/pipeline/dns_analysis.py` at upstream commit `cf839a4` (2026-11-17 review). The original module was authored by ninedter. Local code was reworked for bounded metadata-only input, strict evidence-ID linkage, low-confidence candidate semantics, and this application's offline-first processing.

The upstream repository is licensed under the MIT License. This notice does not change the license of other PCAPSCANNER code, and does not grant rights to third-party datasets/signature tables separately included in upstream.

```text
MIT License

Copyright (c) 2025 ninedter

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Upstream source and license:

- https://github.com/ninedter/pcap-hunter/blob/main/app/pipeline/dns_analysis.py
- https://github.com/ninedter/pcap-hunter/blob/main/LICENSE
