# hunt-report

Automate vulnerability reports for bug bounty hunters. Convert raw scan output (Nuclei, curl, Burp) into submission-ready reports.

## 🚀 Quick Start

```bash
pip install hunt-report
hunt-report --help
```

## 💰 Pricing

- **$1 Trial**: Try it for just $1 - [paypal.me/huntreport/1](https://paypal.me/huntreport/1)
- **$19/mo Pro**: Advanced features - [paypal.me/huntreport/19](https://paypal.me/huntreport/19)
- **$79/mo Team**: Team collaboration - [paypal.me/huntreport/79](https://paypal.me/huntreport/79)

## ✨ Features

- **Raw HTTP/curl Parsing**: Convert raw HTTP responses to structured reports
- **Nuclei JSON Support**: Parse Nuclei scan output directly
- **Evidence-Based Scoring**: Automatic tier scoring based on evidence
- **Multiple Output Formats**: bounty-report.md, h1-submission.md, poc.md, targets.md
- **HackerOne Ready**: Submission-ready formats for bug bounty platforms
- **Fast & CLI-Friendly**: Built for security researchers

## 📊 Demo

Check out the live demo: [twenty-tools.github.io/hunt-report](https://twenty-tools.github.io/hunt-report/)

## 📖 Usage

```bash
# Parse raw HTTP response
hunt-report parse raw_response.txt --format h1-submission

# Parse Nuclei JSON output
hunt-report parse nuclei_output.json --format bounty-report

# Custom output
hunt-report parse scan.json --format poc.md --severity auto
```

## 📁 Output Formats

- `bounty-report.md` - Standard bug bounty report format
- `h1-submission.md` - HackerOne submission format
- `h1-submission.txt` - HackerOne plain text format
- `poc.md` - Proof of concept markdown
- `findings.md` - Structured findings list
- `targets.md` - Target enumeration report

## 🧪 Examples

See our gists for real examples:
- [Demo Report](https://gist.github.com/twenty-tools/924ece0e75032f06e1ace3abe36e968b)
- [Raw HTTP to Report](https://gist.github.com/twenty-tools/2918c6630e0c26a0b32c86ec4f3d36a0)
- [Full Bug Bounty Report](https://gist.github.com/twenty-tools/48f58ea8592c1ce1524be09a3eb9cd27)

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Pull requests welcome! For bug reports and feature requests, please open an issue.

---

**Built for bug bounty hunters, by bug bounty hunters**

🎯 [Try for $1](https://paypal.me/huntreport/1) | 💼 [Pro $19/mo](https://paypal.me/huntreport/19) | 🏢 [Team $79/mo](https://paypal.me/huntreport/79)
