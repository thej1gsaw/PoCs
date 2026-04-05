# Binary Exploitation PoCs

A collection of Proof-of-Concept (PoC) exploit scripts and research notes demonstrating various binary exploitation methodologies. These scripts serve as a technical reference for navigating memory corruption vulnerabilities and bypassing modern security mitigations.

---

## 🛡️ Disclosure Policy & Ethics

To respect the integrity of the CTF platforms and researchers where these vulnerabilities were identified, **this repository does not disclose the original challenge names or specific target binaries.**

> [!IMPORTANT]
> Within the exploit scripts, the target file is represented by the placeholder `<binary>`. This is an intentional choice to respect the wishes of CTF platforms to keep solutions private. By withholding the original binary and challenge context, these PoCs remain educational tools for methodology rather than direct "walkthroughs" or spoilers for active competitions.

---

## 🚀 Overview

The scripts contained here demonstrate a variety of advanced exploitation concepts, including:

* **Memory Corruption:** Arbitrary read/write primitives and control flow hijacking.
* **Information Leaks:** Techniques for bypassing Address Space Layout Randomization (ASLR).
* **Code Reuse:** Construction of sophisticated chains using existing executable memory.
* **Memory Layout Manipulation:** Interacting with different program segments to facilitate stable exploits.

---

## 🛠️ Environment & Setup

Most exploits are developed for Linux-based environments and utilize the following stack:

* **Python 3.10+**
* **Pwntools:** The primary framework for rapid exploit development.
* **GDB / GEF / Pwndbg:** Used for dynamic analysis and memory mapping.
