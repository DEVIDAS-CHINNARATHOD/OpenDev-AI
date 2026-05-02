"""
scanner.py — Repository vulnerability scanner.

Detects 25+ vulnerability types including:
  - SQL injection, NoSQL injection, LDAP injection
  - Cross-Site Scripting (XSS)
  - Unsafe eval() / dynamic code execution
  - Command injection
  - Path traversal
  - Insecure deserialization
  - Weak cryptography
  - Prototype pollution
  - Server-Side Request Forgery (SSRF)
  - Open redirect
  - XML External Entity (XXE)
  - Insecure Direct Object Reference (IDOR)
  - CORS misconfiguration
  - JWT verification bypass
  - Race conditions
  - Mass assignment
  - Log injection
  - Template injection (SSTI)
  - Unrestricted file upload
  - Hardcoded credentials
  - Missing authentication checks
  - Insecure cookie configuration
  - Debug mode in production

Returns a structured findings list compatible with the RL agent state schema.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vulnerability pattern definitions
# ---------------------------------------------------------------------------
VULN_PATTERNS: dict[str, dict[str, Any]] = {
    "sql_injection": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) contains a SQL injection vulnerability.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Rewrite this query to use parameterised statements (e.g. cursor.execute(sql, params) "
            "in Python, or prepared statements in Java/PHP). Never concatenate or format user input "
            "directly into a SQL string. Return only the complete corrected file content."
        ),
        "patterns": [
            re.compile(r'(?i)f["\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*?\{', re.DOTALL),
            re.compile(r'(?i)(execute|query)\s*\(\s*["\'].*?%s.*?["\'].*?%\s*\('),
            re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*?\+\s*\w+'),
            re.compile(r'(?i)cursor\.execute\s*\(\s*[^"\']*\+'),
            re.compile(r'(?i)`(SELECT|INSERT|UPDATE|DELETE)\s.*?\$\{'),
        ],
        "severity": "high",
        "description": "Potential SQL injection — dynamic query construction detected",
        "fix_types": ["prepared_statement", "sanitize_input"],
        "language_hint": ["python", "javascript", "typescript", "php", "java"],
    },
    "xss": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) has an XSS vulnerability.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Replace direct HTML injection with safe alternatives. Use textContent instead of "
            "innerHTML, or sanitise with DOMPurify before assignment. In React avoid "
            "dangerouslySetInnerHTML; render data as JSX children instead. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'\.innerHTML\s*[+]?=(?!\s*DOMPurify)'),
            re.compile(r'\bdocument\.write\s*\('),
            re.compile(r'\.html\s*\(\s*(?!.*escape).*?\+'),
            re.compile(r'dangerouslySetInnerHTML'),
            re.compile(r'\bv-html\b'),
            re.compile(r'\[innerHTML\]'),
        ],
        "severity": "high",
        "description": "Potential Cross-Site Scripting (XSS) — unescaped HTML injection",
        "fix_types": ["sanitize_input", "refactor_code"],
        "language_hint": ["javascript", "typescript"],
    },
    "unsafe_eval": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) uses unsafe dynamic code execution.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Remove eval(), exec(), new Function(), or string-based setTimeout/setInterval. "
            "Replace with explicit function calls, JSON.parse for data, or importlib for dynamic imports. "
            "Return the corrected file."
        ),
        "patterns": [
            re.compile(r'\beval\s*\('),
            re.compile(r'\bnew\s+Function\s*\('),
            re.compile(r'\bsetTimeout\s*\(\s*[\'"]'),
            re.compile(r'\bsetInterval\s*\(\s*[\'"]'),
            re.compile(r'\b__import__\s*\(.*?input'),
            re.compile(r'\bexec\s*\(\s*(?:input|request|req|params|query)'),
        ],
        "severity": "high",
        "description": "Unsafe eval() or dynamic code execution",
        "fix_types": ["refactor_code", "sanitize_input"],
        "language_hint": ["javascript", "typescript", "python"],
    },
    "command_injection": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) is vulnerable to OS command injection.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Replace shell=True or string-concatenated commands with subprocess argument lists "
            "(e.g. subprocess.run(['cmd', arg1, arg2])). Validate/whitelist all user-supplied values "
            "before use. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)(os\.system|subprocess\.call|subprocess\.run|popen)\s*\(.*?\+'),
            re.compile(r'(?i)(os\.system|popen)\s*\(\s*f["\']'),
            re.compile(r'(?i)shell\s*=\s*True.*?(\+|format|f["\'])'),
            re.compile(r'(?i)(exec|system|passthru|shell_exec)\s*\(\s*\$'),
        ],
        "severity": "high",
        "description": "Potential OS command injection via unsanitised input",
        "fix_types": ["sanitize_input", "refactor_code"],
        "language_hint": ["python", "php", "ruby"],
    },
    "path_traversal": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) is vulnerable to path traversal.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Resolve the final path with os.path.realpath() or Path.resolve() and assert it "
            "starts with the expected base directory. Reject paths containing '..' or absolute paths "
            "from user input. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)open\s*\(\s*.*?\+.*?(?:user|request|req|param|input)', re.DOTALL),
            re.compile(r'(?i)open\s*\(\s*f["\'].*?\{'),
            re.compile(r'(?i)(readFile|writeFile|createReadStream)\s*\(.*?\+.*?(?:req|params|query)'),
            re.compile(r'(?i)os\.path\.join\s*\(.*?\+.*?(?:user|request|input)'),
        ],
        "severity": "medium",
        "description": "Potential path traversal — user input in file path",
        "fix_types": ["sanitize_input", "refactor_code"],
        "language_hint": ["python", "javascript", "typescript"],
    },
    "insecure_deserialization": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) uses insecure deserialization.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Replace pickle.loads with json.loads for data exchange. Replace yaml.load with "
            "yaml.safe_load. Replace PHP unserialize with json_decode. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'\bpickle\.loads?\s*\('),
            re.compile(r'\byaml\.load\s*\(\s*(?!.*Loader=yaml\.SafeLoader)'),
            re.compile(r'\bunserialize\s*\(\s*\$'),
        ],
        "severity": "high",
        "description": "Insecure deserialization — arbitrary code execution risk",
        "fix_types": ["sanitize_input", "refactor_code"],
        "language_hint": ["python", "php"],
    },
    "weak_cryptography": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) uses weak cryptography.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Replace MD5/SHA1 with hashlib.sha256 or hashlib.sha3_256. Replace Math.random() "
            "with crypto.getRandomValues() or the Node.js crypto module. Replace DES with AES-256-GCM. "
            "Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)\b(md5|sha1)\s*\('),
            re.compile(r'(?i)hashlib\.(md5|sha1)\s*\('),
            re.compile(r'(?i)Math\.random\s*\('),
            re.compile(r'(?i)DES\s*\(|DES\.new\s*\('),
        ],
        "severity": "medium",
        "description": "Weak or deprecated cryptographic algorithm",
        "fix_types": ["refactor_code"],
        "language_hint": ["python", "javascript"],
    },
    # ── NEW: Prototype Pollution ───────────────────────────────────────────
    "prototype_pollution": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) is vulnerable to prototype pollution.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Avoid merging untrusted objects into existing prototypes. Use Object.create(null) "
            "for plain lookup objects, validate keys against a whitelist before merging, or use "
            "structuredClone() for deep copies. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'Object\.assign\s*\(\s*\w+\s*,\s*(?:req|request|body|params|query|input)'),
            re.compile(r'\b__proto__\b'),
            re.compile(r'\bconstructor\s*\[\s*["\']prototype["\']\s*\]'),
            re.compile(r'(?i)merge\s*\(.*?(?:req\.body|request\.body|user_input)'),
            re.compile(r'(?:lodash|_)\.merge\s*\(\s*\w+\s*,\s*(?:req|body|params)'),
        ],
        "severity": "high",
        "description": "Prototype pollution — attacker can inject properties into Object prototype",
        "fix_types": ["sanitize_input", "refactor_code"],
        "language_hint": ["javascript", "typescript"],
    },
    # ── NEW: SSRF ──────────────────────────────────────────────────────────
    "ssrf": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) is vulnerable to SSRF.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Validate user-supplied URLs against an allowlist of permitted hosts/schemes. "
            "Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x). "
            "Use a URL parsing library to extract and check the hostname before making any request. "
            "Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)fetch\s*\(\s*(?:req|request|params|query|body|user|input)\b'),
            re.compile(r'(?i)requests\.(get|post|put|delete|head)\s*\(\s*(?:url|req|request|user|input)\b'),
            re.compile(r'(?i)urllib\.request\.urlopen\s*\(\s*(?:url|req|user|input)\b'),
            re.compile(r'(?i)axios\.(get|post|put|delete)\s*\(\s*(?:req|body|params|query)'),
            re.compile(r'(?i)http\.get\s*\(\s*(?:req|user|input|url)\b'),
        ],
        "severity": "high",
        "description": "Potential SSRF — server makes requests to user-supplied URLs",
        "fix_types": ["sanitize_input", "refactor_code"],
        "language_hint": ["python", "javascript", "typescript"],
    },
    # ── NEW: Open Redirect ─────────────────────────────────────────────────
    "open_redirect": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) has an open redirect vulnerability.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Validate redirect destinations against a whitelist of allowed paths or domains. "
            "Only allow relative paths, or parse the URL and verify the hostname matches your domain. "
            "Reject or encode any redirect values that include external domains. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)redirect\s*\(\s*(?:req|request)\.(params|query|body)\b'),
            re.compile(r'(?i)res\.redirect\s*\(\s*(?:req|url|next|return_url|redirect_url)\b'),
            re.compile(r'(?i)Location\s*[:=]\s*(?:req|request)\.(params|query|body)'),
            re.compile(r'(?i)window\.location\s*=\s*(?:params|query|searchParams)'),
            re.compile(r'(?i)HttpResponseRedirect\s*\(\s*(?:request|url|next)\b'),
        ],
        "severity": "medium",
        "description": "Open redirect — user input used as redirect target without validation",
        "fix_types": ["sanitize_input", "refactor_code"],
        "language_hint": ["python", "javascript", "typescript", "php"],
    },
    # ── NEW: XXE ───────────────────────────────────────────────────────────
    "xxe": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) has an XXE vulnerability.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Disable external entity processing. In Python use defusedxml instead of xml.etree. "
            "In Java set XMLConstants.FEATURE_SECURE_PROCESSING and disable DOCTYPE declarations. "
            "Set resolve_entities=False in lxml parsers. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)XMLParser\s*\('),
            re.compile(r'(?i)etree\.parse\s*\((?!.*defusedxml)'),
            re.compile(r'(?i)xml\.sax\.parseString\s*\('),
            re.compile(r'(?i)DocumentBuilderFactory(?!.*setFeature.*disallow-doctype)'),
            re.compile(r'(?i)resolve_entities\s*=\s*True'),
        ],
        "severity": "high",
        "description": "XML External Entity (XXE) — unsafe XML parser configuration",
        "fix_types": ["refactor_code"],
        "language_hint": ["python", "java"],
    },
    # ── NEW: IDOR ──────────────────────────────────────────────────────────
    "idor": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) has an IDOR vulnerability.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: After fetching the object by ID, verify that the authenticated user's ID matches "
            "the object's owner field before returning or modifying it. Raise a 403 Forbidden error "
            "if the check fails. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)findById\s*\(\s*(?:req|request)\.(params|query|body)\b'),
            re.compile(r'(?i)\.findOne\s*\(\s*\{\s*(?:_id|id)\s*:\s*(?:req|request)\.(params|query)'),
            re.compile(r'(?i)get_object_or_404\s*\(\s*\w+\s*,\s*(?:pk|id)\s*=\s*(?:request|kwargs)'),
            re.compile(r'(?i)User\.(?:find|get)\s*\(\s*(?:req|params)\b'),
        ],
        "severity": "medium",
        "description": "Insecure Direct Object Reference — object lookup without authorization check",
        "fix_types": ["refactor_code"],
        "language_hint": ["javascript", "typescript", "python"],
    },
    # ── NEW: CORS Misconfiguration ─────────────────────────────────────────
    "cors_misconfiguration": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) has a CORS misconfiguration.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Replace wildcard (*) origins with an explicit list of trusted domains. "
            "Set allow_credentials=False when using wildcards. In production CORS middleware, "
            "supply allow_origins=[...] with your actual frontend URL. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'Access-Control-Allow-Origin\s*[=:]\s*["\']?\*'),
            re.compile(r'(?i)cors\s*\(\s*\)'),
            re.compile(r'(?i)allow_origins\s*=\s*\[\s*["\']?\*["\']?\s*\]'),
            re.compile(r'(?i)origin\s*:\s*true'),
        ],
        "severity": "medium",
        "description": "CORS misconfiguration — overly permissive cross-origin policy",
        "fix_types": ["refactor_code"],
        "language_hint": ["javascript", "typescript", "python"],
    },
    # ── NEW: JWT Verification Bypass ───────────────────────────────────────
    "jwt_no_verification": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) bypasses JWT signature verification.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Remove verify=False and the 'none' algorithm option. Always pass the secret key "
            "and a list of allowed algorithms (e.g. ['HS256']) to jwt.decode(). Wrap decoding in a "
            "try/except for jwt.InvalidTokenError. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)jwt\.decode\s*\(.*?verify\s*=\s*False'),
            re.compile(r'(?i)jwt\.decode\s*\(.*?algorithms\s*=\s*\[\s*["\']none["\']\s*\]'),
            re.compile(r'(?i)jwt\.decode\s*\(.*?options\s*=.*?verify_signature.*?False'),
        ],
        "severity": "high",
        "description": "JWT verification bypass — token decoded without signature validation",
        "fix_types": ["refactor_code"],
        "language_hint": ["python", "javascript", "typescript"],
    },
    # ── NEW: Race Condition ────────────────────────────────────────────────
    "race_condition": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) has a race condition (TOCTOU).\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Wrap the read-check-write sequence in a database transaction with SELECT FOR UPDATE "
            "(or equivalent row-level lock). In Python use threading.Lock() for in-process shared state. "
            "Eliminate the window between the check and the act. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)if\s+.*?balance\s*>=.*?\n.*?balance\s*[-+]?='),
            re.compile(r'(?i)SELECT\s+.*?FOR\s+UPDATE(?!\s*NOWAIT)'),
        ],
        "severity": "medium",
        "description": "Potential race condition — check-then-act pattern without locking",
        "fix_types": ["refactor_code"],
        "language_hint": ["python", "javascript", "typescript", "java", "go"],
    },
    # ── NEW: Mass Assignment ───────────────────────────────────────────────
    "mass_assignment": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) is vulnerable to mass assignment.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Replace direct req.body binding with an explicit allowlist of permitted fields. "
            "In Python pick only safe keys from request.data. In Node.js destructure only the expected "
            "properties before passing to the ORM. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)\.create\s*\(\s*(?:req|request)\.body\s*\)'),
            re.compile(r'(?i)\.update\s*\(\s*(?:req|request)\.body\s*\)'),
            re.compile(r'(?i)Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)'),
            re.compile(r'(?i)\*\*(?:request\.data|request\.POST|kwargs)'),
        ],
        "severity": "medium",
        "description": "Mass assignment — user input directly bound to model without whitelist",
        "fix_types": ["sanitize_input", "refactor_code"],
        "language_hint": ["javascript", "typescript", "python"],
    },
    # ── NEW: Log Injection ─────────────────────────────────────────────────
    "log_injection": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) logs unsanitised user input.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Strip or encode newline characters (\\n, \\r) from user-supplied values before "
            "logging. Use structured logging (key=value pairs) instead of embedding raw input in "
            "format strings. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)logger?\.(info|warn|error|debug)\s*\(\s*f["\'].*?\{(?:req|request|user|input)'),
            re.compile(r'(?i)console\.log\s*\(\s*(?:req|request)\.(?:body|params|query)\b'),
        ],
        "severity": "low",
        "description": "Log injection — user input logged without sanitisation",
        "fix_types": ["sanitize_input"],
        "language_hint": ["python", "javascript", "typescript"],
    },
    # ── NEW: Template Injection (SSTI) ─────────────────────────────────────
    "template_injection": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) is vulnerable to server-side template injection.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Never pass user input as the template string. Use a static template file and pass "
            "user data as context variables only (e.g. render_template('page.html', name=user_input)). "
            "Enable Jinja2 sandboxing if dynamic templates are required. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)Template\s*\(\s*(?:request|req|user|input)\b'),
            re.compile(r'(?i)from_string\s*\(\s*(?:request|req|user|input)\b'),
            re.compile(r'(?i)render_template_string\s*\(\s*(?:request|req|user|input)\b'),
            re.compile(r'(?i)Environment\s*\(.*?autoescape\s*=\s*False'),
        ],
        "severity": "high",
        "description": "Server-side template injection (SSTI) — user input in template string",
        "fix_types": ["sanitize_input", "refactor_code"],
        "language_hint": ["python"],
    },
    # ── NEW: NoSQL Injection ───────────────────────────────────────────────
    "nosql_injection": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) has a NoSQL injection vulnerability.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Validate and sanitise input before using it in MongoDB/DynamoDB queries. "
            "Reject objects with operator keys ($where, $gt, $regex) from user input. "
            "Use an ODM (Mongoose, Motor) with schema validation to enforce field types. "
            "Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)\$where\s*:\s*(?:req|request|user|input)\b'),
            re.compile(r'(?i)\.find\s*\(\s*JSON\.parse\s*\(\s*(?:req|request)'),
            re.compile(r'(?i)collection\.(?:find|update|delete)\s*\(\s*(?:req|request)\.(?:body|query)\s*\)'),
        ],
        "severity": "high",
        "description": "NoSQL injection — user input used in database query operators",
        "fix_types": ["sanitize_input", "prepared_statement"],
        "language_hint": ["javascript", "typescript", "python"],
    },
    # ── NEW: LDAP Injection ────────────────────────────────────────────────
    "ldap_injection": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) has an LDAP injection vulnerability.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Escape all special LDAP characters (*, (, ), \\, NUL) in user input using an "
            "LDAP escape function before constructing filters. Use parameterised LDAP search APIs "
            "where available. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)ldap\.search\s*\(.*?\+.*?(?:user|input|request|param)\b'),
            re.compile(r'(?i)searchFilter\s*=.*?\+.*?(?:req|user|input)\b'),
        ],
        "severity": "high",
        "description": "LDAP injection — user input in LDAP filter without sanitisation",
        "fix_types": ["sanitize_input"],
        "language_hint": ["python", "java", "php"],
    },
    # ── NEW: File Upload ───────────────────────────────────────────────────
    "file_upload": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) has an unrestricted file upload vulnerability.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Add file type validation using an allowlist of MIME types and extensions. "
            "Enforce a maximum file size. Use werkzeug.utils.secure_filename() / multer fileFilter "
            "to sanitise filenames. Store uploads outside the web root. Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)multer\s*\(\s*\{(?!.*fileFilter)'),
            re.compile(r'(?i)move_uploaded_file\s*\(\s*\$'),
            re.compile(r'(?i)request\.files\s*\[.*?\]\.save\s*\((?!.*(?:secure_filename|allowed_ext))'),
        ],
        "severity": "medium",
        "description": "Unrestricted file upload — no file type or size validation detected",
        "fix_types": ["sanitize_input", "refactor_code"],
        "language_hint": ["python", "javascript", "typescript", "php"],
    },
    # ── NEW: Hardcoded Credentials ─────────────────────────────────────────
    "hardcoded_credentials": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) contains hardcoded credentials.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Move the secret to an environment variable. Replace the literal with "
            "os.environ['VAR_NAME'] (Python) or process.env.VAR_NAME (Node.js). "
            "Add the variable name to .env.example with an empty value as documentation. "
            "Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)(?:password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']'),
            re.compile(r'(?i)(?:api_key|apikey|secret_key)\s*=\s*["\'][A-Za-z0-9_\-/+=]{12,}["\']'),
            re.compile(r'(?i)(?:DB_PASSWORD|DATABASE_PASSWORD)\s*=\s*["\'][^"\']+["\']'),
        ],
        "severity": "high",
        "description": "Hardcoded credentials — password or API key assigned directly in source code",
        "fix_types": ["move_to_env"],
        "language_hint": ["python", "javascript", "typescript", "java", "go", "ruby"],
    },
    # ── NEW: Insecure Cookie ───────────────────────────────────────────────
    "insecure_cookie": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) sets an insecure cookie.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Add Secure=True, HttpOnly=True, and SameSite='Strict' (or 'Lax') to all "
            "session and authentication cookies. In Express: res.cookie(name, val, "
            "{secure:true, httpOnly:true, sameSite:'strict'}). In Python/Flask use "
            "response.set_cookie(..., secure=True, httponly=True, samesite='Strict'). "
            "Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)set[_-]?cookie\s*\((?!.*(?:secure|httponly|samesite))'),
            re.compile(r'(?i)res\.cookie\s*\(\s*["\'][^"\']+["\']\s*,\s*[^,]+\s*\)(?!\s*;?\s*\{)'),
        ],
        "severity": "medium",
        "description": "Insecure cookie — missing Secure, HttpOnly, or SameSite flags",
        "fix_types": ["refactor_code"],
        "language_hint": ["python", "javascript", "typescript"],
    },
    # ── NEW: Debug Mode ────────────────────────────────────────────────────
    "debug_mode": {
        "fix_prompt_template": (
            "The file `{file}` (line {line}) enables debug mode.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Set DEBUG to False (or read from an environment variable: "
            "DEBUG=os.getenv('DEBUG','False')=='True'). Remove app.run(debug=True) from production "
            "entry points. Use a production WSGI server (gunicorn/uvicorn) instead. "
            "Return the corrected file."
        ),
        "patterns": [
            re.compile(r'(?i)DEBUG\s*=\s*True'),
            re.compile(r'(?i)app\.run\s*\(.*?debug\s*=\s*True'),
            re.compile(r'(?i)FLASK_DEBUG\s*=\s*1'),
        ],
        "severity": "medium",
        "description": "Debug mode enabled — may expose stack traces and internals in production",
        "fix_types": ["refactor_code"],
        "language_hint": ["python", "javascript", "typescript"],
    },
}

# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------
IGNORED_DIRS: frozenset[str] = frozenset({
    ".git", ".next", "__pycache__", "node_modules",
    ".venv", "venv", "dist", "build", "coverage",
})

SCANNABLE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx",
    ".php", ".rb", ".java", ".go", ".cs",
    ".sh", ".bash",
})

EXT_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".php": "php",
    ".rb": "ruby",
    ".java": "java",
    ".go": "go",
    ".cs": "csharp",
    ".sh": "bash",
    ".bash": "bash",
}

MAX_FILE_SIZE = 500_000  # bytes


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_repository(repo_path: Path) -> list[dict[str, Any]]:
    """
    Scan all code files in *repo_path* for security vulnerabilities.

    Returns a list of findings. Each finding has the shape:
    {
        "id":          int,
        "source":      "code",
        "type":        str,          # e.g. "sql_injection"
        "severity":    "high" | "medium" | "low",
        "description": str,
        "file":        str,          # relative path
        "line":        int,
        "preview":     str,          # truncated offending line
        "language":    str,
        "fix_types":   list[str],
        "fixable":     bool,
    }
    """
    findings: list[dict[str, Any]] = []
    finding_id = 1

    for file_path in _iter_code_files(repo_path):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.warning("scanner: cannot read %s — %s", file_path, exc)
            continue

        lines = content.splitlines()
        relative = str(file_path.relative_to(repo_path))
        language = EXT_TO_LANGUAGE.get(file_path.suffix.lower(), "unknown")

        for vuln_type, cfg in VULN_PATTERNS.items():
            # Skip pattern if language hint doesn't match (avoids false positives)
            hints: list[str] = cfg.get("language_hint", [])
            if hints and language not in hints and language != "unknown":
                continue

            matched_lines: set[int] = set()
            for pattern in cfg["patterns"]:
                for line_num, line in enumerate(lines, start=1):
                    if line_num in matched_lines:
                        continue
                    if pattern.search(line):
                        findings.append({
                            "id": finding_id,
                            "source": "code",
                            "type": vuln_type,
                            "severity": cfg["severity"],
                            "description": cfg["description"],
                            "file": relative,
                            "line": line_num,
                            "preview": line.strip()[:200],
                            "language": language,
                            "fix_types": list(cfg["fix_types"]),
                            "fixable": True,
                        })
                        finding_id += 1
                        matched_lines.add(line_num)
                        break  # one finding per pattern per file

    logger.info("scanner: %d vulnerability findings in %s", len(findings), repo_path)
    return findings


def calculate_security_score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Derive a 0-100 security score from a combined findings list.
    Returns score, letter grade, and per-severity breakdown.
    """
    DEDUCTIONS = {"high": 15, "medium": 8, "low": 3}

    total_deduction = sum(DEDUCTIONS.get(f.get("severity", "low"), 3) for f in findings)
    score = max(0, 100 - total_deduction)

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    by_severity: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in by_severity:
            by_severity[sev] += 1

    by_type: dict[str, int] = {}
    for f in findings:
        t = f.get("type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1

    return {
        "score": score,
        "grade": grade,
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_type": by_type,
        "summary": f"Security score: {score}/100 (Grade {grade}) — {len(findings)} findings",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _iter_code_files(repo_path: Path):
    """Yield scannable code files, skipping ignored dirs and large files."""
    for path in repo_path.rglob("*"):
        if path.is_dir():
            continue
        rel_parts = path.relative_to(repo_path).parts
        if any(part in IGNORED_DIRS for part in rel_parts):
            continue
        if path.suffix.lower() not in SCANNABLE_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        yield path


# ---------------------------------------------------------------------------
# LLM prompt helpers
# ---------------------------------------------------------------------------

def get_fix_prompt(finding: dict[str, Any], file_content: str) -> str:
    """
    Build a vulnerability-specific LLM prompt for a given finding.

    Uses the ``fix_prompt_template`` embedded in VULN_PATTERNS for the
    finding type, then appends the full file content so the model can
    return a corrected version.

    Args:
        finding:      A finding dict as returned by scan_repository().
        file_content: The current source code of the affected file.

    Returns:
        A ready-to-send prompt string.
    """
    vuln_type = finding.get("type", "unknown")
    cfg = VULN_PATTERNS.get(vuln_type, {})
    template = cfg.get(
        "fix_prompt_template",
        (
            "The file `{file}` (line {line}) has a security vulnerability: {description}.\n"
            "Offending code: `{preview}`\n\n"
            "TASK: Fix this vulnerability following security best practices. "
            "Return the complete corrected file content."
        ),
    )

    intro = template.format(
        file=finding.get("file", "unknown"),
        line=finding.get("line", "?"),
        preview=finding.get("preview", ""),
        description=finding.get("description", vuln_type),
    )

    return (
        f"{intro}\n\n"
        "---\n"
        f"Current file content (`{finding.get('file', '')}`):\n"
        "```\n"
        f"{file_content}\n"
        "```\n\n"
        "Return ONLY the corrected, complete file content — no explanations, "
        "no markdown fences, no truncation."
    )
