import fs from "fs";
import path from "path";
import { createHash } from "node:crypto";
import { getDockerInstance } from "./dockerOrchestrator.js";
import { analyzeDependencies } from "./dependencyAnalyzer.js";
import {
    calculateProjectRisk,
    standardizeFinding
} from "./riskPrioritizationEngine.js";
import {
    analyzeAstSource,
    ProjectBudgetManager,
    ProjectTaintCoordinator
} from "./ast/index.js";
import {
    createSinkIdentity,
    reconcileFindingsBySinkIdentity
} from "./findingIdentity.js";
import {
    classifyProjectFile,
    isProjectConfigurationFile,
    readProjectFile
} from "./projectFileReader.js";

const docker = getDockerInstance();
const ANALYZER_LIMITS = Object.freeze({
    dockerOperationTimeoutMs: 10000,
    maxFiles: 10000,
    maxFileBytes: 10 * 1024 * 1024,
    maxTotalBytes: 100 * 1024 * 1024,
    maxDepth: 32
});
const EXCLUDED_SOURCE_DIRECTORIES = new Set([
    ".cache", ".git", ".gradle", ".next", ".pytest_cache", ".terraform", ".venv",
    "__macosx", "__pycache__", "bin", "build", "coverage", "dist", "node_modules",
    "out", "site-packages", "target", "vendor", "venv"
]);

const withDeadline = (operation, timeoutMs, signal) => new Promise((resolve, reject) => {
    if (signal?.aborted) {
        reject(signal.reason || new Error("Analysis cancelled"));
        return;
    }
    let settled = false;
    const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        callback(value);
    };
    const onAbort = () => finish(reject, signal.reason || new Error("Analysis cancelled"));
    const timer = setTimeout(() => {
        const error = new Error("Analysis operation timed out");
        error.code = "ANALYSIS_TIMEOUT";
        finish(reject, error);
    }, timeoutMs);
    signal?.addEventListener("abort", onAbort, { once: true });
    Promise.resolve().then(operation).then(
        (value) => finish(resolve, value),
        (error) => finish(reject, error)
    );
});

/**
 * Production Readiness Analyzer
 * Checks Docker image, Dockerfile and project structure
 */

const isSupportedTextFile = (fileName) =>
    ["source", "document", "configuration"].includes(classifyProjectFile(fileName));

const isConfigurationFile = (fileName) =>
    isProjectConfigurationFile(fileName);

const isPlaceholderSecret = (value) => {
    const normalized = value.trim().toLowerCase();
    return normalized.length < 8 ||
          /(?:process\.env|system\.getenv|os\.(?:getenv|environ)|environ\.get|env\(|\$\{|\$[A-Z_][A-Z0-9_]*|secretmanager|keyvault)/i.test(normalized) ||
          /^(?:your|example|sample|dummy|fake|test|testing|changeme|change_me|replace_me|redacted|placeholder|not[_ -]a[_ -]secret|none|null|undefined)(?:[-_.].*)?$/.test(normalized) ||
        /^(?:x+|0+|1+|123456+|<[^>]*>|\*+)$/.test(normalized) ||
          /(?:example|placeholder|changeme|redacted|dummy[_-]?value|fake[_-]?credential)/.test(normalized) ||
          /^(?:sk|pk)_test_/.test(normalized);
};
const normalizeCredentialLabel = (value) =>
    value.normalize("NFKC").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim();
const CREDENTIAL_LABEL_VALUES = new Set([
    "access token",
    "api key",
    "chave de acesso",
    "chave de api",
    "chave privada",
    "klucz api",
    "klucz prywatny",
    "ключ api",
    "закрытый ключ",
    "пароль",
    "privat nyckel",
    "private key",
    "lösenord",
    "senha",
    "token",
    "token de acesso",
    "token dostępu",
    "токен доступа",
    "åtkomsttoken"
]);
const isCredentialLabelValue = (value) =>
    CREDENTIAL_LABEL_VALUES.has(normalizeCredentialLabel(value));

const CREDENTIAL_KEY_PATTERN = [
    "api[_-]?(?:key|token|secret)",
    "(?:access|auth|refresh|id|bearer|service)[_-]?token|token",
    "(?:client|consumer)[_-]?secret",
    "(?:jwt|session|webhook|signing)[_-]?secret|secret(?:[_-]?(?:key|token|value))?",
    "(?:password|passwd|passphrase|pwd)",
    "(?:private|signing|encryption)[_-]?key",
    "(?:aws[_-]?)?(?:secret[_-]?access[_-]?key|access[_-]?key[_-]?id)",
    "(?:azure|storage|account)[_-]?(?:client[_-]?)?secret",
    "(?:account[_-]?key|shared[_-]?access[_-]?signature)",
    "(?:gcp|google)[_-]?(?:private[_-]?key|api[_-]?key)",
    "(?:database|db|mongo(?:db)?)[_-]?(?:url|uri|password)",
    "(?:[a-z0-9]+[_-])?connection[_-]?string|credential"
].join("|");
const CREDENTIAL_ASSIGNMENT_PATTERN = new RegExp(
    `["']?(${CREDENTIAL_KEY_PATTERN})["']?\\s*(?::\\s*[A-Za-z_]\\w*(?:\\[[^\\]\\r\\n]+\\])?\\s*)?(?:=|:)\\s*(?:"""([^"\\r\\n]*)"""|'''([^'\\r\\n]*)'''|"([^"\\r\\n]*)"|'([^'\\r\\n]*)'|\`([^\`\\r\\n]*)\`|([^\\s,;}\\]]+))`,
    "gi"
);
const MULTILINE_CREDENTIAL_ASSIGNMENT_PATTERN = new RegExp(
    `["']?(${CREDENTIAL_KEY_PATTERN})["']?[ \\t]*(?::[ \\t]*[A-Za-z_]\\w*(?:\\[[^\\]\\r\\n]+\\])?[ \\t]*)?(?:=|:)[ \\t]*(?:"""([\\s\\S]*?)"""|'''([\\s\\S]*?)'''|\`([\\s\\S]*?)\`)`,
    "gi"
);
const PROVIDER_CREDENTIAL_PATTERNS = [
    { type: "AWS access key", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, cwe: "CWE-798" },
    { type: "GitHub token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, cwe: "CWE-798" },
    { type: "Slack token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/g, cwe: "CWE-798" },
    { type: "Stripe secret key", pattern: /\bsk_live_[A-Za-z0-9]{16,}\b/g, cwe: "CWE-798" },
    { type: "Google API key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, cwe: "CWE-798" }
];
const SQL_STATEMENT_PATTERN = /\b(?:SELECT\b|INSERT\s+INTO\b|UPDATE\s+[\w"`\[]+|DELETE\s+FROM\b)/i;
const SQL_EXECUTION_PATTERN = /(?:\b[\w$]+\s*\.\s*)?(?:query|execute|executemany|raw|exec)\s*\(/gi;
const NODE_COMMAND_PATTERN = /(?:\bchild_process\s*\.\s*)?(execFileSync|execFile|execSync|exec|spawnSync|spawn)\s*\(/gi;
const PYTHON_COMMAND_PATTERN = /\b(?:os|subprocess)\s*\.\s*(system|popen|run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(/gi;
const USER_INPUT_PATTERN = /\b(?:req\.(?:query|params|body)|request\.(?:args|form|values)|process\.argv|sys\.argv|input\s*\()/i;
const USER_INPUT_ASSIGNMENT_PATTERNS = [
    /(?:^|[;\r\n])\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:req\.(?:query|params|body)|request\.(?:args|form|values)|process\.argv|sys\.argv|input\s*\()/gi,
    /^\s*([A-Za-z_$][\w$]*)\s*=\s*(?:req\.(?:query|params|body)|request\.(?:args|form|values)|process\.argv|sys\.argv|input\s*\()/gim
];
const isInjectionSourceFile = (fileName) =>
    /\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts|py|pyi)$/i.test(fileName);
const isDeserializationSourceFile = (fileName) =>
    /\.(?:py|pyi|js|jsx|mjs|cjs|ts|tsx|mts|cts)$/i.test(fileName);
const isDynamicExecutionSourceFile = (fileName) =>
    /\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$/i.test(fileName);

const PYTHON_PICKLE_CALL_PATTERN = /\b(?:pickle|_pickle|cPickle)\s*\.\s*(loads?|Unpickler)\s*\(/gi;
const PYTHON_YAML_CALL_PATTERN = /\byaml\s*\.\s*(load|load_all|unsafe_load|unsafe_load_all)\s*\(/gi;
const PYTHON_SAFE_YAML_LOADERS = /\b(?:yaml\.)?(?:SafeLoader|CSafeLoader|BaseLoader|CBaseLoader)\b/;
const PYTHON_MARSHAL_CALL_PATTERN = /\bmarshal\s*\.\s*(loads?)\s*\(/gi;
const PYTHON_SHELVE_CALL_PATTERN = /\bshelve\s*\.\s*open\s*\(/gi;
const NODE_SERIALIZE_CALL_PATTERN = /(?:\b(?:nodeSerialize|serialize)\s*\.\s*unserialize|\bunserialize)\s*\(/gi;

const JS_EVAL_CALL_PATTERN = /(?:(?:\b(?:window|global|globalThis)\s*\.\s*)|\b(?<![\w$.]))eval\s*\(/gi;
const JS_FUNCTION_CONSTRUCTOR_PATTERN = /(?:(?:\b(?:window|global|globalThis)\s*\.\s*)?(?:\bnew\s+)?(?<![\w$])Function)\s*\(/g;
const NODE_VM_CALL_PATTERN = /\bvm\s*\.\s*(?:runInContext|runInNewContext|runInThisContext|compileFunction|Script)\s*\(/gi;
const JS_TIMER_CALL_PATTERN = /(?:\b(?:window|global|globalThis)\s*\.\s*)?(?:setTimeout|setInterval|setImmediate)\s*\(/gi;

const collectStringRanges = (content) => {
    const ranges = [];
    let quote = null;
    let quoteStart = -1;
    let escaped = false;
    let commentEnd = null;
    const templateDepths = [];

    for (let index = 0; index < content.length; index += 1) {
        const character = content[index];
        const next = content[index + 1];
        if (commentEnd) {
            if (content.startsWith(commentEnd, index)) {
                index += commentEnd.length - 1;
                commentEnd = null;
            }
            continue;
        }
        if (quote) {
            if (escaped) {
                escaped = false;
            } else if (character === "\\") {
                escaped = true;
            } else if (quote === "`" && character === "$" && next === "{") {
                ranges.push([quoteStart, index + 2]);
                templateDepths.push(1);
                quote = null;
                index += 1;
            } else if (content.startsWith(quote, index)) {
                const quoteEnd = index + quote.length;
                ranges.push([quoteStart, quoteEnd]);
                index += quote.length - 1;
                quote = null;
            }
            continue;
        }
        if (templateDepths.length > 0) {
            if (character === "{") {
                templateDepths[templateDepths.length - 1] += 1;
            } else if (character === "}") {
                templateDepths[templateDepths.length - 1] -= 1;
                if (templateDepths[templateDepths.length - 1] === 0) {
                    templateDepths.pop();
                    quote = "`";
                    quoteStart = index;
                    continue;
                }
            }
        }
        if (character === "'" || character === '"' || character === "`") {
            const delimiter = character.repeat(3);
            quote = content.startsWith(delimiter, index) ? delimiter : character;
            quoteStart = index;
            index += quote.length - 1;
            continue;
        }
        if (content.startsWith("<!--", index)) {
            commentEnd = "-->";
            index += 3;
            continue;
        }
        if (character === "/" && next === "*") {
            commentEnd = "*/";
            index += 1;
            continue;
        }
        const isLineComment = character === "/" && next === "/" &&
            (index === 0 || /[\s;{}),]/.test(content[index - 1]));
        const isHashComment = character === "#" &&
            (index === 0 || /\s/.test(content[index - 1]));
        if (isLineComment || isHashComment) {
            while (index < content.length && content[index] !== "\n" && content[index] !== "\r") {
                index += 1;
            }
            index -= 1;
        }
    }
    return ranges;
};

const isInsideRange = (offset, ranges) =>
    ranges.some(([start, end]) => offset >= start && offset < end);
const isSqlDynamicExpression = (expression) => {
    if (!SQL_STATEMENT_PATTERN.test(expression)) return false;
    return /`[^`]*\$\{[\s\S]*?`/.test(expression) ||
        /\bf(?:'''|"""|'|")[\s\S]*?\{[^{}]+\}[\s\S]*?(?:'''|"""|'|")/i.test(expression) ||
        /(?:["'`])(?:\\.|[^"'`])*?(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[\s\S]*?(?:["'`])\s*\+/i.test(expression) ||
        /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[\s\S]*?["'`]\s*\+\s*[A-Za-z_$]/i.test(expression) ||
        /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[\s\S]*?["'`]\s*\.format\s*\(/i.test(expression) ||
        /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[\s\S]*?["'`]\s*%\s*(?:\(|[A-Za-z_$])/i.test(expression);
};
const findCallArguments = (source, openParenthesis) => {
    const argumentsList = [];
    let argumentStart = openParenthesis + 1;
    let depth = 1;
    let quote = null;
    let escaped = false;
    for (let index = argumentStart; index < source.length; index += 1) {
        const character = source[index];
        if (quote) {
            if (escaped) escaped = false;
            else if (character === "\\") escaped = true;
            else if (source.startsWith(quote, index)) {
                index += quote.length - 1;
                quote = null;
            }
            continue;
        }
        if (character === "'" || character === '"' || character === "`") {
            const delimiter = character.repeat(3);
            quote = source.startsWith(delimiter, index) ? delimiter : character;
            index += quote.length - 1;
            continue;
        }
        if (character === "(" || character === "[" || character === "{") {
            depth += 1;
        } else if (character === ")" || character === "]" || character === "}") {
            depth -= 1;
            if (depth === 0) {
                argumentsList.push(source.slice(argumentStart, index).trim());
                return argumentsList;
            }
        } else if (character === "," && depth === 1) {
            argumentsList.push(source.slice(argumentStart, index).trim());
            argumentStart = index + 1;
        }
    }
    return null;
};
const isCredentialExemptPath = (relativePath, fileName) => {
    const normalizedPath = relativePath.toLowerCase();
    return classifyProjectFile(fileName) === "document" ||
        /(?:^|\/)(?:__tests__|tests?|specs?|fixtures?|samples?|examples?|docs?)(?:\/|$)/.test(normalizedPath) ||
        /(?:^|[._-])(?:example|sample|template|fixture|test)(?:[._-]|$)/.test(fileName.toLowerCase());
};
const isCommentOnlyLine = (line) => /^\s*(?:#|\/\/|\/\*|\*|<!--)/.test(line);
const maskComments = (content) => {
    const characters = content.split("");
    let quote = null;
    let escaped = false;
    let commentEnd = null;

    for (let index = 0; index < content.length; index += 1) {
        const character = content[index];
        const next = content[index + 1];
        if (commentEnd) {
            if (content.startsWith(commentEnd, index)) {
                for (let end = index; end < index + commentEnd.length; end += 1) {
                    if (characters[end] !== "\n" && characters[end] !== "\r") characters[end] = " ";
                }
                index += commentEnd.length - 1;
                commentEnd = null;
                continue;
            }
            if (character !== "\n" && character !== "\r") characters[index] = " ";
            continue;
        }
        if (quote) {
            if (escaped) {
                escaped = false;
            } else if (character === "\\") {
                escaped = true;
            } else if (content.startsWith(quote, index)) {
                index += quote.length - 1;
                quote = null;
            }
            continue;
        }
        if (character === "'" || character === '"' || character === "`") {
            const delimiter = character.repeat(3);
            quote = content.startsWith(delimiter, index) ? delimiter : character;
            index += quote.length - 1;
            continue;
        }
        if (content.startsWith("<!--", index)) {
            commentEnd = "-->";
            for (let end = index; end < index + 4; end += 1) characters[end] = " ";
            index += 3;
            continue;
        }
        if (character === "/" && next === "*") {
            commentEnd = "*/";
            characters[index] = " ";
            characters[index + 1] = " ";
            index += 1;
            continue;
        }
        const isLineComment = character === "/" && next === "/" &&
            (index === 0 || /[\s;{}),]/.test(content[index - 1]));
        const isHashComment = character === "#" &&
            (index === 0 || /\s/.test(content[index - 1]));
        if (isLineComment || isHashComment) {
            while (index < content.length && content[index] !== "\n" && content[index] !== "\r") {
                characters[index] = " ";
                index += 1;
            }
            index -= 1;
        }
    }

    return characters.join("");
};
const isEnvironmentReference = (value) =>
    /^(?:(?:process\.env|os\.(?:getenv|environ)|environ\.get|System\.getenv|env)\b|\$\{|\$[A-Z_][A-Z0-9_]*|["']?\{\{?\s*secrets?\.)/i.test(value.trim());
const hasCredentialEntropy = (value) =>
    value.length >= 24 && new Set(value.replace(/[^A-Za-z0-9]/g, "")).size >= 10;

const safeRelativePath = (rootPath, filePath) => {
    const relativePath = path.relative(path.resolve(rootPath), path.resolve(filePath));
    if (!relativePath || path.isAbsolute(relativePath) || relativePath === ".." ||
        relativePath.startsWith(`..${path.sep}`)) return null;
    return relativePath.split(path.sep)
        .map((part) => part.replace(/[^\w.@+-]/g, "_"))
        .join("/");
};

const redactProjectTaintTrace = (trace) => {
    const secretPatterns = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{16,}\b|\bsk_live_[A-Za-z0-9]{16,}\b|\bAIza[0-9A-Za-z_-]{35}\b/g;
    const sanitize = (value) => {
        if (typeof value === "string") {
            return value
                .replace(/(['"`])(?:\\.|(?!\1)[^\\])*?\1/g, "<literal>")
                .replace(secretPatterns, "<redacted>")
                .replace(/:\/\/([^:/\s]+):([^@/\s]+)@/g, "://$1:<redacted>@")
                .replace(/\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;}]+/gi, "$1=<redacted>");
        }
        if (Array.isArray(value)) return value.map(sanitize);
        if (!value || typeof value !== "object") return value;
        return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitize(item)]));
    };
    return sanitize(trace);
};

const createLineNumberLookup = (content) => {
    let lastOffset = 0;
    let lineNumber = 1;
    return (offset) => {
        if (offset < lastOffset) {
            lastOffset = 0;
            lineNumber = 1;
        }
        for (let index = lastOffset; index < offset; index += 1) {
            if (content.charCodeAt(index) === 10) lineNumber += 1;
        }
        lastOffset = offset;
        return lineNumber;
    };
};

export async function analyzeProduction(
    buildContext,
    imageName,
    container = null,
    dependencies = {}
) {
    const fileSystem = dependencies.fs || fs;
    const dockerClient = dependencies.docker || docker;
    const staticOnly = dependencies.staticOnly === true;
    const logger = dependencies.logger || console;
    const checks = new Map([
        ["dockerfile_presence", "completed"],
        ["dockerfile_configuration", "completed"],
        ["dockerignore_configuration", "completed"],
        ["environment_configuration", "completed"],
        ["image_metadata", staticOnly ? "skipped" : "completed"],
        ["runtime_inspection", container ? "completed" : "skipped"],
        ["secret_pattern_search", "completed"],
        ["sql_injection_pattern_search", "completed"],
        ["os_command_injection_pattern_search", "completed"],
        ["unsafe_deserialization_pattern_search", "completed"],
        ["dynamic_code_execution_pattern_search", "completed"],
        ["insecure_transport_configuration", "completed"],
        ["dangerous_application_configuration", "completed"],
        ["project_structure", "completed"],
        ["owasp_top_10", "unsupported"],
        ["dynamic_vulnerability_testing", "unsupported"],
        ["dependency_vulnerability_analysis", "failed"],
        ["exploit_verification", "unsupported"]
    ]);
    const checkReasons = new Map([
        ...(staticOnly ? [["image_metadata", "static_only_scope"]] : []),
        ...(!container ? [["runtime_inspection", "no_container_provided"]] : []),
        ["owasp_top_10", "not_implemented"],
        ["dynamic_vulnerability_testing", "not_implemented"],
        ["dependency_vulnerability_analysis", "dependency_analysis_not_completed"],
        ["exploit_verification", "not_implemented"]
    ]);
    const checkDefinitions = {
        dockerfile_presence: {
            name: "Dockerfile presence",
            category: "configuration",
            categoryName: "Configuration analysis",
            scope: "Whether the selected build context contains a Dockerfile."
        },
        dockerfile_configuration: {
            name: "Dockerfile configuration",
            category: "configuration",
            categoryName: "Configuration analysis",
            scope: "Selected Dockerfile heuristics: non-root USER, HEALTHCHECK, build stages, image tags, and npm install usage."
        },
        dockerignore_configuration: {
            name: ".dockerignore configuration",
            category: "configuration",
            categoryName: "Configuration analysis",
            scope: "Presence and node_modules exclusion in the selected build context."
        },
        environment_configuration: {
            name: "Environment configuration",
            category: "configuration",
            categoryName: "Configuration analysis",
            scope: "Whether an .env.example is present without a corresponding .env file."
        },
        image_metadata: {
            name: "Docker image metadata",
            category: "container_metadata",
            categoryName: "Container metadata",
            scope: "Image availability and metadata from the Docker daemon, including image size."
        },
        runtime_inspection: {
            name: "Runtime inspection",
            category: "runtime_inspection",
            categoryName: "Runtime inspection",
            scope: "Container state and runtime metadata from the Docker daemon."
        },
        secret_pattern_search: {
            name: "Hard-coded credential indicators",
            category: "credential_indicators",
            categoryName: "Credential indicators",
            scope: "Bounded checks for literal credential assignments, provider token formats, and PEM private keys in supported UTF-8 source and configuration files. Documentation, examples, and test/fixture paths are excluded from credential matches; patterns do not establish that a credential is active. Excludes .git, dependencies, virtual environments, caches, and generated build directories."
        },
        sql_injection_pattern_search: {
            name: "SQL injection patterns",
            category: "injection_indicators",
            categoryName: "Injection indicators",
            scope: "Bounded syntax patterns for dynamically constructed SQL passed to common JavaScript/TypeScript and Python database query APIs. This is not taint or data-flow analysis and does not establish exploitability."
        },
        os_command_injection_pattern_search: {
            name: "OS command injection patterns",
            category: "injection_indicators",
            categoryName: "Injection indicators",
            scope: "Bounded syntax patterns for user-input indicators passed to shell-based command APIs and process argument APIs in JavaScript/TypeScript and Python. This is not taint or data-flow analysis and does not establish exploitability."
        },
        unsafe_deserialization_pattern_search: {
            name: "Unsafe deserialization patterns",
            category: "deserialization_indicators",
            categoryName: "Deserialization indicators",
            scope: "Bounded syntax patterns for unsafe object deserialization APIs (such as Python pickle, marshal, shelve, PyYAML unsafe loading, and Node.js serialization libraries) in supported Python and JavaScript/TypeScript source files. This is not taint or data-flow analysis and does not establish exploitability."
        },
        dynamic_code_execution_pattern_search: {
            name: "Dynamic code execution patterns",
            category: "dynamic_execution_indicators",
            categoryName: "Dynamic execution indicators",
            scope: "Bounded syntax patterns for dynamic code evaluation APIs (such as eval, Function constructor, Node.js vm execution, and timer string evaluation) in JavaScript and TypeScript source files. This is not taint or data-flow analysis and does not establish exploitability."
        },
        insecure_transport_configuration: {
            name: "Insecure transport configuration",
            category: "configuration",
            categoryName: "Configuration analysis",
            scope: "Explicit TLS verification disabling and non-local HTTP URLs in security-sensitive settings within supported UTF-8 source and configuration files."
        },
        dangerous_application_configuration: {
            name: "Dangerous application configuration",
            category: "configuration",
            categoryName: "Configuration analysis",
            scope: "Explicit wildcard CORS and debug-enabled settings only when production intent is declared in the same supported configuration file."
        },
        project_structure: {
            name: "Project structure",
            category: "project_structure",
            categoryName: "Project structure",
            scope: "Selected project structure heuristics such as README, lockfile, and node_modules presence."
        },
        owasp_top_10: {
            name: "OWASP Top 10 assessment",
            category: "application_security",
            categoryName: "Application security assessment",
            scope: "Application-level OWASP Top 10 analysis."
        },
        dynamic_vulnerability_testing: {
            name: "Dynamic vulnerability testing",
            category: "dynamic_testing",
            categoryName: "Dynamic testing",
            scope: "Runtime probing for application vulnerabilities."
        },
        dependency_vulnerability_analysis: {
            name: "Dependency vulnerability analysis",
            category: "dependency_analysis",
            categoryName: "Dependency analysis",
            scope: "Supported npm and Python lockfiles and exact package versions queried against OSV; other ecosystems are not scanned."
        },
        exploit_verification: {
            name: "Exploit verification",
            category: "exploit_verification",
            categoryName: "Exploit verification",
            scope: "Verification that reported vulnerabilities are exploitable in this application."
        }
    };
    const markCheck = (checkId, status, reason) => {
        checks.set(checkId, status);
        if (reason) checkReasons.set(checkId, reason);
        else checkReasons.delete(checkId);
    };

    const report = {
        score: 100,
        status: "PASS",
        issues: [],
        recommendations: [],
        runtime: {},
        docker: {},
        security: {},
        project: {}
    };

    //---------------------------------------------------
    // Helper
    //---------------------------------------------------

    const addIssue = (severity, title, description, recommendation, checkId, extra = {}) => {

        report.issues.push({
            severity,
            title,
            description,
            recommendation,
            checkId,
            ...extra
        });

        report.recommendations.push(recommendation);
    };

    //---------------------------------------------------
    // Files
    //---------------------------------------------------

    const dockerfilePath = path.join(buildContext, "Dockerfile");

    const dockerignorePath = path.join(buildContext, ".dockerignore");

    const envPath = path.join(buildContext, ".env");

    const envExample = path.join(buildContext, ".env.example");
    const readConfigurationFile = (filePath, checkId) => {
        try {
            const metadata = fileSystem.lstatSync(filePath);
            if (!metadata.isFile() || metadata.size > 1024 * 1024) {
                markCheck(checkId, "failed", "configuration_input_invalid");
                logger.warn("Analyzer configuration file exceeded its read limit", {
                    check: checkId
                });
                return "";
            }
            return readProjectFile(fileSystem, filePath, {
                maxBytes: 1024 * 1024,
                rootPath: buildContext
            }).content;
        } catch (error) {
            const invalidInput = [
                "PROJECT_FILE_TOO_LARGE",
                "PROJECT_FILE_NOT_REGULAR",
                "PROJECT_FILE_BINARY",
                "PROJECT_FILE_INVALID_UTF8",
                "PROJECT_FILE_UNSUPPORTED_ENCODING"
            ].includes(error.code);
            markCheck(
                checkId,
                "failed",
                invalidInput ? "configuration_input_invalid" : "configuration_input_unreadable"
            );
            logger.warn("Analyzer configuration file could not be read", {
                check: checkId,
                code: error.code || error.name || "UNKNOWN"
            });
            return "";
        }
    };

    //---------------------------------------------------
    // Dockerfile Exists
    //---------------------------------------------------

    const dockerfileExists = fileSystem.existsSync(dockerfilePath);
    if (!dockerfileExists) {

        addIssue(
            "Critical",
            "Dockerfile Missing",
            "Project has no Dockerfile.",
            "Create a production Dockerfile.",
            "dockerfile_presence",
            {
                ruleId: undefined,
                category: "configuration",
                confidence: "High",
                cwe: ["CWE-1059"],
                file: null,
                line: null,
                severityRationale: "A missing Dockerfile prevents reproducible containerized builds and safe privilege isolation.",
                origin: "configuration_analysis"
            }
        );

        markCheck("dockerfile_configuration", "skipped", "dockerfile_missing");
        markCheck("dockerignore_configuration", "skipped", "dockerfile_missing");
    } else {
        markCheck("dockerfile_configuration", "completed");
    }

    //---------------------------------------------------
    // Read Dockerfile
    //---------------------------------------------------

    const dockerfile = dockerfileExists
        ? readConfigurationFile(dockerfilePath, "dockerfile_configuration")
        : "";

    //---------------------------------------------------
    // Dockerignore
    //---------------------------------------------------

    if (!dockerfileExists) {
        markCheck("dockerignore_configuration", "skipped", "dockerfile_missing");
    } else if (!fileSystem.existsSync(dockerignorePath)) {

        addIssue(
            "Medium",
            ".dockerignore Missing",
            "Docker will copy unnecessary files.",
            "Create a .dockerignore file.",
            "dockerignore_configuration",
            {
                ruleId: "LUM-CFG-DOCKERIGNORE-MISSING",
                category: "configuration",
                confidence: "High",
                cwe: ["CWE-200"],
                file: null,
                line: null,
                severityRationale: "Absence of .dockerignore allows local secrets, credentials, and build artifacts to be inadvertently baked into images.",
                origin: "configuration_analysis"
            }
        );

    } else {

        report.project.dockerignore = true;

        // Check .dockerignore contents
        const ignore = readConfigurationFile(dockerignorePath, "dockerignore_configuration");

        if (!ignore.includes("node_modules")) {

            addIssue(
                "Medium",
                ".dockerignore Incomplete",
                "node_modules isn't ignored.",
                "Add node_modules to .dockerignore.",
                "dockerignore_configuration",
                {
                    ruleId: "LUM-CFG-DOCKERIGNORE-INCOMPLETE",
                    category: "configuration",
                    confidence: "High",
                    cwe: ["CWE-200"],
                    file: ".dockerignore",
                    line: null,
                    severityRationale: "Excluding node_modules from .dockerignore prevents host node_modules from leaking into container images.",
                    origin: "configuration_analysis"
                }
            );
        }
    }

    //---------------------------------------------------
    // Environment File
    //---------------------------------------------------

    if (!fileSystem.existsSync(envPath) && fileSystem.existsSync(envExample)) {

        addIssue(
            "Medium",
            ".env Missing",
            ".env.example exists but .env is missing.",
            "Create a production .env file.",
            "environment_configuration",
            {
                ruleId: "LUM-CFG-ENV-MISSING",
                category: "configuration",
                confidence: "High",
                cwe: ["CWE-1188"],
                file: null,
                line: null,
                severityRationale: "Production environment configuration file is missing while an example template exists.",
                origin: "configuration_analysis"
            }
        );
    }

    //---------------------------------------------------
    // USER check
    //---------------------------------------------------

    if (dockerfileExists && !dockerfile.includes("USER")) {

        addIssue(
            "High",
            "Container Runs As Root",
            "Running containers as root is insecure.",
            "Add USER node or a non-root user.",
            "dockerfile_configuration",
            {
                ruleId: "LUM-CFG-DOCKER-ROOT",
                category: "configuration",
                confidence: "High",
                cwe: ["CWE-250"],
                file: "Dockerfile",
                line: null,
                severityRationale: "Running container workloads as root grants elevated system privileges that can be leveraged during container escapes.",
                origin: "dockerfile_heuristic"
            }
        );
    }

    //---------------------------------------------------
    // HEALTHCHECK
    //---------------------------------------------------

    if (dockerfileExists && !dockerfile.includes("HEALTHCHECK")) {

        addIssue(
            "Medium",
            "Missing HEALTHCHECK",
            "Container has no health monitoring.",
            "Add a HEALTHCHECK instruction.",
            "dockerfile_configuration",
            {
                ruleId: "LUM-CFG-HEALTHCHECK-MISSING",
                category: "configuration",
                confidence: "High",
                cwe: ["CWE-1059"],
                file: "Dockerfile",
                line: null,
                severityRationale: "Lack of a HEALTHCHECK instruction impairs container orchestrators from detecting hung or compromised processes.",
                origin: "dockerfile_heuristic"
            }
        );
    }

    //---------------------------------------------------
    // Multi-stage Build
    //---------------------------------------------------

    const fromCount = (dockerfile.match(/FROM/g) || []).length;

    if (dockerfileExists && fromCount < 2) {

        addIssue(
            "Low",
            "Single Stage Build",
            "Image can be optimized.",
            "Use multi-stage Docker builds.",
            "dockerfile_configuration",
            {
                ruleId: "LUM-CFG-SINGLE-STAGE",
                category: "configuration",
                confidence: "High",
                cwe: ["CWE-1059"],
                file: "Dockerfile",
                line: null,
                severityRationale: "Single stage builds increase image size and attack surface by bundling build-time toolchains into production.",
                origin: "dockerfile_heuristic"
            }
        );
    }

    //---------------------------------------------------
    // Latest Tag
    //---------------------------------------------------

    if (dockerfileExists && dockerfile.includes(":latest")) {

        addIssue(
            "Medium",
            "Latest Tag Used",
            "Using latest image tag is risky.",
            "Use a fixed version.",
            "dockerfile_configuration",
            {
                ruleId: "LUM-CFG-LATEST-TAG",
                category: "configuration",
                confidence: "High",
                cwe: ["CWE-1104"],
                file: "Dockerfile",
                line: null,
                severityRationale: "Using the mutable :latest tag introduces non-deterministic builds and risks pulling unexpected upstream breaking changes.",
                origin: "dockerfile_heuristic"
            }
        );
    }

    //---------------------------------------------------
    // npm install
    //---------------------------------------------------

    if (
        dockerfileExists &&
        dockerfile.includes("npm install") &&
        !dockerfile.includes("npm ci")
    ) {

        addIssue(
            "Low",
            "npm install Used",
            "npm ci is recommended for production.",
            "Replace npm install with npm ci.",
            "dockerfile_configuration",
            {
                ruleId: "LUM-CFG-NPM-INSTALL",
                category: "configuration",
                confidence: "High",
                cwe: ["CWE-1104"],
                file: "Dockerfile",
                line: null,
                severityRationale: "npm install modifies package-lock.json and allows non-deterministic dependencies; npm ci enforces exact locked versions.",
                origin: "dockerfile_heuristic"
            }
        );
    }

    //---------------------------------------------------
    // Image Information
    //---------------------------------------------------

    if (!staticOnly) {
      try {

        // Verify the image exists using Docker API
        const images = await withDeadline(
            () => dockerClient.listImages(),
            ANALYZER_LIMITS.dockerOperationTimeoutMs,
            dependencies.signal
        );

        const imageExists = images.find(img =>
            (img.RepoTags || []).some(tag => tag === imageName || tag === `${imageName}:latest`)
        );

        if (!imageExists) {
            throw new Error(`Docker image ${imageName}:latest not found`);
        }

        const image = dockerClient.getImage(imageName);

        const inspect = await withDeadline(
            () => image.inspect(),
            ANALYZER_LIMITS.dockerOperationTimeoutMs,
            dependencies.signal
        );
        if (!inspect || typeof inspect.Id !== "string" || !inspect.Id.trim() ||
            !Number.isFinite(inspect.Size) || inspect.Size < 0 ||
            typeof inspect.Created !== "string" || !inspect.Created.trim()) {
            const error = new Error("Docker returned incomplete image metadata");
            error.code = "DOCKER_INVALID_IMAGE_METADATA";
            throw error;
        }

        report.docker.imageId = inspect.Id;
        report.docker.sizeMB = (inspect.Size / 1024 / 1024).toFixed(2);
        report.docker.created = inspect.Created;

        logger.info("Production Analyzer: Image Found");

        report.project.path = ".";
        report.project.dockerfile = fileSystem.existsSync(dockerfilePath);
        report.project.envExample = fileSystem.existsSync(envExample);
        report.project.env = fileSystem.existsSync(envPath);

        if (inspect.Size > 700 * 1024 * 1024) {
            addIssue(
                "Medium",
                "Large Docker Image",
                `Image size is ${report.docker.sizeMB} MB`,
                "Reduce image size using Alpine and multi-stage builds.",
                "image_metadata",
                {
                    ruleId: "LUM-CFG-DOCKER-SIZE",
                    category: "configuration",
                    confidence: "High",
                    cwe: ["CWE-1059"],
                    file: null,
                    line: null,
                    severityRationale: "Excessively large container images increase attack surface, transfer times, and deployment latency.",
                    origin: "image_metadata"
                }
            );
        }

      } catch (err) {
        markCheck("image_metadata", "failed", "image_metadata_unavailable");
        logger.error("Image metadata check failed", {
            code: err.code || err.statusCode || err.name || "UNKNOWN"
        });
      }
    }

    //---------------------------------------------------
    // Runtime
    //---------------------------------------------------

    if (container) {

        try {

            const inspect = await withDeadline(
                () => container.inspect(),
                ANALYZER_LIMITS.dockerOperationTimeoutMs,
                dependencies.signal
            );
            const state = inspect?.State;
            if (!state || typeof state.Running !== "boolean" ||
                typeof state.Status !== "string" || !state.Status.trim() ||
                typeof state.StartedAt !== "string" || !Number.isSafeInteger(state.ExitCode)) {
                const error = new Error("Docker returned incomplete runtime metadata");
                error.code = "DOCKER_INVALID_RUNTIME_METADATA";
                throw error;
            }

            report.runtime.running = state.Running;

            report.runtime.status = state.Status;

            report.runtime.startedAt = state.StartedAt;

            report.runtime.exitCode = state.ExitCode;

        } catch (err) {

            markCheck("runtime_inspection", "failed", "runtime_inspection_failed");
            logger.error("Runtime inspection failed", {
                code: err.code || err.statusCode || err.name || "UNKNOWN"
            });
        }
    }

    //---------------------------------------------------
    // Secret Scanner
    //---------------------------------------------------

    let scannedFileCount = 0;
    let scannedEntryCount = 0;
    let scannedBytes = 0;
    const projectTaintBudgetManager = new ProjectBudgetManager();
    const projectTaintModules = new Map();
    let scanLimitExceeded = false;
    let staticScanStarted = false;
    const skippedStaticFiles = new Set();
    const unsupportedStaticFiles = new Set();
    const binaryStaticFiles = new Set();
    const unreadableStaticFiles = new Set();
    const unsupportedEncodingFiles = new Set();
    const excludedStaticFiles = new Set();
    const excludedStaticDirectories = new Set();
    const credentialExemptFiles = new Set();
    const staticCheckIds = [
        "secret_pattern_search",
        "sql_injection_pattern_search",
        "os_command_injection_pattern_search",
        "unsafe_deserialization_pattern_search",
        "dynamic_code_execution_pattern_search",
        "insecure_transport_configuration",
        "dangerous_application_configuration"
    ];
    const staticEvidenceByCheck = new Map(staticCheckIds.map((checkId) => [
        checkId,
        {
            filesInspected: 0,
            filesSkipped: 0,
            unsupportedFiles: 0,
            binaryFiles: 0,
            failedReads: 0,
            unreadableFiles: 0,
            unsupportedEncodings: 0,
            readErrors: [],
            skippedFileDetails: []
        }
    ]));
    const injectionSourceFiles = new Set();
    const injectionFindings = new Set();
    const deserializationSourceFiles = new Set();
    const deserializationFindings = new Set();
    const dynamicExecutionSourceFiles = new Set();
    const dynamicExecutionFindings = new Set();
    let hasAstParseFailure = false;
    let astFailureReason = null;

    const markStaticChecksFailed = (reason = "static_analysis_failed") => {
        for (const checkId of staticCheckIds) {
            if (checks.get(checkId) !== "failed") markCheck(checkId, "failed", reason);
        }
    };

    const markStaticChecksIncomplete = (reason) => {
        for (const checkId of staticCheckIds) {
            if (checks.get(checkId) === "completed") markCheck(checkId, "partial", reason);
        }
    };

    const markChecksIncomplete = (checkIds, reason) => {
        for (const checkId of checkIds) {
            if (checks.get(checkId) === "completed") markCheck(checkId, "partial", reason);
        }
    };

    const getStaticChecksForFile = (filePath, fileName) => {
        const relativePath = safeRelativePath(buildContext, filePath);
        if (!relativePath ||
            /(?:^|\/)(?:__fixtures__|fixtures?|test-fixtures?)(?:\/|$)/i.test(relativePath) ||
            isCredentialExemptPath(relativePath, fileName)) {
            return [];
        }

        const fileType = classifyProjectFile(fileName);
        if (fileType === "unsupported") {
            return ["secret_pattern_search"];
        }
        if (!["source", "document", "configuration"].includes(fileType)) return [];

        const affected = ["secret_pattern_search"];
        if (fileType === "source" || fileType === "configuration") {
            affected.push("insecure_transport_configuration");
        }
        if (isInjectionSourceFile(fileName)) {
            affected.push("sql_injection_pattern_search", "os_command_injection_pattern_search");
        }
        if (isDeserializationSourceFile(fileName)) {
            affected.push("unsafe_deserialization_pattern_search");
        }
        if (isDynamicExecutionSourceFile(fileName)) {
            affected.push("dynamic_code_execution_pattern_search");
        }
        if (fileType === "configuration") {
            affected.push("insecure_transport_configuration", "dangerous_application_configuration");
        }
        return affected;
    };

    const recordStaticFileOutcome = (checkIds, outcome) => {
        for (const checkId of checkIds) {
            const evidence = staticEvidenceByCheck.get(checkId);
            if (evidence) evidence[outcome] += 1;
        }
    };

    const recordStaticReadError = (checkIds, filePath, code) => {
        const relativePath = safeRelativePath(buildContext, filePath);
        if (!relativePath) return;
        for (const checkId of checkIds) {
            const evidence = staticEvidenceByCheck.get(checkId);
            if (evidence && evidence.readErrors.length < 20) {
                evidence.readErrors.push({ file: relativePath, code });
            }
        }
    };

    const recordSkippedFileDetails = (checkIds, filePath, reason) => {
        const relativePath = safeRelativePath(buildContext, filePath);
        if (!relativePath) return;
        for (const checkId of checkIds) {
            const evidence = staticEvidenceByCheck.get(checkId);
            if (evidence && evidence.skippedFileDetails.length < 20) {
                evidence.skippedFileDetails.push({ file: relativePath, reason });
            }
        }
    };

    const stopStaticScan = () => {
        scanLimitExceeded = true;
        markStaticChecksIncomplete("static_resource_limit_reached");
        logger.warn("Static security checks stopped at their configured resource limit");
    };

    const addStaticIssue = (
        checkId,
        ruleId,
        severity,
        title,
        explanation,
        recommendation,
        filePath,
        lineNumber,
        evidence,
        identity = {}
    ) => {
        const relativePath = safeRelativePath(buildContext, filePath);
        if (!relativePath) {
            markStaticChecksFailed("finding_location_unavailable");
            return;
        }
        addIssue(severity, title, explanation, recommendation, checkId);
        Object.assign(report.issues[report.issues.length - 1], {
            ruleId,
            file: relativePath,
            line: lineNumber,
            evidence,
            remediation: recommendation,
            ...identity
        });
        const finding = report.issues[report.issues.length - 1];
        const sinkIdentity = identity.sourceSpan
            ? [
                "sink-v1",
                relativePath.replace(/\\/g, "/").replace(/^\.\//, ""),
                checkId,
                ruleId,
                identity.sourceSpan.start,
                identity.sourceSpan.end
            ].join(":")
            : null;
        if (sinkIdentity) {
            finding.sinkIdentity = sinkIdentity;
            finding.findingFingerprint = sinkIdentity;
            finding.sinkIdentityStatus = "resolved";
        } else {
            finding.sinkIdentityStatus = "unresolved";
        }
    };

    const credentialFindings = new Map();
    const recordCredential = (finding) => {
        const digest = createHash("sha256").update(finding.value).digest("hex");
        const issueType = String(finding.type || "credential").trim().toLowerCase();
        const key = `credential:${issueType}:${digest}`;
        const safeFinding = {
            ruleId: finding.ruleId,
            ruleIds: new Set([finding.ruleId]),
            type: finding.type,
            severity: finding.severity,
            confidence: finding.confidence,
            severityRationale: finding.severityRationale,
            cwe: new Set(finding.cwe),
            findingFingerprint: key,
            file: finding.file,
            line: finding.line
        };
        const stored = credentialFindings.get(key) || {
            ...safeFinding,
            locations: [],
            locationKeys: new Set(),
            occurrences: 0
        };
        stored.ruleIds.add(finding.ruleId);
        for (const cweId of finding.cwe) stored.cwe.add(cweId);
        const severityRank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
        const confidenceRank = { high: 3, medium: 2, low: 1 };
        if ((severityRank[finding.severity] || 0) > (severityRank[stored.severity] || 0) ||
            ((severityRank[finding.severity] || 0) === (severityRank[stored.severity] || 0) &&
                (confidenceRank[String(finding.confidence).toLowerCase()] || 0) >
                (confidenceRank[String(stored.confidence).toLowerCase()] || 0))) {
            stored.ruleId = finding.ruleId;
            stored.type = finding.type;
            stored.severity = finding.severity;
            stored.confidence = finding.confidence;
            stored.severityRationale = finding.severityRationale;
        }
        const locationKey = `${finding.file}:${finding.line}`;
        if (!stored.locationKeys.has(locationKey)) {
            stored.locationKeys.add(locationKey);
            stored.locations.push({ file: finding.file, line: finding.line });
            stored.occurrences += 1;
        }
        credentialFindings.set(key, stored);
    };

    const inspectStaticContent = (filePath, fileName, content) => {
        const relativePath = safeRelativePath(buildContext, filePath);
        if (!relativePath) {
            markStaticChecksFailed("finding_location_unavailable");
            return;
        }
        const fixturePath = /(?:^|\/)(?:__fixtures__|fixtures?|test-fixtures?)(?:\/|$)/i.test(relativePath);
        const credentialExemptPath = isCredentialExemptPath(relativePath, fileName);
        if (credentialExemptPath) credentialExemptFiles.add(relativePath);
        const getLineNumber = createLineNumberLookup(content);
        const jsSource = /\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$/i.test(fileName);
        const pythonSource = /\.(?:py|pyi)$/i.test(fileName);
        const injectionSourceFile = isInjectionSourceFile(fileName);
        let astResult = null;
        let astAnalysisError = null;
        if (jsSource && !fixturePath && !credentialExemptPath) {
            try {
                astResult = analyzeAstSource(content, {
                    filePath,
                    relativePath,
                    skipTaintAnalysis: true
                });
            } catch (astError) {
                astAnalysisError = astError;
            }
            if (astResult?.isPartial || astResult?.parseStatus === "failed") {
                hasAstParseFailure = true;
                if (!astFailureReason) {
                    if (astResult.errors?.some((error) =>
                        error.code === "SOURCE_SIZE_EXCEEDED" ||
                        error.code === "AST_SOURCE_SIZE_EXCEEDED"
                    )) {
                        astFailureReason = "ast_source_size_limit_exceeded";
                    } else if (astResult.isPartial &&
                        (astResult.metrics?.maxDepth >= 120 ||
                            astResult.metrics?.nodeCount >= 100000)) {
                        astFailureReason = "ast_traversal_limit_exceeded";
                    } else {
                        astFailureReason = "ast_parse_syntax_error";
                    }
                }
            }
            if (astAnalysisError) {
                hasAstParseFailure = true;
                if (!astFailureReason) astFailureReason = "ast_parse_syntax_error";
                logger.warn("AST analysis encountered an unexpected error on source file", {
                    file: relativePath,
                    error: astAnalysisError.message
                });
            }
        }
        if (injectionSourceFile && !fixturePath && !credentialExemptPath) {
            injectionSourceFiles.add(relativePath);
        }
        const deserializationSourceFile = isDeserializationSourceFile(fileName);
        if (deserializationSourceFile && !fixturePath && !credentialExemptPath) {
            deserializationSourceFiles.add(relativePath);
        }
        const dynamicExecutionSourceFile = isDynamicExecutionSourceFile(fileName);
        if (dynamicExecutionSourceFile && !fixturePath && !credentialExemptPath) {
            dynamicExecutionSourceFiles.add(relativePath);
        }
        if (!fixturePath && !credentialExemptPath) {
            const credentialContent = maskComments(content);
            const astCalls = astResult?.sinkProvenance?.calls || [];
            const astCallAt = (offset) => {
                const exact = astCalls.find((call) => call.start === offset);
                if (exact) return exact;
                const calleeToken = credentialContent.slice(offset)
                    .match(/^[A-Za-z_$][\w$]*/)?.[0];
                if (!calleeToken) return null;
                return astCalls
                    .filter((call) =>
                        call.start <= offset &&
                        offset < call.end &&
                        String(call.callee || '').split('.').pop() === calleeToken
                    )
                    .sort((left, right) =>
                        (left.end - left.start) - (right.end - right.start) ||
                        left.start - right.start
                    )[0] || null;
            };
            const recordAssignment = (keyName, rawValue, matchIndex) => {
                const value = rawValue.replace(/[;,]+$/, "").trim();
                const normalizedKey = keyName.toLowerCase().replace(/[-_]/g, "");
                if (!value || isPlaceholderSecret(value) || isEnvironmentReference(value) ||
                    isCredentialLabelValue(value)) return false;

                const passwordLike = /password|passwd|passphrase|pwd/.test(normalizedKey);
                const privateKeyLike = /privatekey/.test(normalizedKey);
                if (privateKeyLike && value.startsWith("-----BEGIN")) return false;
                const providerSpecific = /aws|azure|gcp|google|apikey|accesstoken|clientsecret/.test(normalizedKey);
                const severity = privateKeyLike
                    ? "High"
                    : providerSpecific && hasCredentialEntropy(value) ? "High" : "Medium";
                const type = privateKeyLike ? "private key"
                    : passwordLike ? "password"
                        : /token/.test(normalizedKey) ? "access token"
                            : /aws|azure|gcp|google|accountkey|connectionstring/.test(normalizedKey)
                                ? "cloud credential"
                                : "API key or secret";
                const cwe = privateKeyLike ? ["CWE-321", "CWE-798"]
                    : passwordLike ? ["CWE-259", "CWE-798"]
                        : ["CWE-798"];
                const severityRationale = privateKeyLike
                    ? "High: a non-placeholder literal is assigned to a private-key setting; validity is not verified."
                    : severity === "High"
                        ? "High: a long, varied literal is assigned to a provider-specific credential setting; active validity is not verified."
                        : passwordLike
                            ? "Medium: a password-like setting contains a literal, but pattern matching cannot confirm whether it is active or privileged."
                            : "Medium: a credential-like setting contains a literal, but its privilege and active validity are unknown.";
                recordCredential({
                    ruleId: "LUM-SEC-001",
                    type,
                    severity,
                    confidence: passwordLike || normalizedKey === "secret" ||
                        normalizedKey === "credential" ? "medium" : "high",
                    severityRationale,
                    cwe,
                    file: relativePath,
                    line: getLineNumber(matchIndex),
                    value
                });
                return true;
            };
            const multilineRanges = [];
            const multilinePattern = new RegExp(
                MULTILINE_CREDENTIAL_ASSIGNMENT_PATTERN.source,
                "gi"
            );
            let credentialAssignmentMatch;
            while ((credentialAssignmentMatch = multilinePattern.exec(credentialContent)) !== null) {
                const value = credentialAssignmentMatch[2] ??
                    credentialAssignmentMatch[3] ??
                    credentialAssignmentMatch[4] ?? "";
                if (!/[\r\n]/.test(value)) continue;
                multilineRanges.push([
                    credentialAssignmentMatch.index,
                    credentialAssignmentMatch.index + credentialAssignmentMatch[0].length
                ]);
                recordAssignment(
                    credentialAssignmentMatch[1],
                    value,
                    credentialAssignmentMatch.index
                );
            }

            if (injectionSourceFile) {
                const addInjectionFinding = (
                    ruleId,
                    kind,
                    fileOffset,
                    severity,
                    confidence,
                    rationale,
                    cwe,
                    evidence,
                    recommendation,
                    sinkInfo = null
                ) => {
                    if (sinkInfo?.provenance?.status === "locally_defined") return;
                    const line = getLineNumber(fileOffset);
                    const sourceSpan = Number.isInteger(sinkInfo?.start) &&
                        Number.isInteger(sinkInfo?.end)
                        ? { start: sinkInfo.start, end: sinkInfo.end }
                        : null;
                    const dedupeKey = sourceSpan
                        ? `${ruleId}:${relativePath}:${sourceSpan.start}:${sourceSpan.end}`
                        : null;
                    if (dedupeKey && injectionFindings.has(dedupeKey)) return;
                    if (dedupeKey) injectionFindings.add(dedupeKey);
                    const checkId = ruleId === "LUM-INJ-001"
                        ? "sql_injection_pattern_search"
                        : "os_command_injection_pattern_search";
                    addStaticIssue(
                        checkId,
                        ruleId,
                        severity,
                        kind === "sql" ? "Potentially unsafe dynamic SQL construction"
                            : "Potentially unsafe command construction",
                        kind === "sql"
                            ? "A SQL statement appears to be dynamically constructed and passed to a database execution API. This pattern alone does not establish attacker control or exploitability."
                            : "A command execution API appears to receive a value associated with user input. This pattern alone does not establish attacker control or exploitability.",
                        recommendation,
                        filePath,
                        line,
                        evidence,
                        {
                            ...(sourceSpan ? { sourceSpan } : {}),
                            ...(sinkInfo?.callee ? { sinkExpression: sinkInfo.callee } : {}),
                            ...(sinkInfo?.provenance ? { sinkProvenance: sinkInfo.provenance } : {}),
                            origin: "pattern_analysis",
                            producerOrigins: ["pattern"]
                        }
                    );
                    Object.assign(report.issues[report.issues.length - 1], {
                        confidence,
                        severityRationale: rationale,
                        remediation: recommendation,
                        cwe
                    });
                };

                const unsafeSqlVariables = new Map();
                const sqlAssignmentPatterns = [
                    /(?:^|[;\r\n])\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*((?:f)?"""[\s\S]*?"""|(?:f)?'''[\s\S]*?'''|(?:f)?`[\s\S]*?`|(?:f)?["'][\s\S]*?["'])/g,
                    /^\s*([A-Za-z_$][\w$]*)\s*=\s*((?:f)?"""[\s\S]*?"""|(?:f)?'''[\s\S]*?'''|(?:f)?`[\s\S]*?`|(?:f)?["'][\s\S]*?["'])/gm
                ];
                for (const sqlAssignmentPattern of sqlAssignmentPatterns) {
                    let sqlVariableMatch;
                    while ((sqlVariableMatch = sqlAssignmentPattern.exec(credentialContent)) !== null) {
                        const assignmentEnd = sqlVariableMatch.index + sqlVariableMatch[0].length;
                        const suffix = credentialContent.slice(assignmentEnd)
                            .match(/^\s*(?:\+|%|\.format\s*\()[^;\r\n]*/)?.[0] || "";
                        if (isSqlDynamicExpression(sqlVariableMatch[2] + suffix)) {
                            const variableOffset = sqlVariableMatch.index +
                                sqlVariableMatch[0].indexOf(sqlVariableMatch[1]);
                            unsafeSqlVariables.set(sqlVariableMatch[1], variableOffset);
                        }
                    }
                }

                const sqlCallPattern = new RegExp(SQL_EXECUTION_PATTERN.source, "gi");
                let sqlCallMatch;
                while ((sqlCallMatch = sqlCallPattern.exec(credentialContent)) !== null) {
                    const openParenthesis = sqlCallMatch.index + sqlCallMatch[0].lastIndexOf("(");
                    const callArguments = findCallArguments(credentialContent, openParenthesis);
                    if (!callArguments?.length) continue;
                    const firstArgument = callArguments[0];
                    const firstArgumentIsVariable = /^[A-Za-z_$][\w$]*$/.test(firstArgument);
                    const hasUnsafeVariable = firstArgumentIsVariable &&
                        unsafeSqlVariables.has(firstArgument);
                    if (!isSqlDynamicExpression(firstArgument) && !hasUnsafeVariable) continue;
                    addInjectionFinding(
                        "LUM-INJ-001",
                        "sql",
                        pythonSource && hasUnsafeVariable
                            ? unsafeSqlVariables.get(firstArgument)
                            : sqlCallMatch.index,
                        "High",
                        "medium",
                        "High: dynamic SQL syntax reaches a database execution API; input control and exploitability are not established.",
                        ["CWE-89"],
                        "Dynamic SQL passed to a database API (<redacted>)",
                        "Use a parameterized query with values supplied separately; avoid interpolating or concatenating values into SQL syntax.",
                        astCallAt(sqlCallMatch.index)
                    );
                }

                const userInputVariables = new Set();
                for (const assignmentPattern of USER_INPUT_ASSIGNMENT_PATTERNS) {
                    let userInputMatch;
                    while ((userInputMatch = assignmentPattern.exec(credentialContent)) !== null) {
                        userInputVariables.add(userInputMatch[1]);
                    }
                }
                const commandInputVariables = new Set();
                const commandAssignmentPatterns = [
                    /(?:^|[;\r\n])\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\r\n]*(?:\r?\n[^;\r\n]*)*);/g,
                    /^\s*([A-Za-z_$][\w$]*)\s*=\s*([^\r\n]+)$/gm
                ];
                for (const assignmentPattern of commandAssignmentPatterns) {
                    let assignmentMatch;
                    while ((assignmentMatch = assignmentPattern.exec(credentialContent)) !== null) {
                        const expression = assignmentMatch[2];
                        if (USER_INPUT_PATTERN.test(expression) ||
                            [...userInputVariables].some((identifier) =>
                                new RegExp(`\\b${identifier.replace(/[$]/g, "\\$")}\\b`).test(expression)
                            )) {
                            commandInputVariables.add(assignmentMatch[1]);
                        }
                    }
                }
                const hasUserInput = (text) => USER_INPUT_PATTERN.test(text) ||
                    [...userInputVariables, ...commandInputVariables].some((identifier) =>
                        new RegExp(`\\b${identifier.replace(/[$]/g, "\\$")}\\b`).test(text)
                    );
                const commandSettings = /\bshell\s*[:=]\s*true\b/i;
                const hasChildProcessImport = /\b(?:from\s+["']node:)?child_process["']|\brequire\s*\(\s*["'](?:node:)?child_process["']\s*\)/i.test(credentialContent);
                const nodeCommandPattern = new RegExp(NODE_COMMAND_PATTERN.source, "gi");
                const commandPatterns = [
                    ...(jsSource ? [nodeCommandPattern] : []),
                    ...(pythonSource ? [new RegExp(PYTHON_COMMAND_PATTERN.source, "gi")] : [])
                ];
                for (const commandPattern of commandPatterns) {
                    let commandMatch;
                    while ((commandMatch = commandPattern.exec(credentialContent)) !== null) {
                        const methodName = commandMatch[1].toLowerCase();
                        const openParenthesis = commandMatch.index + commandMatch[0].lastIndexOf("(");
                        const callArguments = findCallArguments(credentialContent, openParenthesis);
                        if (!callArguments?.length) continue;
                        if (jsSource && !commandMatch[0].toLowerCase().includes("child_process") &&
                            !hasChildProcessImport) continue;

                        const isPythonShellApi = pythonSource &&
                            /^(?:system|popen|getoutput|getstatusoutput)$/.test(methodName);
                        const hasShellOption = commandSettings.test(callArguments.slice(1).join(","));
                        const isShellCommand = isPythonShellApi || hasShellOption ||
                            /^(?:exec|execsync)$/.test(methodName);
                        const firstArgument = callArguments[0];
                        const isArgumentArray = /^\s*\[/.test(firstArgument) ||
                            (jsSource && /^(?:execfile|execfilesync|spawn|spawnsync)$/.test(methodName) &&
                                /^\s*\[/.test(callArguments[1] || ""));
                        const commandText = callArguments.join(",");
                        if (!hasUserInput(commandText)) continue;
                        if (!isShellCommand && !isArgumentArray) continue;
                        const saferArgumentArray = isArgumentArray && !hasShellOption;
                        addInjectionFinding(
                            "LUM-INJ-002",
                            "command",
                            commandMatch.index,
                            saferArgumentArray ? "Medium" : "High",
                            saferArgumentArray ? "low" : "medium",
                            saferArgumentArray
                                ? "Medium: a user-input indicator appears in a process argument array; shell parsing is not evident, but argument semantics and input validation still matter."
                                : "High: a user-input indicator appears in a shell-based command API; input control and exploitability are not established.",
                            ["CWE-78"],
                            saferArgumentArray
                                ? "User-input indicator passed in process arguments (<redacted>)"
                                : "User-input indicator passed to shell command construction (<redacted>)",
                            saferArgumentArray
                                ? "Prefer fixed executable and argument structure, validate values against an allowlist, and avoid shell mode."
                                : "Avoid shell command strings; use an argument-array API with a fixed executable and validate each argument against an allowlist.",
                            astCallAt(commandMatch.index)
                        );
                    }
                }
            }

            const stringRanges = collectStringRanges(content);
            const isInsideString = (offset) => isInsideRange(offset, stringRanges);

            if (deserializationSourceFile) {
                const addDeserializationFinding = (
                    ruleId,
                    title,
                    fileOffset,
                    severity,
                    confidence,
                    rationale,
                    cwe,
                    evidence,
                    explanation,
                    recommendation,
                    sinkInfo = null
                ) => {
                    const line = getLineNumber(fileOffset);
                    const sourceSpan = Number.isInteger(sinkInfo?.start) &&
                        Number.isInteger(sinkInfo?.end)
                        ? { start: sinkInfo.start, end: sinkInfo.end }
                        : null;
                    const dedupeKey = sourceSpan
                        ? `${ruleId}:${relativePath}:${sourceSpan.start}:${sourceSpan.end}`
                        : null;
                    if (dedupeKey && deserializationFindings.has(dedupeKey)) return;
                    if (dedupeKey) deserializationFindings.add(dedupeKey);
                    addStaticIssue(
                        "unsafe_deserialization_pattern_search",
                        ruleId,
                        severity,
                        title,
                        explanation,
                        recommendation,
                        filePath,
                        line,
                        evidence,
                        {
                            ...(sourceSpan ? { sourceSpan } : {}),
                            ...(sinkInfo?.callee ? { sinkExpression: sinkInfo.callee } : {}),
                            ...(sinkInfo?.provenance ? { sinkProvenance: sinkInfo.provenance } : {}),
                            origin: "pattern_analysis",
                            producerOrigins: ["pattern"]
                        }
                    );
                    Object.assign(report.issues[report.issues.length - 1], {
                        confidence,
                        severityRationale: rationale,
                        remediation: recommendation,
                        cwe
                    });
                };

                if (pythonSource) {
                    const picklePattern = new RegExp(PYTHON_PICKLE_CALL_PATTERN.source, "gi");
                    let pickleMatch;
                    while ((pickleMatch = picklePattern.exec(credentialContent)) !== null) {
                        if (isInsideString(pickleMatch.index)) continue;
                        const methodName = pickleMatch[1];
                        addDeserializationFinding(
                            "LUM-DES-001",
                            "Unsafe pickle deserialization",
                            pickleMatch.index,
                            "High",
                            "high",
                            "High: pickle deserialization can execute arbitrary code during object reconstruction; attacker control of serialized data is not established.",
                            ["CWE-502"],
                            `pickle.${methodName}() deserialization (<redacted>)`,
                            "The application uses Python pickle deserialization, which can execute arbitrary code during object reconstruction. This pattern alone does not establish attacker control or exploitability.",
                            "Avoid pickle for untrusted or unauthenticated data. Use safe, standard data formats like JSON (json.loads) or cryptographically sign serialized payloads."
                        );
                    }

                    const yamlPattern = new RegExp(PYTHON_YAML_CALL_PATTERN.source, "gi");
                    let yamlMatch;
                    while ((yamlMatch = yamlPattern.exec(credentialContent)) !== null) {
                        if (isInsideString(yamlMatch.index)) continue;
                        const methodName = yamlMatch[1].toLowerCase();
                        const isExplicitUnsafe = methodName.includes("unsafe");
                        const openParenthesis = yamlMatch.index + yamlMatch[0].lastIndexOf("(");
                        const callArguments = findCallArguments(credentialContent, openParenthesis);
                        if (!callArguments?.length) continue;

                        let isSafe = false;
                        if (!isExplicitUnsafe) {
                            const argsText = callArguments.join(",");
                            if (PYTHON_SAFE_YAML_LOADERS.test(argsText)) {
                                isSafe = true;
                            }
                        }
                        if (isSafe) continue;

                        addDeserializationFinding(
                            "LUM-DES-002",
                            "Unsafe YAML deserialization",
                            yamlMatch.index,
                            "High",
                            "high",
                            "High: loading YAML without SafeLoader can instantiate arbitrary Python objects; attacker control of input is not established.",
                            ["CWE-502"],
                            isExplicitUnsafe
                                ? `yaml.${yamlMatch[1]} called (<redacted>)`
                                : "yaml.load called without safe Loader (<redacted>)",
                            "The application parses YAML using yaml.load() without an explicitly safe loader, or uses yaml.unsafe_load(), which can instantiate arbitrary objects and execute code. This pattern alone does not establish attacker control or exploitability.",
                            "Use yaml.safe_load() or specify Loader=yaml.SafeLoader (or yaml.CSafeLoader / yaml.BaseLoader) when parsing YAML data."
                        );
                    }

                    const marshalPattern = new RegExp(PYTHON_MARSHAL_CALL_PATTERN.source, "gi");
                    let marshalMatch;
                    while ((marshalMatch = marshalPattern.exec(credentialContent)) !== null) {
                        if (isInsideString(marshalMatch.index)) continue;
                        const methodName = marshalMatch[1];
                        addDeserializationFinding(
                            "LUM-DES-003",
                            "Unsafe marshal deserialization",
                            marshalMatch.index,
                            "High",
                            "medium",
                            "High: Python marshal deserialization parses internal bytecode representations without validation; attacker control of input is not established.",
                            ["CWE-502"],
                            `marshal.${methodName}() deserialization (<redacted>)`,
                            "The application uses marshal to deserialize data. The marshal module is not intended to be secure against maliciously constructed input. This pattern alone does not establish attacker control or exploitability.",
                            "Do not use marshal for untrusted data. Use standard formats like JSON or a schema-validated serialization mechanism."
                        );
                    }

                    const shelvePattern = new RegExp(PYTHON_SHELVE_CALL_PATTERN.source, "gi");
                    let shelveMatch;
                    while ((shelveMatch = shelvePattern.exec(credentialContent)) !== null) {
                        if (isInsideString(shelveMatch.index)) continue;
                        addDeserializationFinding(
                            "LUM-DES-004",
                            "Unsafe shelve database deserialization",
                            shelveMatch.index,
                            "Medium",
                            "medium",
                            "Medium: shelve uses pickle for object serialization and storage; loading untrusted shelf databases can execute arbitrary code.",
                            ["CWE-502"],
                            "shelve.open() deserialization (<redacted>)",
                            "The application opens a shelve database with shelve.open(). Shelve relies on pickle internally and is insecure when used with untrusted files. This pattern alone does not establish attacker control or exploitability.",
                            "Avoid shelve for untrusted database files. Use SQLite (sqlite3) or structured key-value stores with safe serialization formats."
                        );
                    }
                }

                if (jsSource) {
                    const hasNodeSerializeImport = /\b(?:from\s+["']node-serialize["']|require\s*\(\s*["']node-serialize["']\s*\))/i.test(credentialContent);
                    const nodeSerializePattern = new RegExp(NODE_SERIALIZE_CALL_PATTERN.source, "gi");
                    let serializeMatch;
                    while ((serializeMatch = nodeSerializePattern.exec(credentialContent)) !== null) {
                        if (isInsideString(serializeMatch.index)) continue;
                        if (!hasNodeSerializeImport && !/(?:nodeSerialize|serialize)\s*\./i.test(serializeMatch[0])) continue;
                        addDeserializationFinding(
                            "LUM-DES-005",
                            "Unsafe JavaScript object deserialization",
                            serializeMatch.index,
                            "High",
                            "high",
                            "High: node-serialize unserialize() can execute arbitrary functions embedded in serialized data; attacker control is not established.",
                            ["CWE-502"],
                            "node-serialize unserialize() deserialization (<redacted>)",
                            "The application uses an unsafe deserialization function that can execute arbitrary code embedded in serialized payloads. This pattern alone does not establish attacker control or exploitability.",
                            "Use JSON.parse() with schema validation (such as Zod or Ajv) instead of object deserialization libraries that support code or function reconstruction.",
                            astCallAt(serializeMatch.index)
                        );
                    }
                }
            }

            if (dynamicExecutionSourceFile && jsSource) {
                const addDynamicExecutionFinding = (
                    ruleId,
                    title,
                    fileOffset,
                    severity,
                    confidence,
                    rationale,
                    cwe,
                    evidence,
                    explanation,
                    recommendation,
                    sinkInfo = null
                ) => {
                    if (sinkInfo?.provenance?.status === "locally_defined") return;
                    const line = getLineNumber(fileOffset);
                    const sourceSpan = Number.isInteger(sinkInfo?.start) &&
                        Number.isInteger(sinkInfo?.end)
                        ? { start: sinkInfo.start, end: sinkInfo.end }
                        : null;
                    const dedupeKey = sourceSpan
                        ? `${ruleId}:${relativePath}:${sourceSpan.start}:${sourceSpan.end}`
                        : null;
                    if (dedupeKey && dynamicExecutionFindings.has(dedupeKey)) return;
                    if (dedupeKey) dynamicExecutionFindings.add(dedupeKey);
                    addStaticIssue(
                        "dynamic_code_execution_pattern_search",
                        ruleId,
                        severity,
                        title,
                        explanation,
                        recommendation,
                        filePath,
                        line,
                        evidence,
                        {
                            ...(sourceSpan ? { sourceSpan } : {}),
                            ...(sinkInfo?.callee ? { sinkExpression: sinkInfo.callee } : {}),
                            ...(sinkInfo?.provenance ? { sinkProvenance: sinkInfo.provenance } : {}),
                            origin: "pattern_analysis",
                            producerOrigins: ["pattern"]
                        }
                    );
                    Object.assign(report.issues[report.issues.length - 1], {
                        confidence,
                        severityRationale: rationale,
                        remediation: recommendation,
                        cwe
                    });
                };

                const evalPattern = new RegExp(JS_EVAL_CALL_PATTERN.source, "gi");
                let evalMatch;
                while ((evalMatch = evalPattern.exec(credentialContent)) !== null) {
                    if (isInsideString(evalMatch.index)) continue;
                    const sinkInfo = astCallAt(evalMatch.index);
                    const declaration = astResult?.sinkProvenance?.declarations?.some((range) =>
                        evalMatch.index >= range.start && evalMatch.index < range.end
                    );
                    if (declaration || sinkInfo?.provenance?.status !== "global_builtin") continue;
                    addDynamicExecutionFinding(
                        "LUM-DYN-001",
                        "Dynamic code execution via eval",
                        evalMatch.index,
                        "High",
                        "high",
                        "High: eval() executes arbitrary JavaScript expressions in the caller's execution scope; attacker control of input is not established.",
                        ["CWE-95"],
                        "eval() invocation (<redacted>)",
                        "The application invokes eval(), dynamically executing string input as JavaScript code. This pattern alone does not establish attacker control or exploitability.",
                        "Avoid eval(). Parse data with JSON.parse() or use safe data structures and explicit lookup dispatch tables instead of evaluating code.",
                        sinkInfo
                    );
                }

                const funcPattern = new RegExp(JS_FUNCTION_CONSTRUCTOR_PATTERN.source, "g");
                let funcMatch;
                while ((funcMatch = funcPattern.exec(credentialContent)) !== null) {
                    if (isInsideString(funcMatch.index)) continue;
                    addDynamicExecutionFinding(
                        "LUM-DYN-002",
                        "Dynamic code execution via Function constructor",
                        funcMatch.index,
                        "High",
                        "high",
                        "High: the Function constructor compiles and executes arbitrary code strings; attacker control of input is not established.",
                        ["CWE-95"],
                        "Function constructor invocation (<redacted>)",
                        "The application constructs a dynamic function using new Function() or Function(), compiling string arguments as code. This pattern alone does not establish attacker control or exploitability.",
                        "Avoid dynamic function compilation. Use standard function declarations, arrow functions, or predefined handler maps instead.",
                        astCallAt(funcMatch.index)
                    );
                }

                const hasVmImport = /\b(?:from\s+["'](?:node:)?vm["']|require\s*\(\s*["'](?:node:)?vm["']\s*\))/i.test(credentialContent);
                const vmPattern = new RegExp(NODE_VM_CALL_PATTERN.source, "gi");
                let vmMatch;
                while ((vmMatch = vmPattern.exec(credentialContent)) !== null) {
                    if (isInsideString(vmMatch.index)) continue;
                    if (!hasVmImport && !/\bvm\s*\./.test(vmMatch[0])) continue;
                    addDynamicExecutionFinding(
                        "LUM-DYN-003",
                        "Dynamic code execution via Node.js vm",
                        vmMatch.index,
                        "High",
                        "high",
                        "High: Node.js vm dynamic execution APIs compile and run arbitrary code; the vm module is not a security sandbox.",
                        ["CWE-94"],
                        "vm dynamic execution call (<redacted>)",
                        "The application invokes a Node.js vm execution API (such as vm.runInContext, vm.runInNewContext, or vm.runInThisContext). The vm module is not a security sandbox and executes dynamic code. This pattern alone does not establish attacker control or exploitability.",
                        "Avoid executing dynamic code in Node.js vm. Use isolated subprocesses or dedicated sandboxing engines with hard OS-level process boundaries if code evaluation is required.",
                        astCallAt(vmMatch.index)
                    );
                }

                const timerPattern = new RegExp(JS_TIMER_CALL_PATTERN.source, "gi");
                let timerMatch;
                while ((timerMatch = timerPattern.exec(credentialContent)) !== null) {
                    if (isInsideString(timerMatch.index)) continue;
                    const openParenthesis = timerMatch.index + timerMatch[0].lastIndexOf("(");
                    const callArguments = findCallArguments(credentialContent, openParenthesis);
                    if (!callArguments?.length) continue;
                    const firstArg = callArguments[0].trim();
                    const isFunctionCallback = /^(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/.test(firstArg) || firstArg.includes("=>");
                    const isStringArg = !isFunctionCallback && (
                        /^[`'"]/.test(firstArg) ||
                        /^String\s*\(/.test(firstArg) ||
                        (firstArg.includes("+") && /[`'"]/.test(firstArg))
                    );
                    if (!isStringArg) continue;

                    addDynamicExecutionFinding(
                        "LUM-DYN-004",
                        "Implicit code execution via timer string argument",
                        timerMatch.index,
                        "Medium",
                        "high",
                        "Medium: passing a string to a timer API triggers implicit code evaluation; attacker control of input is not established.",
                        ["CWE-95"],
                        "Timer called with string code argument (<redacted>)",
                        "The application passes a string to a timer API (setTimeout, setInterval, or setImmediate), causing the string to be evaluated as code like eval(). This pattern alone does not establish attacker control or exploitability.",
                        "Pass a function or arrow function callback to timer APIs instead of a string argument.",
                        astCallAt(timerMatch.index)
                    );
                }
            }

            if (jsSource && !fixturePath && !credentialExemptPath) {
                projectTaintModules.set(relativePath, content);
                if (astResult) {
                    function redactTaintTrace(trace) {
                        if (!trace || typeof trace !== 'object') return trace;
                        const sanitizeStr = (s) => typeof s === 'string'
                            ? s.replace(/\bSELECT\b/gi, '<query>')
                               .replace(/\breq\.query\b/g, 'req[<redacted>]')
                               .replace(/\brequest\.args\b/g, 'request[<redacted>]')
                               .replace(/\buserInput\b/g, 'user_<redacted>')
                               .replace(/\bfileName\b/g, 'file_<redacted>')
                            : s;

                        return {
                            source: {
                                ...trace.source,
                                expression: sanitizeStr(trace.source?.expression),
                                path: sanitizeStr(trace.source?.path)
                            },
                            steps: Array.isArray(trace.steps)
                                ? trace.steps.map((st) => ({
                                    ...st,
                                    from: sanitizeStr(st.from),
                                    to: sanitizeStr(st.to),
                                    expression: sanitizeStr(st.expression)
                                }))
                                : [],
                            sink: {
                                ...trace.sink,
                                expression: sanitizeStr(trace.sink?.expression)
                            },
                            sanitized: Boolean(trace.sanitized)
                        };
                    }

                    for (const astFinding of astResult.findings) {
                        const safeEvidence = astFinding.evidence && typeof astFinding.evidence === 'string'
                            ? astFinding.evidence.replace(/\bSELECT\b/gi, '<query>')
                                .replace(/\breq\.query\b/g, 'req[<redacted>]')
                                .replace(/\brequest\.args\b/g, 'request[<redacted>]')
                                .replace(/\buserInput\b/g, 'user_<redacted>')
                                .replace(/\bfileName\b/g, 'file_<redacted>')
                            : astFinding.evidence;

                        addStaticIssue(
                            astFinding.checkId,
                            astFinding.ruleId,
                            astFinding.severity,
                            astFinding.title,
                            astFinding.description,
                            astFinding.remediation,
                            filePath,
                            astFinding.line,
                            safeEvidence,
                            {
                                ...(astFinding.sourceSpan ? { sourceSpan: astFinding.sourceSpan } : {}),
                                ...(astFinding.sinkExpression ? { sinkExpression: astFinding.sinkExpression } : {}),
                                ...(astFinding.sinkProvenance ? { sinkProvenance: astFinding.sinkProvenance } : {}),
                                producerOrigins: astFinding.producerOrigins ||
                                    [astFinding.origin || "ast_analysis"],
                                origin: astFinding.origin || "ast_analysis"
                            }
                        );
                        Object.assign(report.issues[report.issues.length - 1], {
                            confidence: astFinding.confidence,
                            severityRationale: astFinding.severityRationale,
                            cwe: astFinding.cwe,
                            column: astFinding.column,
                            ...(astFinding.isTaintConfirmed ? {
                                isTaintConfirmed: true,
                                taintTrace: redactTaintTrace(astFinding.taintTrace)
                            } : {})
                        });
                        const dedupeKey = astFinding.sinkIdentity ||
                            `${astFinding.ruleId}:${relativePath}:${astFinding.line}:${safeEvidence}`;
                        if (astFinding.checkId === "dynamic_code_execution_pattern_search") {
                            dynamicExecutionFindings.add(dedupeKey);
                        } else if (astFinding.checkId === "unsafe_deserialization_pattern_search") {
                            deserializationFindings.add(dedupeKey);
                        } else if (astFinding.checkId === "sql_injection_pattern_search" ||
                            astFinding.checkId === "os_command_injection_pattern_search") {
                            injectionFindings.add(dedupeKey);
                        }
                    }
                }
            }

            const lines = credentialContent.split(/\r?\n/);
            let offset = 0;
            for (const lineContent of lines) {
                if (!isCommentOnlyLine(lineContent)) {
                    const assignmentPattern = new RegExp(CREDENTIAL_ASSIGNMENT_PATTERN.source, "gi");
                    let match;
                    const matchedValueRanges = [];
                    while ((match = assignmentPattern.exec(lineContent)) !== null) {
                        const absoluteMatchIndex = offset + match.index;
                        if (multilineRanges.some(([start, end]) =>
                            absoluteMatchIndex >= start && absoluteMatchIndex < end
                        )) continue;
                        const value = (match[2] ?? match[3] ?? match[4] ?? match[5] ??
                            match[6] ?? match[7] ?? "")
                            .replace(/[;,]+$/, "").trim();
                        if (match[7] !== undefined && /^[`'"]/.test(value)) continue;
                        const wasRecorded = recordAssignment(
                            match[1],
                            value,
                            absoluteMatchIndex
                        );
                        if (!wasRecorded) continue;
                        const valueOffset = match.index + match[0].lastIndexOf(value);
                        matchedValueRanges.push([valueOffset, valueOffset + value.length]);
                    }

                    for (const provider of PROVIDER_CREDENTIAL_PATTERNS) {
                        provider.pattern.lastIndex = 0;
                        let providerMatch;
                        while ((providerMatch = provider.pattern.exec(lineContent)) !== null) {
                            const value = providerMatch[0];
                            const absoluteMatchIndex = offset + providerMatch.index;
                            if (isPlaceholderSecret(value) ||
                                matchedValueRanges.some(([start, end]) =>
                                    providerMatch.index >= start && providerMatch.index < end
                                ) ||
                                multilineRanges.some(([start, end]) =>
                                    absoluteMatchIndex >= start && absoluteMatchIndex < end
                                )) continue;
                            recordCredential({
                                ruleId: "LUM-SEC-002",
                                type: provider.type,
                                severity: "High",
                                confidence: "high",
                                severityRationale: "High: the literal matches a provider-specific credential format; the scanner cannot verify whether it is active.",
                                cwe: [provider.cwe],
                                file: relativePath,
                                line: getLineNumber(absoluteMatchIndex),
                                value
                            });
                        }
                    }
                }
                offset += lineContent.length + 1;
            }

            const privateKeyPattern = /-----BEGIN ((?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY)-----/g;
            let privateKeyMatch;
            while ((privateKeyMatch = privateKeyPattern.exec(content)) !== null) {
                const endMarker = `-----END ${privateKeyMatch[1]}-----`;
                const endIndex = content.indexOf(endMarker, privateKeyPattern.lastIndex);
                const lineStart = content.lastIndexOf("\n", privateKeyMatch.index - 1) + 1;
                if (isCommentOnlyLine(content.slice(lineStart, privateKeyMatch.index))) {
                    if (endIndex < 0) break;
                    privateKeyPattern.lastIndex = endIndex + endMarker.length;
                    continue;
                }
                if (endIndex < 0) {
                    markCheck("secret_pattern_search", "partial", "private_key_material_incomplete");
                    break;
                }
                const keyBody = credentialContent.slice(privateKeyPattern.lastIndex, endIndex)
                    .replaceAll("\\r\\n", "\n")
                    .replaceAll("\\n", "\n")
                    .replaceAll("\\r", "\r");
                const hasKeyBody = keyBody.split(/\r?\n/)
                    .some((line) => /^[A-Za-z0-9+/=]{20,}$/.test(line.trim()));
                privateKeyPattern.lastIndex = endIndex + endMarker.length;
                if (!hasKeyBody || isPlaceholderSecret(keyBody.trim())) continue;
                recordCredential({
                    ruleId: "LUM-SEC-003",
                    type: "private key",
                    severity: "Critical",
                    confidence: "high",
                    severityRationale: "Critical: a complete PEM private-key structure with encoded key material is present; validity is not cryptographically verified.",
                    cwe: ["CWE-321", "CWE-798"],
                    file: relativePath,
                    line: getLineNumber(privateKeyMatch.index),
                    value: keyBody
                });
            }
        }

        const lines = content.split(/\r?\n/);
        let currentLineNumber = 0;
        let productionDeclared = false;
        let debugLine = null;
        let corsBlockIndent = null;
        const reportedCorsLines = new Set();
        const sensitiveHttpSetting = /\b(?:api|auth|oauth|token|issuer|jwks|endpoint|webhook|service)[\w.-]*\b\s*[:=]\s*["']?http:\/\/([^/\s"'?#]+)/i;
        const disabledTlsPatterns = [
            /\brejectUnauthorized\s*:\s*false\b/i,
            /\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?/i,
            /\b(?:insecure_skip_verify|InsecureSkipVerify)\s*[:=]\s*true\b/i,
            /\b(?:verify_ssl|ssl_verify|tls_verify|certificate_verification)\s*[:=]\s*false\b/i
        ];
        const corsPatterns = [
            /\bAccess-Control-Allow-Origin\b\s*[:=]\s*["']?\*["']?/i,
            /\b(?:allowed[_-]?origins?|cors[_-]?origins?)\b\s*[:=]\s*(?:\[\s*)?["']?\*["']?/i,
            /\bcors\b.{0,40}\borigin\b\s*[:=]\s*["']?\*["']?/i
        ];
        const productionPattern = /\b(?:NODE_ENV|APP_ENV|ENVIRONMENT|SPRING_PROFILES_ACTIVE|spring\.profiles\.active)\b\s*[:=]\s*["']?(?:production|prod)\b/i;
        const productionYamlPattern = /^\s*(?:environment|active)\s*:\s*["']?(?:production|prod)\b|^\s*production\s*:\s*true\b/i;
        const debugPattern = /^\s*["']?(?:debug|debug_mode)["']?\s*[:=]\s*["']?(?:true|1|yes)\b/i;

        for (const line of lines) {
            currentLineNumber += 1;
            const trimmed = line.trim();
            const commentOnly = /^(?:#|\/\/|\/\*|\*|<!--)/.test(trimmed);
            const lineNumber = currentLineNumber;
            if (!commentOnly && (productionPattern.test(line) || productionYamlPattern.test(line))) {
                productionDeclared = true;
            }
            if (!commentOnly && debugPattern.test(line)) debugLine = lineNumber;
            const indentation = line.length - line.trimStart().length;
            if (!commentOnly && /^\s*cors\s*:\s*$/i.test(line)) {
                corsBlockIndent = indentation;
            } else if (corsBlockIndent !== null && trimmed && !commentOnly) {
                if (indentation <= corsBlockIndent) {
                    corsBlockIndent = null;
                } else if (/^\s*(?:origin|origins|allowed[_-]?origins?)\s*:\s*(?:\[\s*)?["']?\*["']?/i.test(line)) {
                    reportedCorsLines.add(lineNumber);
                    addStaticIssue(
                        "dangerous_application_configuration",
                        "LUM-CFG-001",
                        "High",
                        "Permissive wildcard CORS configured",
                        "A CORS-related setting explicitly allows every origin, allowing arbitrary sites to read eligible API responses in browsers.",
                        "Restrict allowed origins to the exact trusted application origins and avoid wildcard access for sensitive APIs.",
                        filePath,
                        lineNumber,
                        "CORS allowed origin=*"
                    );
                }
            }

            if (!commentOnly) {
                if (isConfigurationFile(fileName) ||
                    classifyProjectFile(fileName) === "source") {
                    for (const pattern of disabledTlsPatterns) {
                        if (pattern.test(line)) {
                            addStaticIssue(
                                "insecure_transport_configuration",
                                "LUM-TLS-001",
                                "High",
                                "TLS certificate verification is disabled",
                                "The configuration explicitly disables certificate verification, allowing invalid or intercepted certificates to be accepted.",
                                "Enable certificate verification and configure the required trusted certificate authorities instead of disabling TLS checks.",
                                filePath,
                                lineNumber,
                                "TLS verification disabled"
                            );
                            break;
                        }
                    }
                }

                if (isConfigurationFile(fileName)) {
                    const endpoint = sensitiveHttpSetting.exec(line);
                    const endpointHost = endpoint?.[1]
                        .replace(/:\d+$/, "")
                        .replace(/^\[|\]$/g, "");
                    if (endpoint && !/^(?:localhost|127(?:\.\d{1,3}){3}|::1)$/i.test(endpointHost)) {
                        addStaticIssue(
                            "insecure_transport_configuration",
                            "LUM-TLS-002",
                            "Medium",
                            "Insecure HTTP security endpoint",
                            "A security-sensitive endpoint setting uses unencrypted HTTP to a non-loopback host.",
                            "Use HTTPS for this endpoint and verify the remote certificate.",
                            filePath,
                            lineNumber,
                            "security-sensitive endpoint=http://<non-loopback-host>"
                        );
                    }
                }

                if (isConfigurationFile(fileName) && corsPatterns.some((pattern) => pattern.test(line)) &&
                    !reportedCorsLines.has(lineNumber)) {
                    reportedCorsLines.add(lineNumber);
                    addStaticIssue(
                        "dangerous_application_configuration",
                        "LUM-CFG-001",
                        "High",
                        "Permissive wildcard CORS configured",
                        "A CORS-related setting explicitly allows every origin, allowing arbitrary sites to read eligible API responses in browsers.",
                        "Restrict allowed origins to the exact trusted application origins and avoid wildcard access for sensitive APIs.",
                        filePath,
                        lineNumber,
                        "CORS allowed origin=*"
                    );
                }
            }
        }

        if (isConfigurationFile(fileName) && productionDeclared && debugLine !== null) {
            addStaticIssue(
                "dangerous_application_configuration",
                "LUM-CFG-002",
                "High",
                "Debug mode enabled in production configuration",
                "The same configuration explicitly declares a production environment and enables debug mode.",
                "Disable debug mode in production and expose diagnostics only through access-controlled operational tooling.",
                filePath,
                debugLine,
                "production environment with DEBUG=true"
            );
        }

        if (isConfigurationFile(fileName) && path.extname(fileName.toLowerCase()) === ".json" &&
            !["package.json", "package-lock.json", "npm-shrinkwrap.json"].includes(fileName.toLowerCase())) {
            try {
                JSON.parse(content);
                const corsMatch = /["']cors(?:Options|Config)?["']\s*:\s*\{[\s\S]{0,512}?["'](?:origin|origins|allowedOrigins)["']\s*:\s*(?:"\*"|\[\s*"\*"\s*\])/i.exec(content);
                if (corsMatch) {
                    const lineNumber = getLineNumber(corsMatch.index);
                    if (!reportedCorsLines.has(lineNumber)) {
                        addStaticIssue(
                            "dangerous_application_configuration",
                            "LUM-CFG-001",
                            "High",
                            "Permissive wildcard CORS configured",
                            "A CORS-related setting explicitly allows every origin, allowing arbitrary sites to read eligible API responses in browsers.",
                            "Restrict allowed origins to the exact trusted application origins and avoid wildcard access for sensitive APIs.",
                            filePath,
                            lineNumber,
                            "CORS allowed origin=*"
                        );
                    }
                }
                const jsonProduction = /["'](?:NODE_ENV|APP_ENV|ENVIRONMENT|SPRING_PROFILES_ACTIVE|spring\.profiles\.active)["']\s*:\s*["']?(?:production|prod)\b|["']production["']\s*:\s*true\b/i.test(content);
                const jsonDebug = /["'](?:debug|debug_mode)["']\s*:\s*(?:true|1|"true"|'true')/i.exec(content);
                if (jsonProduction && jsonDebug && debugLine === null) {
                    addStaticIssue(
                        "dangerous_application_configuration",
                        "LUM-CFG-002",
                        "High",
                        "Debug mode enabled in production configuration",
                        "The same configuration explicitly declares a production environment and enables debug mode.",
                        "Disable debug mode in production and expose diagnostics only through access-controlled operational tooling.",
                        filePath,
                        getLineNumber(jsonDebug.index),
                        "production environment with DEBUG=true"
                    );
                }
            } catch {
                markCheck("dangerous_application_configuration", "partial", "malformed_json_configuration");
            }
        }
    };

    const scanFolder = (dir, depth = 0) => {
        if (scanLimitExceeded || dependencies.signal?.aborted) return;
        staticScanStarted = true;
        if (depth > ANALYZER_LIMITS.maxDepth) {
            stopStaticScan();
            return;
        }

        let directory;
        try {
            directory = fileSystem.opendirSync(dir);
        } catch (error) {
            markStaticChecksFailed("project_directory_unreadable");
            logger.warn("Secret-pattern scan could not open a project directory", {
                code: error.code || error.name || "UNKNOWN"
            });
            return;
        }

        try {
          let file;
          while (!scanLimitExceeded && (file = directory.readSync()) !== null) {
            scannedEntryCount += 1;
            if (scannedEntryCount > ANALYZER_LIMITS.maxFiles) {
                stopStaticScan();
                return;
            }

            const fileName = file.name;
            if (EXCLUDED_SOURCE_DIRECTORIES.has(fileName.toLowerCase())) {
                excludedStaticDirectories.add(safeRelativePath(buildContext, path.join(dir, fileName)));
                continue;
            }

            const full = path.join(dir, fileName);

            let stat;

            try {
                stat = fileSystem.lstatSync(full);
            } catch (error) {
                const checkIds = getStaticChecksForFile(full, fileName);
                skippedStaticFiles.add(full);
                unreadableStaticFiles.add(full);
                recordStaticFileOutcome(checkIds, "filesSkipped");
                recordStaticFileOutcome(checkIds, "failedReads");
                recordStaticFileOutcome(checkIds, "unreadableFiles");
                recordStaticReadError(checkIds, full, "entry_unreadable");
                recordSkippedFileDetails(checkIds, full, "entry_unreadable");
                markChecksIncomplete(checkIds, "project_entry_unreadable");
                logger.warn("Secret-pattern scan could not inspect a project path", {
                    code: error.code || error.name || "UNKNOWN"
                });
                continue;
            }

            if (stat.isSymbolicLink()) {
                skippedStaticFiles.add(full);
                const checkIds = getStaticChecksForFile(full, fileName);
                recordStaticFileOutcome(checkIds, "filesSkipped");
                recordSkippedFileDetails(checkIds, full, "symlink_skipped");
                markChecksIncomplete(checkIds, "symlink_skipped");
                continue;
            }

            if (stat.isDirectory()) {

                scanFolder(full, depth + 1);

            } else {
                if (!stat.isFile()) {
                    skippedStaticFiles.add(full);
                    const checkIds = getStaticChecksForFile(full, fileName);
                    recordStaticFileOutcome(checkIds, "filesSkipped");
                    recordStaticReadError(checkIds, full, "unsupported_entry");
                    recordSkippedFileDetails(checkIds, full, "unsupported_entry");
                    markChecksIncomplete(checkIds, "unsupported_project_entry");
                    continue;
                }
                if (!isSupportedTextFile(fileName)) {
                    const fileType = classifyProjectFile(fileName);
                    const checkIds = getStaticChecksForFile(full, fileName);
                    skippedStaticFiles.add(full);
                    if (fileType === "binary") {
                        binaryStaticFiles.add(full);
                        recordStaticFileOutcome(checkIds, "filesSkipped");
                        recordStaticFileOutcome(checkIds, "binaryFiles");
                        recordSkippedFileDetails(checkIds, full, "binary_file_excluded");
                    } else if (fileType !== "ignored") {
                        unsupportedStaticFiles.add(full);
                        recordStaticFileOutcome(checkIds, "filesSkipped");
                        recordStaticFileOutcome(checkIds, "unsupportedFiles");
                        recordSkippedFileDetails(checkIds, full, "unsupported_file_format");
                        markChecksIncomplete(checkIds, "unsupported_file_format");
                    } else {
                        excludedStaticFiles.add(full);
                    }
                    continue;
                }
                const checkIds = getStaticChecksForFile(full, fileName);
                if (stat.size > ANALYZER_LIMITS.maxFileBytes) {
                    skippedStaticFiles.add(full);
                    recordStaticFileOutcome(checkIds, "filesSkipped");
                    recordSkippedFileDetails(checkIds, full, "project_file_too_large");
                    markChecksIncomplete(checkIds, "project_file_too_large");
                    continue;
                }
                if (scannedFileCount >= ANALYZER_LIMITS.maxFiles ||
                    stat.size > ANALYZER_LIMITS.maxTotalBytes - scannedBytes) {
                    skippedStaticFiles.add(full);
                    recordStaticFileOutcome(checkIds, "filesSkipped");
                    recordSkippedFileDetails(checkIds, full, "static_resource_limit_reached");
                    stopStaticScan();
                    return;
                }

                try {
                    const readResult = readProjectFile(
                        fileSystem,
                        full,
                        {
                            maxBytes: ANALYZER_LIMITS.maxFileBytes,
                            rootPath: buildContext
                        }
                    );
                    const content = readResult.content;
                    const bytes = readResult.byteLength;
                    if (bytes > ANALYZER_LIMITS.maxFileBytes ||
                        bytes > ANALYZER_LIMITS.maxTotalBytes - scannedBytes) {
                        stopStaticScan();
                        return;
                    }
                    scannedFileCount += 1;
                    scannedBytes += bytes;
                    inspectStaticContent(full, fileName, content);
                    recordStaticFileOutcome(checkIds, "filesInspected");

                } catch (error) {
                    skippedStaticFiles.add(full);
                    const readErrorCode = error.code === "PROJECT_FILE_UNSUPPORTED_ENCODING"
                        ? "unsupported_encoding"
                        : error.code === "PROJECT_FILE_INVALID_UTF8"
                            ? "invalid_utf8"
                        : error.code === "PROJECT_FILE_BINARY"
                            ? "binary_content"
                            : error.code === "PROJECT_FILE_TOO_LARGE"
                                ? "file_too_large"
                                : "read_failed";
                    recordStaticReadError(checkIds, full, readErrorCode);
                    recordSkippedFileDetails(checkIds, full, readErrorCode);
                    if (error.code === "PROJECT_FILE_BINARY") {
                        binaryStaticFiles.add(full);
                        recordStaticFileOutcome(checkIds, "binaryFiles");
                        markChecksIncomplete(checkIds, "binary_file_skipped");
                    } else if (error.code === "PROJECT_FILE_INVALID_UTF8" ||
                        error.code === "PROJECT_FILE_UNSUPPORTED_ENCODING") {
                        unsupportedEncodingFiles.add(full);
                        recordStaticFileOutcome(checkIds, "failedReads");
                        recordStaticFileOutcome(checkIds, "unsupportedEncodings");
                        markChecksIncomplete(checkIds, "unsupported_text_encoding");
                    } else if (error.code === "PROJECT_FILE_TOO_LARGE") {
                        recordStaticFileOutcome(checkIds, "filesSkipped");
                        markChecksIncomplete(checkIds, "project_file_too_large");
                    } else {
                        unreadableStaticFiles.add(full);
                        recordStaticFileOutcome(checkIds, "failedReads");
                        recordStaticFileOutcome(checkIds, "unreadableFiles");
                        markChecksIncomplete(checkIds, "project_file_unreadable");
                    }
                    logger.warn("Secret-pattern scan could not read a project file", {
                        code: error.code || error.name || "UNKNOWN"
                    });
                }
            }
          }
        } catch (error) {
            markStaticChecksFailed("project_directory_unreadable");
            logger.warn("Secret-pattern scan could not enumerate a project directory", {
                code: error.code || error.name || "UNKNOWN"
            });
        } finally {
            directory.closeSync();
        }
    };

    try {
        const rootMetadata = fileSystem.lstatSync(buildContext);
        if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
            markStaticChecksFailed("project_root_unavailable");
        } else {
            scanFolder(buildContext);
        }
    } catch (error) {
        markStaticChecksFailed("project_root_unavailable");
        logger.warn("Static security checks could not inspect the project root", {
            code: error.code || error.name || "UNKNOWN"
        });
    }
    if (!dependencies.signal?.aborted && projectTaintModules.size > 0) {
        const coordinator = new ProjectTaintCoordinator(buildContext, {
            modules: Object.fromEntries(projectTaintModules),
            budgetManager: projectTaintBudgetManager
        });
        const projectTaintResult = coordinator.analyze();
        if (projectTaintResult.coverageStatus !== "completed") {
            const frameworkLimitation = projectTaintResult.limitations
                .filter((code) => [
                    "dynamic_route_registration_detected",
                    "framework_router_identity_ambiguous",
                    "framework_handler_ambiguous",
                    "framework_handler_external_boundary",
                    "framework_handler_unresolved",
                    "framework_discovery_traversal_limit_exceeded",
                    "unsupported_framework_request_parameter",
                    "unsupported_framework_request_pattern"
                ].includes(code))
                .sort()[0];
            const coverageReason = hasAstParseFailure
                ? (astFailureReason || "ast_parse_syntax_error")
                : frameworkLimitation || "cross_file_taint_analysis_incomplete";
            for (const checkId of [
                "dynamic_code_execution_pattern_search",
                "os_command_injection_pattern_search",
                "sql_injection_pattern_search",
                "unsafe_deserialization_pattern_search"
            ]) {
                if (checks.get(checkId) === "completed") {
                    markCheck(checkId, "partial", coverageReason);
                }
            }
        }

        for (const finding of projectTaintResult.findings) {
            const hasCrossModuleStep = finding.taintTrace?.steps?.some((step) =>
                step.fromModule && step.toModule && step.fromModule !== step.toModule
            );
            const hasFrameworkEntryPoint = finding.taintTrace?.steps?.some((step) =>
                step.frameworkEntryPoint === true
            );
            if (!hasCrossModuleStep && !hasFrameworkEntryPoint) continue;

            const absoluteFindingPath = path.resolve(buildContext, finding.file || "");
            const relativeFindingPath = safeRelativePath(buildContext, absoluteFindingPath);
            if (!relativeFindingPath) {
                markStaticChecksFailed("finding_location_unavailable");
                continue;
            }
            const sourceSpan = finding.sourceSpan;
            const existingIssue = Number.isInteger(sourceSpan?.start) &&
                Number.isInteger(sourceSpan?.end)
                ? report.issues.find((issue) =>
                    issue.ruleId === finding.ruleId &&
                    issue.file === relativeFindingPath &&
                    issue.sourceSpan?.start === sourceSpan.start &&
                    issue.sourceSpan?.end === sourceSpan.end
                )
                : null;
            const safeTrace = redactProjectTaintTrace(finding.taintTrace);
            if (existingIssue) {
                existingIssue.category = finding.category || existingIssue.category;
                existingIssue.severity = finding.severity || existingIssue.severity;
                existingIssue.confidence = finding.confidence || existingIssue.confidence;
                existingIssue.cwe = finding.cwe || existingIssue.cwe;
                existingIssue.title = finding.title || existingIssue.title;
                existingIssue.description = finding.description || existingIssue.description;
                existingIssue.severityRationale = finding.severityRationale || existingIssue.severityRationale;
                existingIssue.remediation = finding.remediation || existingIssue.remediation;
                existingIssue.recommendation = finding.recommendation || existingIssue.recommendation;
                existingIssue.evidence = finding.evidence || existingIssue.evidence;
                existingIssue.astConfirmed = true;
                existingIssue.isTaintConfirmed = true;
                existingIssue.taintTrace = safeTrace;
                existingIssue.origin = finding.origin || "ast_taint_analysis";
                existingIssue.detectionMethod = finding.detectionMethod || finding.origin;
                existingIssue.line = finding.line;
                existingIssue.sourceSpan = sourceSpan;
                existingIssue.sinkExpression = finding.sinkExpression || existingIssue.sinkExpression;
                existingIssue.sinkProvenance = finding.sinkProvenance || existingIssue.sinkProvenance;
                existingIssue.producerOrigins = [...new Set([
                    ...(existingIssue.producerOrigins || []),
                    "project_taint"
                ])].sort();
                existingIssue.sinkIdentity = createSinkIdentity(existingIssue);
                existingIssue.findingFingerprint = existingIssue.sinkIdentity ||
                    existingIssue.findingFingerprint;
                if (Number.isInteger(finding.column)) existingIssue.column = finding.column;
                existingIssue.locations = [{
                    file: relativeFindingPath,
                    line: finding.line,
                    ...(Number.isInteger(finding.column) ? { column: finding.column } : {}),
                    ...(Number.isInteger(sourceSpan?.start) ? { start: sourceSpan.start } : {}),
                    ...(Number.isInteger(sourceSpan?.end) ? { end: sourceSpan.end } : {})
                }];
                continue;
            }

            addIssue(
                finding.severity,
                finding.title,
                finding.description,
                finding.remediation,
                finding.checkId
            );
            Object.assign(report.issues[report.issues.length - 1], {
                ruleId: finding.ruleId,
                cwe: finding.cwe,
                confidence: finding.confidence,
                severityRationale: finding.severityRationale,
                remediation: finding.remediation,
                file: relativeFindingPath,
                line: finding.line,
                column: finding.column,
                origin: finding.origin || "ast_taint_analysis",
                detectionMethod: finding.detectionMethod || finding.origin,
                sourceSpan: sourceSpan || undefined,
                sinkExpression: finding.sinkExpression || undefined,
                sinkProvenance: finding.sinkProvenance || undefined,
                producerOrigins: ["project_taint"],
                sinkIdentity: createSinkIdentity({
                    ...finding,
                    file: relativeFindingPath
                }),
                findingFingerprint: createSinkIdentity({
                    ...finding,
                    file: relativeFindingPath
                }),
                isTaintConfirmed: true,
                taintTrace: safeTrace,
                evidence: finding.evidence || `${finding.title} (<redacted>)`,
                locations: [{
                    file: relativeFindingPath,
                    line: finding.line,
                    ...(Number.isInteger(finding.column) ? { column: finding.column } : {}),
                    ...(Number.isInteger(sourceSpan?.start) ? { start: sourceSpan.start } : {}),
                    ...(Number.isInteger(sourceSpan?.end) ? { end: sourceSpan.end } : {})
                }],
                occurrences: 1
            });
        }
    }
    if (dependencies.signal?.aborted) {
        markStaticChecksIncomplete("analysis_cancelled");
    } else if (staticScanStarted && scannedFileCount === 0) {
        markChecksIncomplete([
            "secret_pattern_search",
            "insecure_transport_configuration",
            "dangerous_application_configuration"
        ], "no_supported_text_files");
    }
    if (injectionSourceFiles.size === 0 &&
        checks.get("sql_injection_pattern_search") !== "failed" &&
        (checks.get("sql_injection_pattern_search") === "completed" ||
            checkReasons.get("sql_injection_pattern_search") === "no_supported_text_files")) {
        markCheck("sql_injection_pattern_search", "partial", "no_supported_injection_source_files");
    }
    if (injectionSourceFiles.size === 0 &&
        checks.get("os_command_injection_pattern_search") !== "failed" &&
        (checks.get("os_command_injection_pattern_search") === "completed" ||
            checkReasons.get("os_command_injection_pattern_search") === "no_supported_text_files")) {
        markCheck("os_command_injection_pattern_search", "partial", "no_supported_injection_source_files");
    }
    if (deserializationSourceFiles.size === 0 &&
        checks.get("unsafe_deserialization_pattern_search") !== "failed" &&
        (checks.get("unsafe_deserialization_pattern_search") === "completed" ||
            checkReasons.get("unsafe_deserialization_pattern_search") === "no_supported_text_files")) {
        markCheck("unsafe_deserialization_pattern_search", "partial", "no_supported_deserialization_source_files");
    }
    if (dynamicExecutionSourceFiles.size === 0 &&
        checks.get("dynamic_code_execution_pattern_search") !== "failed" &&
        (checks.get("dynamic_code_execution_pattern_search") === "completed" ||
            checkReasons.get("dynamic_code_execution_pattern_search") === "no_supported_text_files")) {
        markCheck("dynamic_code_execution_pattern_search", "partial", "no_supported_dynamic_execution_source_files");
    }
    if (hasAstParseFailure) {
        for (const checkId of [
            "dynamic_code_execution_pattern_search",
            "os_command_injection_pattern_search",
            "sql_injection_pattern_search",
            "unsafe_deserialization_pattern_search"
        ]) {
            if (checks.get(checkId) === "completed") {
                markCheck(checkId, "partial", astFailureReason || "ast_parse_syntax_error");
            }
        }
    }

    for (const finding of credentialFindings.values()) {
        finding.locations.sort((left, right) =>
            left.file.localeCompare(right.file) || left.line - right.line
        );
        const firstLocation = finding.locations[0];
        const credentialRemediation = "Revoke and rotate the value if it may have been used, remove it from source control, and load credentials from a managed secret store or protected environment configuration.";
        addIssue(
            finding.severity,
            `Possible hard-coded ${finding.type}`,
            "A credential indicator was found in a literal value. The scanner cannot determine whether it is valid or active.",
            credentialRemediation,
            "secret_pattern_search"
        );
        Object.assign(report.issues[report.issues.length - 1], {
            findingFingerprint: finding.findingFingerprint,
            ...(finding.ruleIds.size > 1
                ? { ruleIds: [...finding.ruleIds].sort() }
                : {}),
            ruleId: finding.ruleId,
            cwe: [...finding.cwe].sort(),
            confidence: finding.confidence,
            severityRationale: finding.severityRationale,
            remediation: credentialRemediation,
            file: firstLocation.file,
            line: firstLocation.line,
            locations: finding.locations,
            occurrences: finding.occurrences,
            evidence: `${finding.type}=<redacted>`
        });
    }

    //---------------------------------------------------
    // Dependency Vulnerabilities
    //---------------------------------------------------

    let dependencyAnalysis;
    try {
        const osvEnabled = dependencies.osvEnabled !== undefined
            ? dependencies.osvEnabled
            : process.env.LUMINICENT_OSV_API_ENABLED === undefined ||
                process.env.LUMINICENT_OSV_API_ENABLED === "true";
        const result = await analyzeDependencies(dependencies.dependencyRoot || buildContext, {
            fs: fileSystem,
            fetch: dependencies.fetch,
            signal: dependencies.signal,
            now: dependencies.now,
            enabled: osvEnabled
        });
        dependencyAnalysis = result.metadata;
        const dependencyStatus = result.metadata.reason === "advisory_query_disabled"
            ? "skipped"
            : result.metadata.status === "partial"
                ? "partial"
                : result.status;
        markCheck(
            "dependency_vulnerability_analysis",
            dependencyStatus,
            dependencyStatus === "completed" ? null : result.metadata.reason || "dependency_analysis_failed"
        );
        for (const finding of result.findings) {
            const remediation = finding.remediation || (finding.fixedVersion
                ? `Upgrade ${finding.dependency.package} to ${finding.fixedVersion} or later.`
                : `Review advisory ${finding.dependency.advisoryId} and update ${finding.dependency.package} to a version confirmed as unaffected.`);
            const cveIds = finding.cveIds || finding.dependency?.cveIds || [];
            const ghsaIds = finding.ghsaIds || finding.dependency?.ghsaIds || [];
            const cvssScore = finding.cvssScore ?? finding.dependency?.cvssScore ?? null;
            const cvssVector = finding.cvssVector ?? finding.dependency?.cvssVector ?? null;
            const fixedVersion = finding.fixedVersion ?? finding.dependency?.fixedVersion ?? null;
            const affectedVersionRange = finding.affectedVersionRange ?? finding.dependency?.affectedVersionRange ?? null;
            const severityRationale = finding.severityRationale || (cvssScore !== null
                ? `Advisory database severity: ${finding.severity} (CVSS score ${cvssScore})`
                : `Advisory database severity: ${finding.severity}`);

            addIssue(
                finding.severity,
                `Dependency vulnerability: ${finding.dependency.package} (${finding.dependency.advisoryId})`,
                finding.summary,
                remediation,
                "dependency_vulnerability_analysis",
                {
                    ruleId: "LUM-DEP-OSV",
                    category: "dependency",
                    confidence: "High",
                    cwe: finding.dependency?.cweIds || [],
                    cveIds,
                    ghsaIds,
                    cvssScore,
                    cvssVector,
                    affectedVersionRange,
                    fixedVersion,
                    severityRationale,
                    file: finding.dependency?.manifest || null,
                    line: null,
                    origin: "manifest_advisory",
                    dependency: {
                        ...finding.dependency,
                        ...(fixedVersion ? { fixedVersion } : {}),
                        advisoryModified: finding.advisoryModified
                    }
                }
            );
            report.issues[report.issues.length - 1].dependency = {
                ...finding.dependency,
                ...(fixedVersion ? { fixedVersion } : {}),
                advisoryModified: finding.advisoryModified
            };
            report.issues[report.issues.length - 1].remediation = remediation;
        }
    } catch (error) {
        markCheck("dependency_vulnerability_analysis", "failed", "dependency_analysis_failed");
        dependencyAnalysis = {
            source: "OSV",
            status: "failed",
            reason: "dependency_analysis_failed",
            freshness: "No local advisory cache is used; OSV does not expose a database-wide freshness timestamp."
        };
        logger.warn("Dependency vulnerability analysis failed", {
            code: error.code || error.name || "UNKNOWN"
        });
    }
    report.dependencyAnalysis = dependencyAnalysis;

    //---------------------------------------------------
    // Project Checks
    //---------------------------------------------------

    const nodeModules = path.join(buildContext, "node_modules");

    if (fileSystem.existsSync(nodeModules)) {

        addIssue(
            "Low",
            "node_modules Included",
            "Project contains node_modules.",
            "Use .dockerignore to exclude node_modules.",
            "project_structure",
            {
                ruleId: "LUM-STR-NODE-MODULES",
                category: "project_structure",
                confidence: "High",
                cwe: ["CWE-1059"],
                file: "node_modules",
                line: null,
                severityRationale: "Committing or copying node_modules directly bloats the repository and risks host-architecture binary mismatches.",
                origin: "configuration_analysis"
            }
        );
    }

    const readme = path.join(buildContext, "README.md");

    if (!fileSystem.existsSync(readme)) {

        addIssue(
            "Low",
            "README Missing",
            "Project documentation is missing.",
            "Add a README.md.",
            "project_structure",
            {
                ruleId: "LUM-STR-README-MISSING",
                category: "project_structure",
                confidence: "High",
                cwe: ["CWE-1059"],
                file: null,
                line: null,
                severityRationale: "Project documentation is missing, impacting operational readiness.",
                origin: "configuration_analysis"
            }
        );
    }

    // Check lock file for Node projects
    const packageLock = path.join(buildContext, "package-lock.json");
    const packageManifest = path.join(buildContext, "package.json");

    if (fileSystem.existsSync(packageManifest) && !fileSystem.existsSync(packageLock)) {

        addIssue(
            "Low",
            "Lock File Missing",
            "Dependencies are not locked.",
            "Commit package-lock.json.",
            "project_structure",
            {
                ruleId: "LUM-STR-LOCKFILE-MISSING",
                category: "project_structure",
                confidence: "High",
                cwe: ["CWE-1104"],
                file: "package.json",
                line: null,
                severityRationale: "Dependencies are declared without a lockfile, allowing unpinned transitive version changes.",
                origin: "configuration_analysis"
            }
        );
    }

    //---------------------------------------------------
    // Final Status & Standardization
    //---------------------------------------------------

    // Remove duplicate recommendations
    report.recommendations = [...new Set(report.recommendations)];

    // Standardize findings
    report.issues = reconcileFindingsBySinkIdentity(report.issues);
    const initialRisk = calculateProjectRisk(report.issues, { coverageComplete: false });
    report.issues = initialRisk.findings;
    report.findings = initialRisk.findings;

    const reasonMessages = {
        advisory_data_unavailable_or_invalid: "The external advisory service failed or returned unusable data.",
        advisory_query_disabled: "Dependency advisory lookups are disabled; dependency coverage was not completed.",
        advisory_query_timeout: "The external advisory lookup timed out.",
        analysis_cancelled: "The analysis was cancelled before this check completed.",
        configuration_input_invalid: "A required configuration input was not a regular file or exceeded its read limit.",
        configuration_input_unreadable: "A required configuration input could not be read.",
        dependency_analysis_failed: "Dependency analysis could not complete.",
        dependency_file_binary: "A dependency manifest contains binary data and could not be decoded.",
        dependency_file_invalid_encoding: "A dependency manifest is not valid UTF-8.",
        dependency_file_unreadable: "A dependency manifest could not be read safely.",
        dependency_analysis_not_completed: "Dependency analysis did not complete.",
        dependency_count_exceeds_limit: "The dependency inventory exceeded its analysis limit.",
        dependency_entry_limit_exceeded: "The dependency inventory exceeded its entry limit.",
        dependency_depth_limit_exceeded: "The dependency inventory exceeded its directory-depth limit.",
        dependency_inventory_incomplete: "The dependency inventory could not be inspected completely.",
        dependency_symlink_skipped: "A symbolic link prevented complete dependency inventory.",
        dockerfile_missing: "Dockerfile-dependent checks were skipped because the project has no Dockerfile.",
        finding_location_unavailable: "A finding could not be safely associated with a project-relative location.",
        image_metadata_unavailable: "Image metadata could not be retrieved.",
        lockfile_exceeds_size_limit: "A dependency lockfile exceeded its analysis size limit.",
        malformed_json_configuration: "A supported JSON configuration file is malformed, so this check is incomplete.",
        no_container_provided: "Runtime inspection was skipped because no container was provided.",
        no_supported_dependency_manifest: "No supported dependency lockfile was found; other dependency ecosystems are not analyzed.",
        no_supported_text_files: "The project contains no supported UTF-8 source, configuration, or documentation files.",
        no_supported_injection_source_files: "No non-exempt JavaScript, TypeScript, or Python source files were available for injection-pattern checks.",
        no_supported_deserialization_source_files: "No non-exempt Python or JavaScript/TypeScript source files were available for unsafe deserialization checks.",
        no_supported_dynamic_execution_source_files: "No non-exempt JavaScript or TypeScript source files were available for dynamic code execution checks.",
        dependency_total_size_limit_exceeded: "Dependency files exceeded the total analysis size limit.",
        multiple_npm_lockfiles: "Multiple npm lockfiles in one project scope could not be resolved safely.",
        not_implemented: "This check is not implemented.",
        npm_lockfile_invalid: "An npm lockfile or its corresponding manifest could not be validated.",
        npm_lockfile_missing: "An npm manifest was found without a supported lockfile.",
        python_lockfile_invalid: "A Python lockfile or requirements file could not be validated.",
        python_lockfile_missing: "A Python manifest was found without a supported lockfile.",
        unresolved_dependency_ranges: "One or more dependencies declare unresolved version ranges rather than pinned versions.",
        transitive_coverage_incomplete: "The dependency manifest does not specify the complete transitive dependency graph.",
        private_key_material_incomplete: "A private-key marker was found without a complete supported key structure.",
        project_directory_unreadable: "A project directory could not be inspected completely.",
        project_entry_unreadable: "A project entry could not be inspected.",
        project_file_unreadable: "A supported project file could not be read or decoded.",
        project_file_too_large: "A supported project file exceeded its configured per-file read limit.",
        project_root_unavailable: "The extracted project root could not be inspected.",
        runtime_inspection_failed: "Runtime metadata inspection failed.",
        static_analysis_failed: "Static analysis could not complete.",
        static_only_scope: "Image metadata is outside the static-only scan scope.",
        static_resource_limit_reached: "A static-analysis resource limit was reached; remaining files were not checked.",
        symlink_skipped: "A symbolic link was skipped to keep analysis within the extracted project boundary.",
        unsupported_dependency_formats: "Only supported npm and Python lockfiles are analyzed; other detected dependency formats are not covered.",
        unsupported_file_format: "One or more unsupported file formats were skipped.",
        unsupported_text_encoding: "A supported project file could not be decoded as strict UTF-8.",
        unsupported_project_entry: "A non-regular project entry was skipped.",
        binary_file_skipped: "One or more binary files were skipped because this check supports text input.",
        ast_parse_syntax_error: "One or more JavaScript or TypeScript files had syntax errors that prevented full AST analysis.",
        ast_source_size_limit_exceeded: "One or more JavaScript or TypeScript files exceeded the AST source analysis size limit.",
        ast_traversal_limit_exceeded: "One or more JavaScript or TypeScript files exceeded AST traversal limits.",
        cross_file_taint_analysis_incomplete: "Project-wide cross-file taint analysis was incomplete because a module, symbol, call-graph, cache, or shared resource limit was reached.",
        dynamic_route_registration_detected: "A statically verified Express-like router has a dynamic or ambiguous route registration that could not be fully analyzed.",
        framework_handler_ambiguous: "A registered framework handler resolved to multiple project symbols and was not guessed.",
        framework_handler_external_boundary: "A registered handler belongs to an external package and was not traversed.",
        framework_handler_unresolved: "A registered framework handler could not be resolved to a statically indexed project function.",
        framework_discovery_traversal_limit_exceeded: "Framework entry-point discovery exceeded its bounded AST traversal limit.",
        unsupported_framework_request_parameter: "A registered handler uses an unsupported request parameter pattern.",
        unsupported_framework_request_pattern: "A registered handler destructures request data using an unsupported pattern."
    };
    const checksWithDetails = [...checks].map(([id, status]) => {
        const definition = checkDefinitions[id];
        const findingCount = report.issues.filter((issue) => issue.checkId === id).length;
        const reasonCode = status === "completed"
            ? undefined
            : checkReasons.get(id) || "static_analysis_failed";
        const reason = reasonCode
            ? {
                code: reasonCode,
                message: reasonMessages[reasonCode] || "Coverage for this check is unavailable or incomplete."
            }
            : undefined;
        let explanation;
        if (status === "completed") {
            explanation = findingCount > 0
                ? `${findingCount} finding(s) reported within the stated scope.`
                : "No issues found within the stated scope.";
        } else {
            explanation = reason.message;
            if (id === "dependency_vulnerability_analysis" &&
                reasonCode === "unsupported_dependency_formats" &&
                dependencyAnalysis?.unsupportedFormats?.length) {
                explanation += ` Detected but not covered: ${dependencyAnalysis.unsupportedFormats.join(", ")}.`;
            }
        }
        let evidence;
        if (staticCheckIds.includes(id)) {
            const checkEvidence = staticEvidenceByCheck.get(id);
            evidence = {
                filesInspected: checkEvidence.filesInspected,
                filesAnalyzed: checkEvidence.filesInspected,
                filesSkipped: checkEvidence.filesSkipped,
                unsupportedFiles: checkEvidence.unsupportedFiles,
                binaryFiles: checkEvidence.binaryFiles,
                failedReads: checkEvidence.failedReads,
                unreadableFiles: checkEvidence.unreadableFiles,
                unsupportedEncodings: checkEvidence.unsupportedEncodings,
                ...(checkEvidence.readErrors.length > 0
                    ? { readErrors: checkEvidence.readErrors }
                    : {}),
                ...(checkEvidence.skippedFileDetails.length > 0
                    ? { skippedFileDetails: checkEvidence.skippedFileDetails }
                    : {}),
                entriesInspected: scannedEntryCount,
                projectFilesInspected: scannedFileCount,
                projectFilesSkipped: skippedStaticFiles.size,
                projectUnsupportedFiles: unsupportedStaticFiles.size,
                projectBinaryFiles: binaryStaticFiles.size,
                ...(id === "secret_pattern_search"
                    ? { credentialExemptFiles: credentialExemptFiles.size }
                    : {})
            };
        } else if (id === "dependency_vulnerability_analysis") {
            evidence = {
                manifestsInspected: dependencyAnalysis?.manifestCount ?? null,
                declarationsDiscovered: dependencyAnalysis?.declarationsDiscoveredCount ?? null,
                packageVersionsResolved: dependencyAnalysis?.packageVersionsResolvedCount ??
                    dependencyAnalysis?.resolvedCount ?? null,
                packagesSubmittedToOSV: dependencyAnalysis?.packagesSubmittedToOsvCount ??
                    dependencyAnalysis?.submittedCount ?? null,
                packagesSuccessfullyInspected: dependencyAnalysis?.packagesSuccessfullyInspectedCount ??
                    dependencyAnalysis?.inspectedCount ?? null,
                packagesUnresolved: dependencyAnalysis?.packagesUnresolvedCount ??
                    dependencyAnalysis?.unresolvedCount ?? null,
                packagesSkipped: dependencyAnalysis?.packagesSkippedCount ??
                    dependencyAnalysis?.skippedCount ?? null,
                advisoriesFound: dependencyAnalysis?.advisoriesFoundCount ??
                    dependencyAnalysis?.advisoryCount ?? null
            };
        } else if (id === "dockerfile_presence" || id === "dockerfile_configuration") {
            evidence = { dockerfilePresent: dockerfileExists };
        } else if (id === "dockerignore_configuration") {
            evidence = { dockerfilePresent: dockerfileExists, dockerignorePresent: fileSystem.existsSync(dockerignorePath) };
        } else if (id === "environment_configuration") {
            evidence = {
                environmentExamplePresent: fileSystem.existsSync(envExample),
                environmentFilePresent: fileSystem.existsSync(envPath)
            };
        } else if (id === "project_structure") {
            evidence = {
                readmePresent: fileSystem.existsSync(readme),
                packageManifestPresent: fileSystem.existsSync(packageManifest),
                npmLockfilePresent: fileSystem.existsSync(packageLock),
                nodeModulesPresent: fileSystem.existsSync(nodeModules)
            };
        } else if (id === "image_metadata") {
            evidence = { imageMetadataAvailable: Boolean(report.docker.imageId) };
        } else if (id === "runtime_inspection") {
            evidence = { containerProvided: Boolean(container), runtimeMetadataAvailable: Boolean(report.runtime.status) };
        } else {
            evidence = {};
        }
        return {
            id,
            name: definition.name,
            category: definition.category,
            categoryName: definition.categoryName,
            status,
            scope: definition.scope,
            explanation,
            evidence,
            ...(reason ? { reason } : {}),
            findingCount
        };
    });
    const coverageComplete = checksWithDetails.every((check) => check.status === "completed");
    const coverageCounts = Object.fromEntries(
        ["completed", "partial", "skipped", "unsupported", "failed"].map((status) => [
            status,
            checksWithDetails.filter((check) => check.status === status).length
        ])
    );
    const categoryGroups = new Map();
    for (const check of checksWithDetails) {
        const group = categoryGroups.get(check.category) || {
            id: check.category,
            name: check.categoryName,
            checks: [],
            reasons: [],
            findingCount: 0
        };
        group.checks.push(check.id);
        group.findingCount += check.findingCount;
        if (check.reason && !group.reasons.some((reason) => reason.code === check.reason.code)) {
            group.reasons.push(check.reason);
        }
        categoryGroups.set(check.category, group);
    }
    const statusPriority = ["failed", "partial", "unsupported", "skipped", "completed"];
    const categories = [...categoryGroups.values()].map((category) => {
        const categoryChecks = checksWithDetails.filter((check) => check.category === category.id);
        category.status = statusPriority.find((status) =>
            categoryChecks.some((check) => check.status === status)
        );
        return category;
    });
    report.scan = {
        status: coverageComplete ? "completed" : "partial",
        findingsDetected: report.issues.length > 0,
        findingCount: report.issues.length,
        coverage: {
            status: coverageComplete ? "completed" : "partial",
            checkCount: checksWithDetails.length,
            counts: coverageCounts,
            inventory: {
                filesInspected: scannedFileCount,
                filesSkipped: skippedStaticFiles.size,
                unreadableFiles: unreadableStaticFiles.size,
                unsupportedEncodings: unsupportedEncodingFiles.size,
                unsupportedFiles: unsupportedStaticFiles.size,
                binaryFiles: binaryStaticFiles.size,
                excludedFilesByPolicy: excludedStaticFiles.size,
                excludedDirectoriesByPolicy: excludedStaticDirectories.size
            },
            categories
        },
        assessment: report.issues.length > 0
            ? coverageComplete
                ? "Findings were reported by checks performed; this is not a complete security assessment."
                : "Findings were reported, but coverage is incomplete; this is not a complete security assessment."
            : coverageComplete
                ? "No findings in checks performed; this does not establish that the application is secure."
                : "No findings in checks performed, but coverage is incomplete; this does not establish that the application is secure.",
        checks: checksWithDetails
    };

    // Calculate final project risk and score based on completed scan coverage
    const finalRisk = calculateProjectRisk(report.issues, { coverageComplete });
    report.score = finalRisk.securityScore;
    report.status = finalRisk.status;
    report.summary = finalRisk.summary;
    report.risk = {
        score: finalRisk.riskScore,
        level: finalRisk.riskLevel,
        securityScore: finalRisk.securityScore,
        totalImpact: finalRisk.totalImpact,
        formula: finalRisk.formula,
        calibrationConstant: finalRisk.calibrationConstant,
        summary: finalRisk.summary,
        rationale: finalRisk.rationale
    };
    report.schemaVersion = "2.0.0";
    report.findings = finalRisk.findings;
    report.issues = finalRisk.findings;
    report.scan.findingCount = report.issues.length;
    report.scan.findingsDetected = report.issues.length > 0;
    report.limitations = [
        "Analysis is strictly static; dynamic runtime behavior, symbolic execution, and payload reachability were not evaluated.",
        "Absence of findings in unanalyzed or unsupported file formats does not establish absence of vulnerabilities.",
        "Static pattern indicators carry inherent false-positive and false-negative trade-offs; findings must be validated in application context."
    ];

    // Add timestamp
    report.generatedAt = (dependencies.now || (() => new Date()))().toISOString();

    return report;
}