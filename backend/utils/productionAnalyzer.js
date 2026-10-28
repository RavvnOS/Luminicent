import fs from "fs";
import path from "path";
import { getDockerInstance } from "./dockerOrchestrator.js";
import { analyzeDependencies } from "./dependencyAnalyzer.js";

const docker = getDockerInstance();
const ANALYZER_LIMITS = Object.freeze({
    dockerOperationTimeoutMs: 10000,
    maxFiles: 10000,
    maxFileBytes: 10 * 1024 * 1024,
    maxTotalBytes: 100 * 1024 * 1024,
    maxDepth: 32
});
const SOURCE_EXTENSIONS = new Set([
    ".c", ".cc", ".cpp", ".cs", ".css", ".dart", ".go", ".h", ".hpp", ".html",
    ".java", ".js", ".jsx", ".key", ".kt", ".map", ".pem", ".php", ".py", ".rb",
    ".rs", ".scala", ".sh", ".sql", ".svg", ".svelte", ".swift", ".ts", ".tsx", ".vue"
]);
const DOCUMENT_EXTENSIONS = new Set([".adoc", ".md", ".rst", ".txt"]);
const CONFIG_EXTENSIONS = new Set([
    ".cfg", ".conf", ".config", ".env", ".gradle", ".hcl", ".ini", ".json",
    ".properties", ".tf", ".toml", ".xml", ".yaml", ".yml"
]);
const BINARY_EXTENSIONS = new Set([
    ".7z", ".bmp", ".class", ".dll", ".exe", ".gif", ".gz", ".ico", ".jar",
    ".jpeg", ".jpg", ".mp3", ".mp4", ".pdf", ".png", ".pyc", ".so", ".tar",
    ".tif", ".tiff", ".wasm", ".webp", ".woff", ".woff2", ".zip"
]);
const SUPPORTED_TEXT_BASENAMES = new Set([
    ".dockerignore", ".gitignore", ".npmrc", ".pypirc", ".netrc", "dockerfile",
    "gemfile", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa", "license", "makefile",
    "notice", "procfile"
]);
const IGNORED_NON_SOURCE_BASENAMES = new Set([".ds_store", "desktop.ini", "thumbs.db"]);
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

const readBoundedFile = (fileSystem, filePath, maxBytes) => {
    let descriptor;
    try {
        const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
        descriptor = fileSystem.openSync(filePath, flags);
        const metadata = fileSystem.fstatSync(descriptor);
        if (!metadata.isFile() || metadata.size > maxBytes) {
            const error = new Error("Analyzer file size limit exceeded");
            error.code = "ANALYZER_FILE_LIMIT";
            throw error;
        }
        const chunks = [];
        const buffer = Buffer.alloc(64 * 1024);
        let totalBytes = 0;
        while (true) {
            const readBytes = fileSystem.readSync(
                descriptor,
                buffer,
                0,
                Math.min(buffer.length, maxBytes - totalBytes + 1),
                null
            );
            if (readBytes === 0) break;
            totalBytes += readBytes;
            if (totalBytes > maxBytes) {
                const error = new Error("Analyzer file size limit exceeded");
                error.code = "ANALYZER_FILE_LIMIT";
                throw error;
            }
            chunks.push(Buffer.from(buffer.subarray(0, readBytes)));
        }
        const content = Buffer.concat(chunks, totalBytes);
        if (content.includes(0)) {
            const error = new Error("Analyzer does not scan binary files");
            error.code = "ANALYZER_BINARY_FILE";
            throw error;
        }
        try {
            return new TextDecoder("utf-8", { fatal: true }).decode(content);
        } catch {
            const error = new Error("Analyzer file is not valid UTF-8 text");
            error.code = "ANALYZER_BINARY_FILE";
            throw error;
        }
    } finally {
        if (descriptor !== undefined) fileSystem.closeSync(descriptor);
    }
};

const isSupportedTextFile = (fileName) => {
    const lowerName = fileName.toLowerCase();
    if (SUPPORTED_TEXT_BASENAMES.has(lowerName)) return true;
    return lowerName === ".env" || lowerName.startsWith(".env.") ||
        SOURCE_EXTENSIONS.has(path.extname(lowerName)) ||
        DOCUMENT_EXTENSIONS.has(path.extname(lowerName)) ||
        CONFIG_EXTENSIONS.has(path.extname(lowerName));
};

const isConfigurationFile = (fileName) =>
    CONFIG_EXTENSIONS.has(path.extname(fileName.toLowerCase())) ||
    [".dockerignore", ".env", ".npmrc", ".pypirc", ".netrc", "dockerfile"].includes(fileName.toLowerCase());

const isPlaceholderSecret = (value) => {
    const normalized = value.trim().toLowerCase();
    return normalized.length < 8 ||
        /(?:process\.env|system\.getenv|os\.getenv|env\(|\$\{)/i.test(normalized) ||
        /^(?:your|example|sample|dummy|fake|test|testing|changeme|change_me|replace_me|redacted|placeholder|not_a_secret|none|null|undefined)(?:[-_].*)?$/.test(normalized) ||
        /^(?:x+|0+|1+|123456+|<[^>]*>|\*+)$/.test(normalized) ||
        /(?:example|placeholder|changeme|redacted)/.test(normalized);
};

const safeRelativePath = (rootPath, filePath) => {
    const relativePath = path.relative(path.resolve(rootPath), path.resolve(filePath));
    if (!relativePath || path.isAbsolute(relativePath) || relativePath === ".." ||
        relativePath.startsWith(`..${path.sep}`)) return null;
    return relativePath.split(path.sep)
        .map((part) => part.replace(/[^\w.@+-]/g, "_"))
        .join("/");
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
    const logger = dependencies.logger || console;
    const checks = new Map([
        ["dockerfile_presence", "completed"],
        ["dockerfile_configuration", "completed"],
        ["dockerignore_configuration", "completed"],
        ["environment_configuration", "completed"],
        ["image_metadata", "completed"],
        ["runtime_inspection", container ? "completed" : "not_performed"],
        ["secret_pattern_search", "completed"],
        ["insecure_transport_configuration", "completed"],
        ["dangerous_application_configuration", "completed"],
        ["project_structure", "completed"],
        ["owasp_top_10", "unsupported"],
        ["dynamic_vulnerability_testing", "unsupported"],
        ["dependency_vulnerability_analysis", "failed"],
        ["exploit_verification", "unsupported"]
    ]);
    const checkDefinitions = {
        dockerfile_presence: {
            name: "Dockerfile presence",
            scope: "Whether the selected build context contains a Dockerfile."
        },
        dockerfile_configuration: {
            name: "Dockerfile configuration",
            scope: "Selected Dockerfile heuristics: non-root USER, HEALTHCHECK, build stages, image tags, and npm install usage."
        },
        dockerignore_configuration: {
            name: ".dockerignore configuration",
            scope: "Presence and node_modules exclusion in the selected build context."
        },
        environment_configuration: {
            name: "Environment configuration",
            scope: "Whether an .env.example is present without a corresponding .env file."
        },
        image_metadata: {
            name: "Docker image metadata",
            scope: "Image availability and metadata from the Docker daemon, including image size."
        },
        runtime_inspection: {
            name: "Runtime inspection",
            scope: "Container state and runtime metadata from the Docker daemon."
        },
        secret_pattern_search: {
            name: "Hard-coded credential indicators",
            scope: "Bounded pattern checks for likely credentials in supported UTF-8 source, configuration, and documentation files; patterns do not establish that a credential is active. Excludes .git, dependencies, virtual environments, caches, and generated build directories."
        },
        insecure_transport_configuration: {
            name: "Insecure transport configuration",
            scope: "Explicit TLS verification disabling and non-local HTTP URLs in security-sensitive settings within supported UTF-8 source and configuration files."
        },
        dangerous_application_configuration: {
            name: "Dangerous application configuration",
            scope: "Explicit wildcard CORS and debug-enabled settings only when production intent is declared in the same supported configuration file."
        },
        project_structure: {
            name: "Project structure",
            scope: "Selected project structure heuristics such as README, lockfile, and node_modules presence."
        },
        owasp_top_10: {
            name: "OWASP Top 10 assessment",
            scope: "Application-level OWASP Top 10 analysis."
        },
        dynamic_vulnerability_testing: {
            name: "Dynamic vulnerability testing",
            scope: "Runtime probing for application vulnerabilities."
        },
        dependency_vulnerability_analysis: {
            name: "Dependency vulnerability analysis",
            scope: "Supported npm lockfiles and exact package versions queried against OSV; other ecosystems are not scanned."
        },
        exploit_verification: {
            name: "Exploit verification",
            scope: "Verification that reported vulnerabilities are exploitable in this application."
        }
    };
    const markCheck = (checkId, status) => checks.set(checkId, status);

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

    const addIssue = (severity, title, description, recommendation, checkId) => {

        report.issues.push({
            severity,
            title,
            description,
            recommendation,
            checkId
        });

        report.recommendations.push(recommendation);

        switch (severity) {

            case "Critical":
                report.score -= 20;
                break;

            case "High":
                report.score -= 15;
                break;

            case "Medium":
                report.score -= 10;
                break;

            case "Low":
                report.score -= 5;
                break;
        }
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
                markCheck(checkId, "failed");
                logger.warn("Analyzer configuration file exceeded its read limit", {
                    check: checkId
                });
                return "";
            }
            return fileSystem.readFileSync(filePath, "utf8");
        } catch (error) {
            markCheck(checkId, "failed");
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
            "dockerfile_presence"
        );

        markCheck("dockerfile_configuration", "not_performed");
        markCheck("dockerignore_configuration", "not_performed");
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
        markCheck("dockerignore_configuration", "not_performed");
    } else if (!fileSystem.existsSync(dockerignorePath)) {

        addIssue(
            "Medium",
            ".dockerignore Missing",
            "Docker will copy unnecessary files.",
            "Create a .dockerignore file.",
            "dockerignore_configuration"
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
                "dockerignore_configuration"
            );
        }
    }

    //---------------------------------------------------
    // Environment File
    //---------------------------------------------------

    if (dockerfileExists && !fileSystem.existsSync(envPath) && fileSystem.existsSync(envExample)) {

        addIssue(
            "Medium",
            ".env Missing",
            ".env.example exists but .env is missing.",
            "Create a production .env file.",
            "environment_configuration"
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
            "dockerfile_configuration"
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
            "dockerfile_configuration"
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
            "dockerfile_configuration"
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
            "dockerfile_configuration"
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
            "dockerfile_configuration"
        );
    }

    //---------------------------------------------------
    // Image Information
    //---------------------------------------------------

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
                "image_metadata"
            );
        }

    } catch (err) {
        markCheck("image_metadata", "failed");
        logger.error("Image metadata check failed", {
            code: err.code || err.statusCode || err.name || "UNKNOWN"
        });
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

            report.runtime.running = inspect.State.Running;

            report.runtime.status = inspect.State.Status;

            report.runtime.startedAt = inspect.State.StartedAt;

            report.runtime.exitCode = inspect.State.ExitCode;

        } catch (err) {

            markCheck("runtime_inspection", "failed");
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
    let scanLimitExceeded = false;
    let malformedJsonConfiguration = false;
    let staticScanIncomplete = false;
    let unsupportedFileFormatFound = false;
    let binaryFileSkipped = false;
    const staticCheckIds = [
        "secret_pattern_search",
        "insecure_transport_configuration",
        "dangerous_application_configuration"
    ];

    const markStaticChecksFailed = () => {
        staticScanIncomplete = true;
        for (const checkId of staticCheckIds) markCheck(checkId, "failed");
    };

    const markStaticChecksIncomplete = () => {
        for (const checkId of staticCheckIds) {
            if (checks.get(checkId) === "completed") markCheck(checkId, "partial");
        }
    };

    const stopStaticScan = () => {
        scanLimitExceeded = true;
        markStaticChecksFailed();
        logger.warn("Static security checks stopped at their configured resource limit");
    };

    const addStaticIssue = (checkId, ruleId, severity, title, explanation, recommendation, filePath, lineNumber, evidence) => {
        const relativePath = safeRelativePath(buildContext, filePath);
        if (!relativePath) {
            markStaticChecksFailed();
            return;
        }
        addIssue(severity, title, explanation, recommendation, checkId);
        Object.assign(report.issues[report.issues.length - 1], {
            ruleId,
            file: relativePath,
            line: lineNumber,
            evidence
        });
    };

    const inspectStaticContent = (filePath, fileName, content) => {
        const relativePath = safeRelativePath(buildContext, filePath);
        if (!relativePath) {
            markStaticChecksFailed();
            return;
        }
        const fixturePath = /(?:^|\/)(?:__fixtures__|fixtures?|test-fixtures?)(?:\/|$)/i.test(relativePath);
        const getLineNumber = createLineNumberLookup(content);
        const assignmentPattern = /\b(api[_-]?key|client[_-]?secret|secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|password|passwd|private[_-]?key|aws_secret_access_key|mongo(?:db)?[_-]?uri|database[_-]?url|connection[_-]?string|jwt[_-]?secret)\b\s*[:=]\s*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})'|([^\s,;#}\]]{8,}))/gi;
        let match;
        const reportedSecrets = new Set();
        const reportedSecretLines = new Set();
        while ((match = assignmentPattern.exec(content)) !== null) {
            const value = (match[2] || match[3] || match[4] || "").replace(/[;,]+$/, "");
            if (fixturePath || isPlaceholderSecret(value) ||
                match[1].toLowerCase().includes("private") && value.startsWith("-----BEGIN")) continue;
            const line = getLineNumber(match.index);
            const unique = `${line}:${match[1].toLowerCase()}`;
            if (reportedSecrets.has(unique)) continue;
            reportedSecrets.add(unique);
            reportedSecretLines.add(line);
            addStaticIssue(
                "secret_pattern_search",
                "LUM-SEC-001",
                "High",
                "Possible hard-coded credential",
                "A credential-like value is assigned to a sensitive setting. Pattern matching does not prove that the value is valid or active.",
                "Revoke and rotate the value if it may have been used, then load credentials from a managed secret store or protected environment configuration.",
                filePath,
                line,
                `${match[1]}=<redacted>`
            );
        }

        const privateKeyPattern = /-----BEGIN ((?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY)-----/g;
        while ((match = privateKeyPattern.exec(content)) !== null) {
            if (fixturePath) continue;
            const endMarker = `-----END ${match[1]}-----`;
            const endIndex = content.indexOf(endMarker, privateKeyPattern.lastIndex);
            if (endIndex < 0) {
                markCheck("secret_pattern_search", "failed");
                break;
            }
            const hasKeyBody = content.slice(privateKeyPattern.lastIndex, endIndex)
                    .split(/\r?\n/)
                    .some((line) => /^[A-Za-z0-9+/=]{20,}$/.test(line.trim()));
            privateKeyPattern.lastIndex = endIndex + endMarker.length;
            if (!hasKeyBody) continue;
            addStaticIssue(
                "secret_pattern_search",
                "LUM-SEC-001",
                "Critical",
                "Private-key material detected",
                "A private-key PEM header was found. The key may be test or example material; the scanner does not validate it.",
                "Remove the key from source control and rotate or revoke it if it could be real.",
                filePath,
                getLineNumber(match.index),
                "PRIVATE KEY material=<redacted>"
            );
        }

        const providerTokenPattern = /\b(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|sk_live_[A-Za-z0-9]{16,})\b/g;
        while ((match = providerTokenPattern.exec(content)) !== null) {
            if (fixturePath || isPlaceholderSecret(match[0]) ||
                reportedSecretLines.has(getLineNumber(match.index))) continue;
            addStaticIssue(
                "secret_pattern_search",
                "LUM-SEC-001",
                "High",
                "Possible hard-coded credential",
                "A value matches a known credential format. This does not establish that the credential is valid or active.",
                "Revoke and rotate the value if it may have been used, then remove it from source control and use a managed secret store.",
                filePath,
                getLineNumber(match.index),
                "credential-like token=<redacted>"
            );
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
                    SOURCE_EXTENSIONS.has(path.extname(fileName.toLowerCase()))) {
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
                malformedJsonConfiguration = true;
                markCheck("dangerous_application_configuration", "failed");
            }
        }
    };

    const scanFolder = (dir, depth = 0) => {
        if (scanLimitExceeded || dependencies.signal?.aborted) return;
        if (depth > ANALYZER_LIMITS.maxDepth) {
            stopStaticScan();
            return;
        }

        let directory;
        try {
            directory = fileSystem.opendirSync(dir);
        } catch (error) {
            markStaticChecksFailed();
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
                continue;
            }

            const full = path.join(dir, fileName);

            let stat;

            try {
                stat = fileSystem.lstatSync(full);
            } catch (error) {
                markStaticChecksFailed();
                logger.warn("Secret-pattern scan could not inspect a project path", {
                    code: error.code || error.name || "UNKNOWN"
                });
                continue;
            }

            if (stat.isSymbolicLink()) {
                markStaticChecksFailed();
                continue;
            }

            if (stat.isDirectory()) {

                scanFolder(full, depth + 1);

            } else {
                if (!stat.isFile()) {
                    markStaticChecksFailed();
                    continue;
                }
                if (!isSupportedTextFile(fileName)) {
                    if (BINARY_EXTENSIONS.has(path.extname(fileName.toLowerCase()))) {
                        binaryFileSkipped = true;
                        markStaticChecksIncomplete();
                    } else if (!IGNORED_NON_SOURCE_BASENAMES.has(fileName.toLowerCase())) {
                        unsupportedFileFormatFound = true;
                        markStaticChecksIncomplete();
                    }
                    continue;
                }
                if (stat.size > ANALYZER_LIMITS.maxFileBytes ||
                    scannedFileCount >= ANALYZER_LIMITS.maxFiles ||
                    stat.size > ANALYZER_LIMITS.maxTotalBytes - scannedBytes) {
                    stopStaticScan();
                    return;
                }

                try {

                    const content = readBoundedFile(
                        fileSystem,
                        full,
                        ANALYZER_LIMITS.maxFileBytes
                    );
                    const bytes = Buffer.byteLength(content);
                    if (bytes > ANALYZER_LIMITS.maxFileBytes ||
                        bytes > ANALYZER_LIMITS.maxTotalBytes - scannedBytes) {
                        stopStaticScan();
                        return;
                    }
                    scannedFileCount += 1;
                    scannedBytes += bytes;
                    inspectStaticContent(full, fileName, content);

                } catch (error) {
                    if (error.code === "ANALYZER_FILE_LIMIT") {
                        stopStaticScan();
                        return;
                    }
                    markStaticChecksFailed();
                    logger.warn("Secret-pattern scan could not read a project file", {
                        code: error.code || error.name || "UNKNOWN"
                    });
                }
            }
          }
        } catch (error) {
            markStaticChecksFailed();
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
            markStaticChecksFailed();
        } else {
            scanFolder(buildContext);
        }
    } catch (error) {
        markStaticChecksFailed();
        logger.warn("Static security checks could not inspect the project root", {
            code: error.code || error.name || "UNKNOWN"
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
        markCheck(
            "dependency_vulnerability_analysis",
            result.metadata.status === "partial"
                ? "incomplete"
                : result.status === "completed" ? "completed" : result.status
        );
        for (const finding of result.findings) {
            addIssue(
                finding.severity,
                `Dependency vulnerability: ${finding.dependency.package} (${finding.dependency.advisoryId})`,
                finding.summary,
                finding.fixedVersion
                    ? `Upgrade ${finding.dependency.package} to ${finding.fixedVersion} or later.`
                    : `Review advisory ${finding.dependency.advisoryId} and update ${finding.dependency.package} to a version confirmed as unaffected.`,
                "dependency_vulnerability_analysis"
            );
            report.issues[report.issues.length - 1].dependency = {
                ...finding.dependency,
                ...(finding.fixedVersion ? { fixedVersion: finding.fixedVersion } : {}),
                advisoryModified: finding.advisoryModified
            };
        }
    } catch (error) {
        markCheck("dependency_vulnerability_analysis", "failed");
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
            "project_structure"
        );
    }

    const readme = path.join(buildContext, "README.md");

    if (!fileSystem.existsSync(readme)) {

        addIssue(
            "Low",
            "README Missing",
            "Project documentation is missing.",
            "Add a README.md.",
            "project_structure"
        );
    }

    // Check lock file for Node projects
    const packageLock = path.join(buildContext, "package-lock.json");

    if (!fileSystem.existsSync(packageLock)) {

        addIssue(
            "Low",
            "Lock File Missing",
            "Dependencies are not locked.",
            "Commit package-lock.json.",
            "project_structure"
        );
    }

    //---------------------------------------------------
    // Final Status
    //---------------------------------------------------

    if (report.score >= 90)
        report.status = "Excellent";

    else if (report.score >= 75)
        report.status = "Good";

    else if (report.score >= 60)
        report.status = "Needs Improvement";

    else
        report.status = "Poor";

    // Remove duplicate recommendations
    report.recommendations = [...new Set(report.recommendations)];

    // Prevent score from going below 0
    report.score = Math.max(0, report.score);

    // Generate summary counts for frontend display
    report.summary = {
        critical: report.issues.filter(i => i.severity === "Critical").length,
        high: report.issues.filter(i => i.severity === "High").length,
        medium: report.issues.filter(i => i.severity === "Medium").length,
        low: report.issues.filter(i => i.severity === "Low").length,
        unknown: report.issues.filter(i => i.severity === "Unknown").length
    };

    const checksWithDetails = [...checks].map(([id, rawStatus]) => {
        const definition = checkDefinitions[id];
        const findingCount = report.issues.filter((issue) => issue.checkId === id).length;
        const status = rawStatus === "completed"
            ? findingCount > 0 ? "findings" : "passed"
            : rawStatus === "not_performed"
                ? "skipped"
                : rawStatus === "partial"
                    ? "incomplete"
                    : rawStatus;
        let explanation;
        if (status === "passed") explanation = "No issues found within the stated scope.";
        else if (status === "findings") explanation = `${findingCount} finding(s) reported within the stated scope.`;
        else if (status === "failed" && staticCheckIds.includes(id) && scanLimitExceeded) {
            explanation = `The bounded static scan reached a resource limit (entries/files: ${ANALYZER_LIMITS.maxFiles}, depth: ${ANALYZER_LIMITS.maxDepth}, file size: ${ANALYZER_LIMITS.maxFileBytes} bytes, total scanned: ${ANALYZER_LIMITS.maxTotalBytes} bytes); remaining coverage was not assessed.`;
        } else if (status === "failed" && id === "dangerous_application_configuration" && malformedJsonConfiguration) {
            explanation = "At least one supported JSON configuration file is malformed, so dangerous-configuration coverage is incomplete.";
        } else if (status === "incomplete" && staticCheckIds.includes(id) &&
            (unsupportedFileFormatFound || binaryFileSkipped)) {
            explanation = "One or more binary or unsupported file formats were skipped; coverage is limited to the supported UTF-8 source, configuration, and documentation types.";
        } else if (status === "failed" && staticCheckIds.includes(id) && staticScanIncomplete) {
            explanation = "One or more supported files could not be inspected (for example, unreadable input, a symlink, invalid UTF-8, or a non-regular file); coverage is incomplete.";
        } else if (status === "failed") explanation = "The check could not complete; treat its coverage as unavailable.";
        else if (id === "dependency_vulnerability_analysis" &&
            (status === "unsupported" || status === "incomplete")) {
            const formats = Array.isArray(dependencyAnalysis?.unsupportedFormats)
                ? dependencyAnalysis.unsupportedFormats.filter((format) => typeof format === "string")
                : [];
            if (dependencyAnalysis?.reason === "no_supported_dependency_manifest") {
                explanation = "No supported npm lockfile was found; other dependency ecosystems are not analyzed.";
            } else if (formats.length > 0) {
                explanation = `Only supported npm lockfiles are analyzed; these detected ecosystems were not covered: ${formats.join(", ")}.`;
            } else {
                explanation = "Dependency coverage is unavailable or incomplete; only supported npm lockfiles are analyzed.";
            }
        } else if (status === "unsupported") explanation = "This check is not implemented.";
        else if (status === "skipped") explanation = id === "runtime_inspection"
            ? "Runtime inspection was skipped because no container was available."
            : "This check was skipped because its required input was unavailable.";
        else explanation = "The check ran but could not assess its full intended scope.";
        return { id, name: definition.name, status, scope: definition.scope, explanation, findingCount };
    });
    const coverageComplete = checksWithDetails.every((check) =>
        check.status === "passed" || check.status === "findings"
    );
    report.scan = {
        status: coverageComplete ? "completed" : "partial",
        findingsDetected: report.issues.length > 0,
        findingCount: report.issues.length,
        assessment: report.issues.length > 0
            ? coverageComplete
                ? "Findings were reported by checks performed; this is not a complete security assessment."
                : "Findings were reported, but coverage is incomplete; this is not a complete security assessment."
            : coverageComplete
                ? "No findings in checks performed; this does not establish that the application is secure."
                : "No findings in checks performed, but coverage is incomplete; this does not establish that the application is secure.",
        checks: checksWithDetails
    };

    // Add timestamp
    report.generatedAt = (dependencies.now || (() => new Date()))().toISOString();

    return report;
}