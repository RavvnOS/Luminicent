const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

const router = express.Router();
router.use((_req, res) => {
  res.status(410).json({ error: 'Legacy GitHub deployment route is disabled' });
});

// Helper to make GET requests to GitHub API
function getGithubJson(url, token) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'DevOps-Deployment-Simulator',
        'X-GitHub-Api-Version': '2022-11-28'
      }
    };
    if (token) {
      options.headers['Authorization'] = `Bearer ${token}`;
    }

    const req = https.request(options, (res) => {
      let responseBody = '';
      res.on('data', (chunk) => {
        responseBody += chunk;
      });
      res.on('end', () => {
        try {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(JSON.parse(responseBody));
          } else {
            let errorMsg = `GitHub API error: ${res.statusCode}`;
            try {
              const errObj = JSON.parse(responseBody);
              errorMsg = errObj.message || errorMsg;
            } catch (e) {}
            reject(new Error(errorMsg));
          }
        } catch (e) {
          reject(new Error(`Failed to parse response: ${responseBody.substring(0, 100)}`));
        }
      });
    });

    req.on('error', (err) => reject(err));
    req.end();
  });
}

// Helper to download the zipball (follows redirects)
function downloadZipball(url, destPath, token) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': 'DevOps-Deployment-Simulator',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
      }
    };
    if (token) {
      options.headers['Authorization'] = `Bearer ${token}`;
    }

    const req = https.request(options, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        // Follow redirect
        downloadZipball(res.headers.location, destPath, token)
          .then(resolve)
          .catch(reject);
        return;
      }

      if (res.statusCode !== 200) {
        let responseBody = '';
        res.on('data', (chunk) => { responseBody += chunk; });
        res.on('end', () => {
          let errorMsg = `GitHub Download error: ${res.statusCode}`;
          try {
            const errObj = JSON.parse(responseBody);
            errorMsg = errObj.message || errorMsg;
          } catch (e) {}
          reject(new Error(errorMsg));
        });
        return;
      }

      const fileStream = fs.createWriteStream(destPath);
      res.pipe(fileStream);

      fileStream.on('finish', () => {
        fileStream.close();
        resolve(destPath);
      });

      fileStream.on('error', (err) => {
        fs.unlink(destPath, () => {});
        reject(err);
      });
    });

    req.on('error', (err) => {
      fs.unlink(destPath, () => {});
      reject(err);
    });

    req.end();
  });
}

// Helper to perform POST JSON requests (used for OAuth token exchange)
function postJson(url, data) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const postData = JSON.stringify(data);
    
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'User-Agent': 'DevOps-Deployment-Simulator'
      }
    };

    const req = https.request(options, (res) => {
      let responseBody = '';
      res.on('data', (chunk) => {
        responseBody += chunk;
      });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(responseBody);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            reject(new Error(parsed.error_description || parsed.error || `HTTP ${res.statusCode}`));
          }
        } catch (e) {
          reject(new Error(`Failed to parse response: ${responseBody}`));
        }
      });
    });

    req.on('error', (err) => reject(err));
    req.write(postData);
    req.end();
  });
}

// Helper to cleanup directories
const cleanupPath = (targetPath) => {
  if (!targetPath) return;
  try {
    if (fs.existsSync(targetPath)) {
      fs.rmSync(targetPath, { recursive: true, force: true });
    }
  } catch (cleanupError) {
    console.error(`Cleanup error for ${targetPath}:`, cleanupError);
  }
};

// Route: Redirect to GitHub authorize page
router.get('/login', (req, res) => {
  const clientId = process.env.GITHUB_CLIENT_ID;
  
  if (!clientId || clientId === 'your_github_client_id_here') {
    return res.status(501).json({
      error: 'OAuth not configured',
      message: 'GitHub OAuth Client ID is not configured on the server. Please connect using a Personal Access Token (PAT) instead.'
    });
  }

  let githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&scope=repo,user`;
  if (req.query.redirect_uri) {
    githubAuthUrl += `&redirect_uri=${encodeURIComponent(req.query.redirect_uri)}`;
  } else if (process.env.STRICT_REDIRECT_URI === 'true' && process.env.GITHUB_REDIRECT_URI) {
    githubAuthUrl += `&redirect_uri=${encodeURIComponent(process.env.GITHUB_REDIRECT_URI)}`;
  }
  res.redirect(githubAuthUrl);
});

// Route: Handle GitHub redirect callback
router.get('/callback', async (req, res) => {
  const { code } = req.query;
  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;
  const redirectUri = process.env.GITHUB_REDIRECT_URI;
  const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';

  if (!code) {
    return res.status(400).json({ error: 'Authorization code is required' });
  }

  try {
    let tokenResponse = await postJson('https://github.com/login/oauth/access_token', {
      client_id: clientId,
      client_secret: clientSecret,
      code
    });

    if (tokenResponse.error && redirectUri) {
      tokenResponse = await postJson('https://github.com/login/oauth/access_token', {
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri
      });
    }

    if (tokenResponse.error) {
      throw new Error(tokenResponse.error_description || tokenResponse.error);
    }

    const token = tokenResponse.access_token;
    if (req.headers.accept?.includes('application/json')) {
      return res.json({ success: true, token });
    }
    res.redirect(`${frontendUrl}?github_token=${token}`);
  } catch (error) {
    console.error('OAuth Callback Error:', error);
    if (req.headers.accept?.includes('application/json')) {
      return res.status(500).json({ error: error.message });
    }
    res.redirect(`${frontendUrl}?github_error=${encodeURIComponent(error.message)}`);
  }
});

// Route: Fetch current user profile
router.get('/user', async (req, res) => {
  const token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null;
  if (!token) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  try {
    const userData = await getGithubJson('https://api.github.com/user', token);
    res.json(userData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Route: List repositories
router.get('/repos', async (req, res) => {
  const token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null;
  if (!token) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  try {
    const repos = await getGithubJson('https://api.github.com/user/repos?per_page=100&sort=updated', token);
    res.json(repos);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Route: List branches of a repo
router.get('/branches', async (req, res) => {
  const token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null;
  const { owner, repo } = req.query;

  if (!owner || !repo) {
    return res.status(400).json({ error: 'owner and repo parameters are required' });
  }

  if (!token) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  try {
    const branches = await getGithubJson(`https://api.github.com/repos/${owner}/${repo}/branches`, token);
    res.json(branches);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Route: Download repo zipball, extract, build and run container simulation
router.post('/deploy', async (req, res) => {
  const { owner, repo, branch, token } = req.body;
  if (!owner || !repo || !branch) {
    return res.status(400).json({ error: 'owner, repo, and branch are required' });
  }

  const sessionId = req.body.sessionId || Date.now().toString();
  const zipPath = path.join('uploads', `${sessionId}.zip`);
  const extractPath = path.join('uploads', sessionId);
  const dockerOrchestrator = req.orchestrator;

  try {
    fs.mkdirSync(path.dirname(zipPath), { recursive: true });

    dockerOrchestrator.emitStatus(sessionId, {
      status: 'DOWNLOADING',
      stage: 'upload',
      type: 'info',
      percent: 5,
      message: `Downloading repository archive ${owner}/${repo} (branch: ${branch})...`
    });

    const zipballUrl = `https://api.github.com/repos/${owner}/${repo}/zipball/${branch}`;
    await downloadZipball(zipballUrl, zipPath, token);

    dockerOrchestrator.emitStatus(sessionId, {
      status: 'EXTRACTING',
      stage: 'extract',
      type: 'info',
      percent: 15,
      message: 'Extracting repository package...'
    });

    fs.mkdirSync(extractPath, { recursive: true });
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractPath, true);

    // GitHub zipball extracts to a nested wrapper folder (e.g. owner-repo-commit_sha)
    // Look inside the extractPath. If there is a single directory, make it our buildContext
    const repoRoot = normalizeRepoRoot(extractPath);
    const buildContext = findBuildContext(repoRoot);
    console.log('GitHub deploy repoRoot:', repoRoot);
    console.log('GitHub deploy buildContext:', buildContext);
    console.log('GitHub build context files:', fs.readdirSync(buildContext));

    const dockerfilePath = ensureDockerfile(buildContext);

    dockerOrchestrator.emitStatus(sessionId, {
      status: 'EXTRACTED',
      stage: 'extract',
      type: 'success',
      percent: 25,
      message: `Repository downloaded and extracted successfully and Dockerfile ready at ${path.relative(buildContext, dockerfilePath)}`
    });

    const imageName = `devops-sim-${sessionId}`;
    await dockerOrchestrator.buildImage(buildContext, imageName, sessionId, dockerfilePath);

    const container = await dockerOrchestrator.runContainer(imageName, sessionId);
    await dockerOrchestrator.streamLogs(container, sessionId);

    res.json({
      success: true,
      sessionId,
      message: 'Simulation started'
    });

    // Auto cleanup after 60 seconds (like standard zip simulation)
    setTimeout(async () => {
      await dockerOrchestrator.cleanup(sessionId);
      cleanupPath(extractPath);
    }, 60000);

  } catch (error) {
    console.error('GitHub deployment error:', error);
    dockerOrchestrator.emitStatus(sessionId, {
      status: 'ERROR',
      stage: 'error',
      type: 'error',
      message: error.message,
      error: error.message
    });
    cleanupPath(extractPath);
    res.status(500).json({ error: error.message });
  } finally {
    cleanupPath(zipPath);
  }
});

module.exports = router;
