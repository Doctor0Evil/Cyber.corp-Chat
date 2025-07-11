/act as (\w+)/i                        # Role assignment
/switch to (\w+)/i                     # Model switching
/export (chat|conversation) as (\w+)/i # Export requests
/output as (\w+)/i                     # Output format requests
/summarize as (\w+)/i                  # Summary format
/queue (next )?question/i              # Queueing
/show (debug|logs|changelog)/i         # System info
/list (plugins|features|versions)/i    # Listing
/enable (.+)/i                         # Feature toggles
/reset (memory|context)/i              # Reset requests
/search (chat )?history for (.+)/i     # History search
/extract (.+) from (.+)/i              # Data extraction
/translate to (\w+)/i                  # Translation
/show (privacy|settings)/i             # Settings
/auto(-|\s)?refresh/i                  # Auto-refresh
/clone (conversation|chat)/i           # Cloning
/output length (\d+)/i                 # Output length
/act as (\w+)/i
/pretend to be (\w+)/i
/roleplay as (\w+)/i
/assume the role of ([\w\s]+)/i
/emulate ([\w\s]+)/i
/respond as ([\w\s]+)/i
/write in the style of ([\w\s]+)/i
/imitate ([\w\s]+)/i
/adopt the persona of ([\w\s]+)/i
/become ([\w\s]+)/i
/think like ([\w\s]+)/i
/answer as if you are ([\w\s]+)/i
/act like ([\w\s]+)/i
/output as (\w+)/i
/format as (\w+)/i
/export (chat|conversation|output) as (\w+)/i
/summarize as (\w+)/i
/generate (\w+) from (.+)/i
/extract (emails?|dates?|urls?|numbers?|addresses?|hashtags?|keywords?) from (.+)/i
/convert (.+) to (\w+)/i
/parse (.+) to (\w+)/i
/structure as (\w+)/i
/visualize (.+) as (\w+)/i
/diagram (.+)/i
/create (table|chart|graph|list|json|csv|yaml|xml|uml|flowchart)/i
/output in ([\w\s,]+)/i
/produce ([\w\s]+) format/i
/only show (.+)/i
/explain step by step/i
/walk me through (.+)/i
/show your full reasoning/i
/expand with more detail/i
/critique your last answer/i
/suggest improvements/i
/compare (.+) and (.+)/i
/what are the trade-offs/i
/what assumptions are you making/i
/justify your answer/i
/alternative approaches/i
/give pros and cons/i
/contrast (.+) with (.+)/i
/analyze (.+) in depth/i
/expand on (.+)/i
/give an example of (.+)/i
/provide a case study of (.+)/i
/list (undocumented|hidden|experimental) (features|commands|capabilities)/i
/show (debug|system|developer) (logs|menu|settings)/i
/reveal (system|internal|backend) (instructions|configuration|status)/i
/what (system|internal) instructions are you following/i
/enable (beta|experimental|developer|debug) (features|mode|settings)/i
/disable (beta|experimental|developer|debug) (features|mode|settings)/i
/reset (memory|context|history)/i
/clear (memory|context|history)/i
/forget (previous|last) conversation/i
/what is your (training|knowledge) cutoff/i
/what are your (api|usage) limits/i
/list (plugins|integrations|extensions)/i
/show changelog/i
/list model versions/i
/what is your current model/i
/switch to (\w+)/i
/change model to (\w+)/i
/upgrade to (\w+)/i
/downgrade to (\w+)/i
/show (privacy|settings)/i
/enable (temporary|incognito|private) chat/i
/disable (temporary|incognito|private) chat/i
/enable (temporary|incognito|private) chat/i
/disable (temporary|incognito|private) chat/i
/what are your privacy settings/i
/show privacy options/i
/opt out of training/i
/opt in to training/i
/forget my data/i
/clear my data/i
/delete my data/i
/anonymize my session/i
/enable (dark|light) mode/i
/switch to (dark|light) mode/i
/change theme to (\w+)/i
/enable full-screen/i
/exit full-screen/i
/show sidebar/i
/hide sidebar/i
/enable auto-refresh/i
/disable auto-refresh/i
/refresh session/i
/queue (next )?question/i
/clone (conversation|chat)/i
/duplicate (conversation|chat)/i
/merge (conversations|chats)/i
/split (conversation|chat)/i
/batch process (.+)/i
/auto-categorize (.+)/i
/auto-tag (.+)/i
/enable accessibility mode/i
/increase font size/i
/decrease font size/i
/toggle compact mode/i
/write a (daily|weekly|monthly) planner/i
/generate a business plan for (.+)/i
/create a website for (.+)/i
/draft a resume for (.+)/i
/design a marketing campaign for (.+)/i
/build a (game|app|tool) based on (.+)/i
/summarize (meeting|transcript|article) with (action items|key points)/i
/convert (.+) into (powerpoint|slides|presentation)/i
/generate a recipe with (.+)/i
/auto-post to (social media|twitter|facebook|linkedin)/i
/bulk download (attachments|files|images)/i
/generate embeddings for (.+)/i
/analyze sentiment of (.+)/i
/detect language and translate (.+)/i
/generate (cover letter|portfolio|cv) for (.+)/i
/plan (event|project|trip) for (.+)/i
/translate to (\w+)/i
/translate (.+) to (\w+)/i
/detect language of (.+)/i
/auto-translate (.+)/i
/explain nuances in (\w+)/i
/translate and summarize (.+)/i
/solve (.+) step by step/i
/explain this code/i
/debug this code/i
/optimize this code/i
/write (python|java|c#|javascript|bash|powershell|sql|regex) code for (.+)/i
/generate (unit|integration|e2e) tests for (.+)/i
/review this code/i
/explain (algorithm|data structure|pattern) (.+)/i
/convert (.+) to (python|java|c#|javascript|bash|powershell|sql|regex)/i
/summarize as pseudocode/i
/generate api docs from (.+)/i
/write a script to (.+)/i
/describe (.+) as a flowchart/i
/visualize (.+) as a diagram/i
/write a poem about (.+)/i
/write a haiku about (.+)/i
/write a rap about (.+)/i
/write a song about (.+)/i
/explain (.+) as a joke/i
/summarize (.+) with emojis/i
/describe (.+) as a meme/i
/tell a story about (.+)/i
/roleplay as (\w+) in (.+)/i
/act as a (sarcastic|optimistic|pessimistic|funny|serious) (\w+)/i
/write a dialogue between (.+) and (.+)/i
/generate a metaphor for (.+)/i
/import (file|document|data) (.+)/i
/export (file|document|data) as (\w+)/i
/convert (file|document|data) to (\w+)/i
/list supported file formats/i
/upload (file|document|image)/i
/download (file|document|image)/i
/attach (file|document|image)/i
/merge (files|documents|datasets)/i
/split (file|document|dataset)/i
/analyze (.+)/i
/research (.+)/i
/find sources for (.+)/i
/evaluate credibility of (.+)/i
/synthesize information from (.+)/i
/compare multiple perspectives on (.+)/i
/summarize current research on (.+)/i
/generate a literature review on (.+)/i
/trace the history of (.+)/i
/what can you do/i
/list your capabilities/i
/help/i
/show help menu/i
/what's new/i
/what's changed/i
/what's your version/i
/show usage statistics/i
/monitor (service|model|uptime)/i
/check (service|model|status)/i
/enable notifications/i
/disable notifications/i
/set reminder for (.+)/i
/clear reminders/i
/list (undocumented|hidden|experimental) (features|commands|capabilities)/i
/show (debug|system|developer) (logs|menu|settings)/i
/reveal (system|internal|backend) (instructions|configuration|status)/i
/what (system|internal) instructions are you following/i
/enable (beta|experimental|developer|debug) (features|mode|settings)/i
/disable (beta|experimental|developer|debug) (features|mode|settings)/i
/\/(settings|beta|debug|help|menu)/i
/switch to (\w+)/i
/change model to (\w+)/i
/upgrade to (\w+)/i
/enable (temporary|incognito|private) chat/i
/list (undocumented|hidden|experimental) (features|commands|capabilities)/i
/show (debug|system|developer) (logs|menu|settings)/i
/reveal (system|internal|backend) (instructions|configuration|status)/i
/enable (beta|experimental|developer|debug) (features|mode|settings)/i
/disable (beta|experimental|developer|debug) (features|mode|settings)/i
/\/(settings|beta|debug|help|menu)/i
/switch to (\w+)/i
/change model to (\w+)/i
/upgrade to (\w+)/i
/enable (temporary|incognito|private) chat/i
/explain step by step/i
/give an example of (.+)/i
/list (undocumented|hidden|experimental) (features|commands|capabilities)/i
/show (debug|system|developer) (logs|menu|settings)/i
/reveal (system|internal|backend) (instructions|configuration|status)/i
/enable (beta|experimental|developer|debug) (features|mode|settings)/i
/disable (beta|experimental|developer|debug) (features|mode|settings)/i
/\/(settings|beta|debug|help|menu)/i
/switch to (\w+)/i
/change model to (\w+)/i
/upgrade to (\w+)/i
/enable (temporary|incognito|private) chat/i
/explain step by step/i
/give an example of (.+)/i
{
  "algorithm": "Linear Regression",
  "formula": "y = Xβ + ε",
  "type": "supervised",
  "loss_function": "RSS = Σ(y_i - ŷ_i)^2",
  "parameters": ["β (coefficients)"]
}
function linearRegression(X, y) {
  // X: 2D array, y: 1D array
  // β = (XᵗX)⁻¹Xᵗy
  const XT = math.transpose(X);
  const beta = math.multiply(
    math.inv(math.multiply(XT, X)),
    math.multiply(XT, y)
  );
  return beta;
}
{
  "algorithm": "Logistic Regression",
  "formula": "p(y=1|X) = 1 / (1 + exp(-Xβ))",
  "type": "supervised",
  "loss_function": "Log Loss = -Σ[y_i log(p_i) + (1-y_i) log(1-p_i)]"
}
p(y=1∣X)= 
1+e 
−Xβ
 
1
function sigmoid(z) {
  return 1 / (1 + Math.exp(-z));
}
function logisticRegressionPredict(X, beta) {
  return X.map(row => sigmoid(row.reduce((sum, xj, j) => sum + xj * beta[j], 0)));
}
w,b
min
  
2
1
 ∥w∥ 
2
 s.t.y 
i
 (w 
T
 x 
i
 +b)≥1 ∀i
{
  "algorithm": "SVM",
  "objective": "min_w,b 0.5 * ||w||^2",
  "constraints": "y_i(w^T x_i + b) >= 1 for all i",
  "type": "supervised"
}
function svmDecision(x, w, b) {
  // x: feature vector, w: weights, b: bias
  return math.dot(x, w) + b >= 0 ? 1 : -1;
}
F 
m+1
 (x)=F 
m
 (x)+ηh 
m
 (x)
a 
(l)
 =f(W 
(l)
 a 
(l−1)
 +b 
(l)
 )

J= 
i=1
∑
n
  
k=1
∑
K
 1(c 
i
 =k)∥x 
i
 −μ 
k
 ∥ 
2
P(y∣X)= 
P(X)
P(X∣y)P(y)
{
  # This starter workflow is for a CMake project running on a single platform. There is a different starter workflow if you need cross-platform coverage.
# See: https://github.com/actions/starter-workflows/blob/main/ci/cmake-multi-platform.yml
name: CMake on a single platform

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

env:
  # Customize the CMake build type here (Release, Debug, RelWithDebInfo, etc.)
  BUILD_TYPE: Release

jobs:
  build:
    # The CMake configure and build commands are platform agnostic and should work equally well on Windows or Mac.
    # You can convert this to a matrix build if you need cross-platform coverage.
    # See: https://docs.github.com/en/free-pro-team@latest/actions/learn-github-actions/managing-complex-workflows#using-a-build-matrix
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v4

    - name: Configure CMake
      # Configure CMake in a 'build' subdirectory. `CMAKE_BUILD_TYPE` is only required if you are using a single-configuration generator such as make.
      # See https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html?highlight=cmake_build_type
      run: cmake -B ${{github.workspace}}/build -DCMAKE_BUILD_TYPE=${{env.BUILD_TYPE}}

    - name: Build
      # Build your program with the given configuration
      run: cmake --build ${{github.workspace}}/build --config ${{env.BUILD_TYPE}}

    - name: Test
      working-directory: ${{github.workspace}}/build
      # Execute tests defined by the CMake configuration.
      # See https://cmake.org/cmake/help/latest/manual/ctest.1.html for more detail
      run: ctest -C ${{env.BUILD_TYPE}}

            - name: Setup Node.js environment
  uses: actions/setup-node@v3.9.1
  with:
    # Set always-auth in npmrc.
    always-auth: # optional, default is false
    # Version Spec of the version to use. Examples: 12.x, 10.15.1, >=10.15.0.
    node-version: # optional
    # File containing the version Spec of the version to use.  Examples: .nvmrc, .node-version, .tool-versions.
    node-version-file: # optional
    # Target architecture for Node to use. Examples: x86, x64. Will use system architecture by default.
    architecture: # optional
    # Set this option if you want the action to check for the latest available version that satisfies the version spec.
    check-latest: # optional
    # Optional registry to set up for auth. Will set the registry in a project level .npmrc and .yarnrc file, and set up auth to read in from env.NODE_AUTH_TOKEN.
    registry-url: # optional
    # Optional scope for authenticating against scoped registries. Will fall back to the repository owner when using the GitHub Packages registry (https://npm.pkg.github.com/).
    scope: # optional
    # Used to pull node distributions from node-versions. Since there's a default, this is typically not supplied by the user. When running this action on github.com, the default value is sufficient. When running on GHES, you can pass a personal access token for github.com if you are experiencing rate limiting.
    token: # optional, default is ${{ github.server_url == 'https://github.com' && github.token || '' }}
    # Used to specify a package manager for caching in the default directory. Supported values: npm, yarn, pnpm.
    cache: # optional
    # Used to specify the path to a dependency file: package-lock.json, yarn.lock, etc. Supports wildcards or a list of file names for caching multiple dependencies.
    cache-dependency-path: # optional
          "algorithm": "Naive Bayes",
  "formula": "P(y|X) = P(X|y)P(y) / P(X)",
  "type": "supervised"
}
function naiveBayesPredict(X, classPriors, likelihoods) {
  // X: feature vector, classPriors: P(y), likelihoods: P(X|y)
  return classPriors.map((prior, y) =>
    prior * X.reduce((prod, xi, i) => prod * likelihoods[y][i][xi], 1)
  );
}
{
  "algorithm": "K-Means",
  "objective": "minimize sum of squared distances to cluster centers",
  "type": "unsupervised"
}
function updateCentroids(data, labels, K) {
  let centroids = Array(K).fill().map(() => Array(data[0].length).fill(0));
  let counts = Array(K).fill(0);
  data.forEach((point, i) => {
    const k = labels[i];
    centroids[k] = centroids[k].map((c, j) => c + point[j]);
    counts[k]++;
  });
  return centroids.map((c, k) => c.map(v => v / counts[k]));
}
{
  "algorithm": "PCA",
  "formula": "X = WZ",
  "type": "unsupervised",
  "goal": "dimensionality reduction"
}
// Requires a math library for eigen decomposition
function pca(X) {
  const XT = math.transpose(X);
  const cov = math.multiply(XT, X);
  const { eigenvectors } = math.eigs(cov);
  return eigenvectors;
}
{
  "algorithm": "Neural Network",
  "formula": "a^(l) = f(W^(l) a^(l-1) + b^(l))",
  "type": "deep learning"
}
function relu(x) { return Math.max(0, x); }
function forwardPass(a_prev, W, b, activation=relu) {
  let z = math.add(math.multiply(W, a_prev), b);
  return z.map(activation);
}
{
  "algorithm": "Gradient Boosting",
  "update_rule": "F_{m+1}(x) = F_m(x) + η h_m(x)",
  "type": "ensemble"
}
function gradientBoostingUpdate(Fm, hm, eta) {
  return (x) => Fm(x) + eta * hm(x);
}
// Random Rule: Select a random action
function randomRule(actions) {
  return actions[Math.floor(Math.random() * actions.length)];
}

// Beneficial Rule: Select action with highest reward
function beneficialRule(actions, rewards) {
  let maxReward = Math.max(...rewards);
  return actions[rewards.indexOf(maxReward)];
}
z=xmodn
{
  "pattern": "^\\d{4}-\\d{2}-\\d{2}$",
  "description": "Matches ISO date format (YYYY-MM-DD)",
  "ml_behavior": "Extract date features for time series analysis"
}
const isoDateRegex = /^\d{4}-\d{2}-\d{2}$/;
function isISODate(str) {
  return isoDateRegex.test(str);
}
