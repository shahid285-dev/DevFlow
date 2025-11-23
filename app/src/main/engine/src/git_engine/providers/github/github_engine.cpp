#include "github_engine.hpp"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

using json = nlohmann::json;

GitHubExtension::GitHubExtension(const GitHubConfig& config) : config_(config) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

GitHubExtension::~GitHubExtension() {
    curl_global_cleanup();
}

void GitHubExtension::set_config(const GitHubConfig& config) {
    std::lock_guard<std::mutex> lock(api_mutex_);
    config_ = config;
}

GitHubExtension::GitHubConfig GitHubExtension::get_config() const {
    return config_;
}

bool GitHubExtension::authenticate() {
    try {
        auto response = api_get("/user");
        return response.contains("login");
    } catch (const std::exception&) {
        return false;
    }
}

GitHubExtension::RateLimitInfo GitHubExtension::get_rate_limit() {
    auto response = api_get("/rate_limit");
    RateLimitInfo info;
    
    if (response.contains("resources")) {
        auto core = response["resources"]["core"];
        info.limit = core["limit"];
        info.remaining = core["remaining"];
        info.reset_time = core["reset"];
    }
    
    return info;
}

bool GitHubExtension::is_rate_limited() {
    auto limits = get_rate_limit();
    return limits.remaining <= 0;
}

GitHubExtension::GitHubUser GitHubExtension::get_current_user() {
    auto response = api_get("/user");
    return user_from_json(response);
}

GitHubExtension::GitHubUser GitHubExtension::get_user(const std::string& username) {
    auto response = api_get("/users/" + username);
    return user_from_json(response);
}

std::vector<GitHubExtension::GitHubUser> GitHubExtension::list_followers(const std::string& username) {
    std::string endpoint = username.empty() ? "/user/followers" : "/users/" + username + "/followers";
    auto response = api_get(endpoint);
    
    std::vector<GitHubUser> followers;
    for (const auto& item : response) {
        followers.push_back(user_from_json(item));
    }
    return followers;
}

std::vector<GitHubExtension::GitHubUser> GitHubExtension::list_following(const std::string& username) {
    std::string endpoint = username.empty() ? "/user/following" : "/users/" + username + "/following";
    auto response = api_get(endpoint);
    
    std::vector<GitHubUser> following;
    for (const auto& item : response) {
        following.push_back(user_from_json(item));
    }
    return following;
}

std::vector<GitHubExtension::GitHubRepository> GitHubExtension::list_user_repositories(const std::string& username) {
    std::string endpoint = username.empty() ? "/user/repos" : "/users/" + username + "/repos";
    auto response = api_get(endpoint);
    
    std::vector<GitHubRepository> repos;
    for (const auto& item : response) {
        repos.push_back(repository_from_json(item));
    }
    return repos;
}

GitHubExtension::GitHubRepository GitHubExtension::create_repository(const std::string& name, const std::string& description, bool is_private, bool is_template) {
    json data = {
        {"name", name},
        {"description", description},
        {"private", is_private},
        {"is_template", is_template},
        {"auto_init", true}
    };
    
    auto response = api_post("/user/repos", data);
    return repository_from_json(response);
}

GitHubExtension::GitHubRepository GitHubExtension::get_repository(const std::string& owner, const std::string& repo) {
    auto response = api_get("/repos/" + owner + "/" + repo);
    return repository_from_json(response);
}

std::vector<GitHubExtension::GitHubRepository> GitHubExtension::list_organization_repositories(const std::string& org) {
    auto response = api_get("/orgs/" + org + "/repos");
    
    std::vector<GitHubRepository> repos;
    for (const auto& item : response) {
        repos.push_back(repository_from_json(item));
    }
    return repos;
}

bool GitHubExtension::delete_repository(const std::string& owner, const std::string& repo) {
    try {
        api_delete("/repos/" + owner + "/" + repo);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

GitHubExtension::GitHubRepository GitHubExtension::fork_repository(const std::string& owner, const std::string& repo, const std::string& organization) {
    json data;
    if (!organization.empty()) {
        data["organization"] = organization;
    }
    
    auto response = api_post("/repos/" + owner + "/" + repo + "/forks", data);
    return repository_from_json(response);
}

void GitHubExtension::clone_github_repository(const std::string& owner, const std::string& repo, const std::string& local_path, const std::function<bool(size_t, size_t)>& progress_callback) {
    auto repository = get_repository(owner, repo);
    clone_repository(repository.clone_url, local_path, progress_callback);
}

void GitHubExtension::sync_fork(const std::string& upstream_owner, const std::string& upstream_repo) {
    auto current_repo = get_repository(config_.username, upstream_repo);
    
    if (!current_repo.is_fork) {
        throw std::runtime_error("Repository is not a fork");
    }
    
    fetch("upstream");
    
    auto upstream_branch = get_repository(upstream_owner, upstream_repo).default_branch;
    auto current_branch = get_current_branch();
    
    checkout_branch(upstream_branch);
    pull("upstream", upstream_branch);
    checkout_branch(current_branch);
    
    merge(upstream_branch);
}

void GitHubExtension::set_branch_protection(const std::string& owner, const std::string& repo, const std::string& branch, const BranchProtectionRule& rule) {
    json data = {
        {"required_status_checks", {
            {"strict", rule.require_branches_up_to_date},
            {"contexts", rule.required_status_checks}
        }},
        {"enforce_admins", rule.enforce_admins},
        {"required_pull_request_reviews", {
            {"required_approving_review_count", rule.required_approving_review_count},
            {"require_code_owner_reviews", rule.require_code_owner_reviews},
            {"dismiss_stale_reviews", true},
            {"require_last_push_approval", false}
        }},
        {"restrictions", nullptr},
        {"required_linear_history", rule.require_linear_history},
        {"allow_force_pushes", rule.allow_force_pushes},
        {"allow_deletions", rule.allow_deletions}
    };
    
    if (!rule.restrictions.empty()) {
        data["restrictions"] = {{"users", json::array()}, {"teams", json::array()}};
    }
    
    api_put("/repos/" + owner + "/" + repo + "/branches/" + branch + "/protection", data);
}

GitHubExtension::BranchProtectionRule GitHubExtension::get_branch_protection(const std::string& owner, const std::string& repo, const std::string& branch) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/branches/" + branch + "/protection");
    
    BranchProtectionRule rule;
    rule.require_linear_history = response.value("required_linear_history", false);
    rule.allow_force_pushes = response.value("allow_force_pushes", false);
    rule.allow_deletions = response.value("allow_deletions", false);
    rule.enforce_admins = response.value("enforce_admins", false);
    
    if (response.contains("required_pull_request_reviews")) {
        auto reviews = response["required_pull_request_reviews"];
        rule.require_pull_request_reviews = true;
        rule.required_approving_review_count = reviews.value("required_approving_review_count", 1);
        rule.require_code_owner_reviews = reviews.value("require_code_owner_reviews", false);
    }
    
    if (response.contains("required_status_checks")) {
        auto checks = response["required_status_checks"];
        rule.require_branches_up_to_date = checks.value("strict", false);
        rule.required_status_checks = checks["contexts"].get<std::vector<std::string>>();
    }
    
    return rule;
}

void GitHubExtension::delete_branch_protection(const std::string& owner, const std::string& repo, const std::string& branch) {
    api_delete("/repos/" + owner + "/" + repo + "/branches/" + branch + "/protection");
}

GitHubExtension::GitHubIssue GitHubExtension::create_issue(const std::string& owner, const std::string& repo, const std::string& title, const std::string& body, const std::vector<std::string>& assignees, const std::vector<std::string>& labels) {
    json data = {
        {"title", title},
        {"body", body},
        {"assignees", assignees},
        {"labels", labels}
    };
    
    auto response = api_post("/repos/" + owner + "/" + repo + "/issues", data);
    return issue_from_json(response);
}

GitHubExtension::GitHubIssue GitHubExtension::get_issue(const std::string& owner, const std::string& repo, int issue_number) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/issues/" + std::to_string(issue_number));
    return issue_from_json(response);
}

std::vector<GitHubExtension::GitHubIssue> GitHubExtension::list_issues(const std::string& owner, const std::string& repo, const std::string& state, const std::string& assignee, const std::vector<std::string>& labels) {
    std::string endpoint = "/repos/" + owner + "/" + repo + "/issues?state=" + state;
    
    if (!assignee.empty()) {
        endpoint += "&assignee=" + assignee;
    }
    
    if (!labels.empty()) {
        for (const auto& label : labels) {
            endpoint += "&labels=" + label;
        }
    }
    
    auto response = api_get(endpoint);
    
    std::vector<GitHubIssue> issues;
    for (const auto& item : response) {
        issues.push_back(issue_from_json(item));
    }
    return issues;
}

GitHubExtension::GitHubIssue GitHubExtension::update_issue(const std::string& owner, const std::string& repo, int issue_number, const std::string& title, const std::string& body, const std::string& state, const std::vector<std::string>& assignees, const std::vector<std::string>& labels) {
    json data;
    
    if (!title.empty()) data["title"] = title;
    if (!body.empty()) data["body"] = body;
    if (!state.empty()) data["state"] = state;
    if (!assignees.empty()) data["assignees"] = assignees;
    if (!labels.empty()) data["labels"] = labels;
    
    auto response = api_patch("/repos/" + owner + "/" + repo + "/issues/" + std::to_string(issue_number), data);
    return issue_from_json(response);
}

bool GitHubExtension::close_issue(const std::string& owner, const std::string& repo, int issue_number) {
    try {
        update_issue(owner, repo, issue_number, "", "", "closed");
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

GitHubExtension::GitHubPullRequest GitHubExtension::create_pull_request(const std::string& owner, const std::string& repo, const std::string& title, const std::string& head_branch, const std::string& base_branch, const std::string& body, bool is_draft) {
    json data = {
        {"title", title},
        {"head", head_branch},
        {"base", base_branch},
        {"body", body},
        {"draft", is_draft}
    };
    
    auto response = api_post("/repos/" + owner + "/" + repo + "/pulls", data);
    return pull_request_from_json(response);
}

GitHubExtension::GitHubPullRequest GitHubExtension::get_pull_request(const std::string& owner, const std::string& repo, int pr_number) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(pr_number));
    return pull_request_from_json(response);
}

std::vector<GitHubExtension::GitHubPullRequest> GitHubExtension::list_pull_requests(const std::string& owner, const std::string& repo, const std::string& state, const std::string& head_branch, const std::string& base_branch) {
    std::string endpoint = "/repos/" + owner + "/" + repo + "/pulls?state=" + state;
    
    if (!head_branch.empty()) {
        endpoint += "&head=" + head_branch;
    }
    
    if (!base_branch.empty()) {
        endpoint += "&base=" + base_branch;
    }
    
    auto response = api_get(endpoint);
    
    std::vector<GitHubPullRequest> prs;
    for (const auto& item : response) {
        prs.push_back(pull_request_from_json(item));
    }
    return prs;
}

GitHubExtension::GitHubPullRequest GitHubExtension::update_pull_request(const std::string& owner, const std::string& repo, int pr_number, const std::string& title, const std::string& body, const std::string& state, const std::string& base_branch) {
    json data;
    
    if (!title.empty()) data["title"] = title;
    if (!body.empty()) data["body"] = body;
    if (!state.empty()) data["state"] = state;
    if (!base_branch.empty()) data["base"] = base_branch;
    
    auto response = api_patch("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(pr_number), data);
    return pull_request_from_json(response);
}

bool GitHubExtension::merge_pull_request(const std::string& owner, const std::string& repo, int pr_number, const std::string& commit_title, const std::string& commit_message, const std::string& merge_method) {
    json data = {
        {"merge_method", merge_method}
    };
    
    if (!commit_title.empty()) data["commit_title"] = commit_title;
    if (!commit_message.empty()) data["commit_message"] = commit_message;
    
    try {
        api_put("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(pr_number) + "/merge", data);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

GitHubExtension::Review GitHubExtension::create_review(const std::string& owner, const std::string& repo, int pr_number, const std::string& body, const std::string& event, const std::vector<std::string>& comments) {
    json data = {
        {"body", body},
        {"event", event}
    };
    
    if (!comments.empty()) {
        data["comments"] = json::array();
    }
    
    auto response = api_post("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(pr_number) + "/reviews", data);
    
    Review review;
    review.id = response["id"];
    review.body = response.value("body", "");
    review.state = response["state"];
    review.submitted_at = response["submitted_at"];
    review.commit_id = response["commit_id"];
    review.user = user_from_json(response["user"]);
    
    return review;
}

std::vector<GitHubExtension::Review> GitHubExtension::list_reviews(const std::string& owner, const std::string& repo, int pr_number) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(pr_number) + "/reviews");
    
    std::vector<Review> reviews;
    for (const auto& item : response) {
        Review review;
        review.id = item["id"];
        review.body = item.value("body", "");
        review.state = item["state"];
        review.submitted_at = item["submitted_at"];
        review.commit_id = item["commit_id"];
        review.user = user_from_json(item["user"]);
        reviews.push_back(review);
    }
    return reviews;
}

void GitHubExtension::dismiss_review(const std::string& owner, const std::string& repo, int pr_number, int64_t review_id, const std::string& message) {
    json data = {
        {"message", message}
    };
    
    api_put("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(pr_number) + "/reviews/" + std::to_string(review_id) + "/dismissals", data);
}

GitHubExtension::GitHubRelease GitHubExtension::create_release(const std::string& owner, const std::string& repo, const std::string& tag_name, const std::string& name, const std::string& body, bool is_draft, bool is_prerelease, const std::string& target_commitish) {
    json data = {
        {"tag_name", tag_name},
        {"name", name},
        {"body", body},
        {"draft", is_draft},
        {"prerelease", is_prerelease}
    };
    
    if (!target_commitish.empty()) {
        data["target_commitish"] = target_commitish;
    }
    
    auto response = api_post("/repos/" + owner + "/" + repo + "/releases", data);
    return release_from_json(response);
}

std::vector<GitHubExtension::GitHubRelease> GitHubExtension::list_releases(const std::string& owner, const std::string& repo) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/releases");
    
    std::vector<GitHubRelease> releases;
    for (const auto& item : response) {
        releases.push_back(release_from_json(item));
    }
    return releases;
}

GitHubExtension::GitHubRelease GitHubExtension::get_release_by_tag(const std::string& owner, const std::string& repo, const std::string& tag_name) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/releases/tags/" + tag_name);
    return release_from_json(response);
}

bool GitHubExtension::delete_release(const std::string& owner, const std::string& repo, int64_t release_id) {
    try {
        api_delete("/repos/" + owner + "/" + repo + "/releases/" + std::to_string(release_id));
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<GitHubExtension::GitHubWorkflow> GitHubExtension::list_workflows(const std::string& owner, const std::string& repo) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/actions/workflows");
    
    std::vector<GitHubWorkflow> workflows;
    for (const auto& item : response["workflows"]) {
        GitHubWorkflow workflow;
        workflow.id = item["id"];
        workflow.name = item["name"];
        workflow.path = item["path"];
        workflow.state = item["state"];
        workflow.created_at = item["created_at"];
        workflow.updated_at = item["updated_at"];
        workflow.html_url = item["html_url"];
        workflow.badge_url = item.value("badge_url", "");
        workflows.push_back(workflow);
    }
    return workflows;
}

std::vector<GitHubExtension::WorkflowRun> GitHubExtension::list_workflow_runs(const std::string& owner, const std::string& repo, int64_t workflow_id, const std::string& branch) {
    std::string endpoint = "/repos/" + owner + "/" + repo + "/actions/runs";
    
    if (workflow_id > 0) {
        endpoint = "/repos/" + owner + "/" + repo + "/actions/workflows/" + std::to_string(workflow_id) + "/runs";
    }
    
    if (!branch.empty()) {
        endpoint += "?branch=" + branch;
    }
    
    auto response = api_get(endpoint);
    
    std::vector<WorkflowRun> runs;
    for (const auto& item : response["workflow_runs"]) {
        WorkflowRun run;
        run.id = item["id"];
        run.name = item["name"];
        run.head_branch = item["head_branch"];
        run.head_sha = item["head_sha"];
        run.run_number = std::to_string(item["run_number"].get<int>());
        run.event = item["event"];
        run.status = item["status"];
        run.conclusion = item.value("conclusion", "");
        run.workflow_id = item["workflow_id"];
        run.created_at = item["created_at"];
        run.updated_at = item["updated_at"];
        runs.push_back(run);
    }
    return runs;
}

GitHubExtension::WorkflowRun GitHubExtension::get_workflow_run(const std::string& owner, const std::string& repo, int64_t run_id) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/actions/runs/" + std::to_string(run_id));
    
    WorkflowRun run;
    run.id = response["id"];
    run.name = response["name"];
    run.head_branch = response["head_branch"];
    run.head_sha = response["head_sha"];
    run.run_number = std::to_string(response["run_number"].get<int>());
    run.event = response["event"];
    run.status = response["status"];
    run.conclusion = response.value("conclusion", "");
    run.workflow_id = response["workflow_id"];
    run.created_at = response["created_at"];
    run.updated_at = response["updated_at"];
    
    return run;
}

bool GitHubExtension::rerun_workflow(const std::string& owner, const std::string& repo, int64_t run_id) {
    try {
        api_post("/repos/" + owner + "/" + repo + "/actions/runs/" + std::to_string(run_id) + "/rerun", json::object());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool GitHubExtension::cancel_workflow(const std::string& owner, const std::string& repo, int64_t run_id) {
    try {
        api_post("/repos/" + owner + "/" + repo + "/actions/runs/" + std::to_string(run_id) + "/cancel", json::object());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::string GitHubExtension::download_workflow_logs(const std::string& owner, const std::string& repo, int64_t run_id) {
    return make_request("GET", get_api_url("/repos/" + owner + "/" + repo + "/actions/runs/" + std::to_string(run_id) + "/logs"));
}

std::vector<GitHubExtension::GitHubActionSecret> GitHubExtension::list_secrets(const std::string& owner, const std::string& repo) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/actions/secrets");
    
    std::vector<GitHubActionSecret> secrets;
    for (const auto& item : response["secrets"]) {
        GitHubActionSecret secret;
        secret.name = item["name"];
        secret.created_at = item["created_at"];
        secret.updated_at = item["updated_at"];
        secrets.push_back(secret);
    }
    return secrets;
}

void GitHubExtension::create_or_update_secret(const std::string& owner, const std::string& repo, const std::string& secret_name, const std::string& encrypted_value) {
    json data = {
        {"encrypted_value", encrypted_value},
        {"key_id", "unused"} 
    };
    
    api_put("/repos/" + owner + "/" + repo + "/actions/secrets/" + secret_name, data);
}

bool GitHubExtension::delete_secret(const std::string& owner, const std::string& repo, const std::string& secret_name) {
    try {
        api_delete("/repos/" + owner + "/" + repo + "/actions/secrets/" + secret_name);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<GitHubExtension::GitHubCodespace> GitHubExtension::list_codespaces(const std::string& owner, const std::string& repo) {
    std::string endpoint = "/user/codespaces";
    
    if (!owner.empty() && !repo.empty()) {
        endpoint = "/repos/" + owner + "/" + repo + "/codespaces";
    } else if (!owner.empty()) {
        endpoint = "/orgs/" + owner + "/codespaces";
    }
    
    auto response = api_get(endpoint);
    
    std::vector<GitHubCodespace> codespaces;
    for (const auto& item : response["codespaces"]) {
        codespaces.push_back(codespace_from_json(item));
    }
    return codespaces;
}

GitHubExtension::GitHubCodespace GitHubExtension::get_codespace(const std::string& codespace_name) {
    auto response = api_get("/user/codespaces/" + codespace_name);
    return codespace_from_json(response);
}

GitHubExtension::GitHubCodespace GitHubExtension::create_codespace(const std::string& owner, const std::string& repo, const std::string& branch, const std::string& location, const std::string& machine_type) {
    json data = {
        {"repository_id", get_repository(owner, repo).id}
    };
    
    if (!branch.empty()) data["ref"] = branch;
    if (!location.empty()) data["location"] = location;
    if (!machine_type.empty()) data["machine"] = machine_type;
    
    auto response = api_post("/user/codespaces", data);
    return codespace_from_json(response);
}

bool GitHubExtension::delete_codespace(const std::string& codespace_name) {
    try {
        api_delete("/user/codespaces/" + codespace_name);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool GitHubExtension::start_codespace(const std::string& codespace_name) {
    try {
        api_post("/user/codespaces/" + codespace_name + "/start", json::object());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool GitHubExtension::stop_codespace(const std::string& codespace_name) {
    try {
        api_post("/user/codespaces/" + codespace_name + "/stop", json::object());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::string GitHubExtension::get_codespace_export(const std::string& codespace_name) {
    auto response = api_get("/user/codespaces/" + codespace_name + "/exports");
    return response["export_url"];
}

std::vector<GitHubExtension::GitHubPackage> GitHubExtension::list_packages(const std::string& owner, const std::string& package_type) {
    std::string endpoint = "/user/packages";
    
    if (!package_type.empty()) {
        endpoint += "?package_type=" + package_type;
    }
    
    auto response = api_get(endpoint);
    
    std::vector<GitHubPackage> packages;
    for (const auto& item : response) {
        GitHubPackage package;
        package.name = item["name"];
        package.package_type = item["package_type"];
        package.visibility = item["visibility"];
        package.created_at = item["created_at"];
        package.updated_at = item["updated_at"];
        package.version_count = item["version_count"];
        packages.push_back(package);
    }
    return packages;
}

GitHubExtension::GitHubPackage GitHubExtension::get_package(const std::string& owner, const std::string& package_type, const std::string& package_name) {
    auto response = api_get("/user/packages/" + package_type + "/" + package_name);
    
    GitHubPackage package;
    package.name = response["name"];
    package.package_type = response["package_type"];
    package.visibility = response["visibility"];
    package.created_at = response["created_at"];
    package.updated_at = response["updated_at"];
    package.version_count = response["version_count"];
    
    return package;
}

bool GitHubExtension::delete_package(const std::string& owner, const std::string& package_type, const std::string& package_name) {
    try {
        api_delete("/user/packages/" + package_type + "/" + package_name);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool GitHubExtension::restore_package(const std::string& owner, const std::string& package_type, const std::string& package_name) {
    try {
        api_post("/user/packages/" + package_type + "/" + package_name + "/restore", json::object());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<GitHubExtension::SecurityVulnerability> GitHubExtension::get_vulnerability_alerts(const std::string& owner, const std::string& repo) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/vulnerability-alerts");
    
    std::vector<SecurityVulnerability> vulnerabilities;
    for (const auto& item : response) {
        SecurityVulnerability vuln;
        vuln.package_name = item["package"]["name"];
        vuln.severity = item["severity"];
        vuln.vulnerable_version_range = item["vulnerable_version_range"];
        vuln.first_patched_version = item.value("first_patched_version", "");
        vuln.advisory_url = item["advisory"]["url"];
        vuln.summary = item["advisory"]["summary"];
        vuln.published_at = item["advisory"]["published_at"];
        vulnerabilities.push_back(vuln);
    }
    return vulnerabilities;
}

bool GitHubExtension::enable_vulnerability_alerts(const std::string& owner, const std::string& repo) {
    try {
        api_put("/repos/" + owner + "/" + repo + "/vulnerability-alerts", json::object());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool GitHubExtension::disable_vulnerability_alerts(const std::string& owner, const std::string& repo) {
    try {
        api_delete("/repos/" + owner + "/" + repo + "/vulnerability-alerts");
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<GitHubExtension::DependabotAlert> GitHubExtension::list_dependabot_alerts(const std::string& owner, const std::string& repo) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/dependabot/alerts");
    
    std::vector<DependabotAlert> alerts;
    for (const auto& item : response) {
        DependabotAlert alert;
        alert.number = item["number"];
        alert.state = item["state"];
        alert.dependency = item["dependency"]["package"]["name"];
        alert.manifest_path = item["dependency"]["manifest_path"];
        alert.created_at = item["created_at"];
        alert.updated_at = item["updated_at"];
        alert.dismissed_at = item.value("dismissed_at", "");
        
        if (item.contains("dismissed_by")) {
            alert.dismissed_by = user_from_json(item["dismissed_by"]);
        }
        
        alert.dismissal_reason = item.value("dismissed_reason", "");
        
        SecurityVulnerability vuln;
        vuln.package_name = item["security_vulnerability"]["package"]["name"];
        vuln.severity = item["security_vulnerability"]["severity"];
        vuln.vulnerable_version_range = item["security_vulnerability"]["vulnerable_version_range"];
        vuln.advisory_url = item["security_advisory"]["url"];
        vuln.summary = item["security_advisory"]["summary"];
        vuln.published_at = item["security_advisory"]["published_at"];
        
        alert.vulnerability = vuln;
        alerts.push_back(alert);
    }
    return alerts;
}

GitHubExtension::DependabotAlert GitHubExtension::get_dependabot_alert(const std::string& owner, const std::string& repo, int64_t alert_number) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/dependabot/alerts/" + std::to_string(alert_number));
    
    DependabotAlert alert;
    alert.number = response["number"];
    alert.state = response["state"];
    alert.dependency = response["dependency"]["package"]["name"];
    alert.manifest_path = response["dependency"]["manifest_path"];
    alert.created_at = response["created_at"];
    alert.updated_at = response["updated_at"];
    alert.dismissed_at = response.value("dismissed_at", "");
    
    if (response.contains("dismissed_by")) {
        alert.dismissed_by = user_from_json(response["dismissed_by"]);
    }
    
    alert.dismissal_reason = response.value("dismissed_reason", "");
    
    return alert;
}

bool GitHubExtension::update_dependabot_alert(const std::string& owner, const std::string& repo, int64_t alert_number, const std::string& state, const std::string& dismissal_reason) {
    json data = {
        {"state", state}
    };
    
    if (!dismissal_reason.empty()) {
        data["dismissed_reason"] = dismissal_reason;
    }
    
    try {
        api_patch("/repos/" + owner + "/" + repo + "/dependabot/alerts/" + std::to_string(alert_number), data);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

GitHubExtension::GitHubWebhook GitHubExtension::create_webhook(const std::string& owner, const std::string& repo, const std::string& url, const std::vector<std::string>& events, const std::string& secret) {
    json data = {
        {"name", "web"},
        {"config", {
            {"url", url},
            {"content_type", "json"}
        }},
        {"events", events},
        {"active", true}
    };
    
    if (!secret.empty()) {
        data["config"]["secret"] = secret;
    }
    
    auto response = api_post("/repos/" + owner + "/" + repo + "/hooks", data);
    
    GitHubWebhook webhook;
    webhook.id = response["id"];
    webhook.name = response["name"];
    webhook.events = response["events"].get<std::vector<std::string>>();
    webhook.url = response["config"]["url"];
    webhook.is_active = response["active"];
    webhook.created_at = response["created_at"];
    webhook.updated_at = response["updated_at"];
    
    return webhook;
}

std::vector<GitHubExtension::GitHubWebhook> GitHubExtension::list_webhooks(const std::string& owner, const std::string& repo) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/hooks");
    
    std::vector<GitHubWebhook> webhooks;
    for (const auto& item : response) {
        GitHubWebhook webhook;
        webhook.id = item["id"];
        webhook.name = item["name"];
        webhook.events = item["events"].get<std::vector<std::string>>();
        webhook.url = item["config"]["url"];
        webhook.is_active = item["active"];
        webhook.created_at = item["created_at"];
        webhook.updated_at = item["updated_at"];
        webhooks.push_back(webhook);
    }
    return webhooks;
}

GitHubExtension::GitHubWebhook GitHubExtension::get_webhook(const std::string& owner, const std::string& repo, int64_t hook_id) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/hooks/" + std::to_string(hook_id));
    
    GitHubWebhook webhook;
    webhook.id = response["id"];
    webhook.name = response["name"];
    webhook.events = response["events"].get<std::vector<std::string>>();
    webhook.url = response["config"]["url"];
    webhook.is_active = response["active"];
    webhook.created_at = response["created_at"];
    webhook.updated_at = response["updated_at"];
    
    return webhook;
}

bool GitHubExtension::delete_webhook(const std::string& owner, const std::string& repo, int64_t hook_id) {
    try {
        api_delete("/repos/" + owner + "/" + repo + "/hooks/" + std::to_string(hook_id));
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<GitHubExtension::GitHubTeam> GitHubExtension::list_teams(const std::string& owner, const std::string& repo) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/teams");
    
    std::vector<GitHubTeam> teams;
    for (const auto& item : response) {
        GitHubTeam team;
        team.id = item["id"];
        team.name = item["name"];
        team.slug = item["slug"];
        team.description = item.value("description", "");
        team.privacy = item["privacy"];
        team.permission = item["permission"];
        team.members_count = item["members_count"];
        team.repos_count = item["repos_count"];
        team.created_at = item["created_at"];
        team.updated_at = item["updated_at"];
        teams.push_back(team);
    }
    return teams;
}

void GitHubExtension::add_team_to_repository(const std::string& owner, const std::string& repo, const std::string& team_slug, const std::string& permission) {
    json data = {
        {"permission", permission}
    };
    
    api_put("/orgs/" + owner + "/teams/" + team_slug + "/repos/" + owner + "/" + repo, data);
}

void GitHubExtension::remove_team_from_repository(const std::string& owner, const std::string& repo, const std::string& team_slug) {
    api_delete("/orgs/" + owner + "/teams/" + team_slug + "/repos/" + owner + "/" + repo);
}

std::vector<GitHubExtension::GitHubUser> GitHubExtension::list_collaborators(const std::string& owner, const std::string& repo) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/collaborators");
    
    std::vector<GitHubUser> collaborators;
    for (const auto& item : response) {
        collaborators.push_back(user_from_json(item));
    }
    return collaborators;
}

void GitHubExtension::add_collaborator(const std::string& owner, const std::string& repo, const std::string& username, const std::string& permission) {
    json data = {
        {"permission", permission}
    };
    
    api_put("/repos/" + owner + "/" + repo + "/collaborators/" + username, data);
}

void GitHubExtension::remove_collaborator(const std::string& owner, const std::string& repo, const std::string& username) {
    api_delete("/repos/" + owner + "/" + repo + "/collaborators/" + username);
}

GitHubExtension::GitHubPages GitHubExtension::get_pages_info(const std::string& owner, const std::string& repo) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/pages");
    
    GitHubPages pages;
    pages.url = response["html_url"];
    pages.status = response["status"];
    pages.cname = response.value("cname", "");
    pages.is_https = response["https_enforced"];
    pages.source_branch = response["source"]["branch"];
    pages.source_path = response["source"]["path"];
    pages.published_at = response.value("published_at", "");
    
    return pages;
}

bool GitHubExtension::enable_pages(const std::string& owner, const std::string& repo, const std::string& source_branch, const std::string& source_path) {
    json data = {
        {"build_type", "workflow"},
        {"source", {
            {"branch", source_branch},
            {"path", source_path}
        }}
    };
    
    try {
        api_post("/repos/" + owner + "/" + repo + "/pages", data);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool GitHubExtension::disable_pages(const std::string& owner, const std::string& repo) {
    try {
        api_delete("/repos/" + owner + "/" + repo + "/pages");
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<GitHubExtension::Discussion> GitHubExtension::list_discussions(const std::string& owner, const std::string& repo, const std::string& category) {
    std::string endpoint = "/repos/" + owner + "/" + repo + "/discussions";
    
    if (!category.empty()) {
        endpoint += "?category=" + category;
    }
    
    auto response = api_get(endpoint);
    
    std::vector<Discussion> discussions;
    for (const auto& item : response) {
        Discussion discussion;
        discussion.number = item["number"];
        discussion.title = item["title"];
        discussion.body = item["body"];
        discussion.user = user_from_json(item["user"]);
        discussion.category = item["category"]["name"];
        discussion.state = item["state"];
        discussion.answer_chosen_at = item.value("answer_chosen_at", 0);
        discussion.comments_count = item["comments_count"];
        discussion.created_at = item["created_at"];
        discussion.updated_at = item["updated_at"];
        
        if (item.contains("answer_chosen_by")) {
            discussion.answer_chosen_by = user_from_json(item["answer_chosen_by"]);
        }
        
        discussions.push_back(discussion);
    }
    return discussions;
}

GitHubExtension::Discussion GitHubExtension::get_discussion(const std::string& owner, const std::string& repo, int64_t discussion_number) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/discussions/" + std::to_string(discussion_number));
    
    Discussion discussion;
    discussion.number = response["number"];
    discussion.title = response["title"];
    discussion.body = response["body"];
    discussion.user = user_from_json(response["user"]);
    discussion.category = response["category"]["name"];
    discussion.state = response["state"];
    discussion.answer_chosen_at = response.value("answer_chosen_at", 0);
    discussion.comments_count = response["comments_count"];
    discussion.created_at = response["created_at"];
    discussion.updated_at = response["updated_at"];
    
    if (response.contains("answer_chosen_by")) {
        discussion.answer_chosen_by = user_from_json(response["answer_chosen_by"]);
    }
    
    return discussion;
}

GitHubExtension::Discussion GitHubExtension::create_discussion(const std::string& owner, const std::string& repo, const std::string& title, const std::string& body, const std::string& category) {
    json data = {
        {"title", title},
        {"body", body},
        {"category", category}
    };
    
    auto response = api_post("/repos/" + owner + "/" + repo + "/discussions", data);
    
    Discussion discussion;
    discussion.number = response["number"];
    discussion.title = response["title"];
    discussion.body = response["body"];
    discussion.user = user_from_json(response["user"]);
    discussion.category = response["category"]["name"];
    discussion.state = response["state"];
    discussion.comments_count = response["comments_count"];
    discussion.created_at = response["created_at"];
    discussion.updated_at = response["updated_at"];
    
    return discussion;
}

std::vector<GitHubExtension::Project> GitHubExtension::list_projects(const std::string& owner, const std::string& repo) {
    auto response = api_get("/repos/" + owner + "/" + repo + "/projects");
    
    std::vector<Project> projects;
    for (const auto& item : response) {
        Project project;
        project.id = item["id"];
        project.name = item["name"];
        project.body = item["body"];
        project.state = item["state"];
        project.number = item["number"];
        project.html_url = item["html_url"];
        project.created_at = item["created_at"];
        project.updated_at = item["updated_at"];
        projects.push_back(project);
    }
    return projects;
}

GitHubExtension::Project GitHubExtension::create_project(const std::string& owner, const std::string& repo, const std::string& name, const std::string& body) {
    json data = {
        {"name", name},
        {"body", body}
    };
    
    auto response = api_post("/repos/" + owner + "/" + repo + "/projects", data);
    
    Project project;
    project.id = response["id"];
    project.name = response["name"];
    project.body = response["body"];
    project.state = response["state"];
    project.number = response["number"];
    project.html_url = response["html_url"];
    project.created_at = response["created_at"];
    project.updated_at = response["updated_at"];
    
    return project;
}

bool GitHubExtension::delete_project(int64_t project_id) {
    try {
        api_delete("/projects/" + std::to_string(project_id));
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

GitHubExtension::SearchResult GitHubExtension::search_repositories(const std::string& query, const std::string& sort, const std::string& order, int per_page) {
    std::string endpoint = "/search/repositories?q=" + query + "&per_page=" + std::to_string(per_page);
    
    if (!sort.empty()) endpoint += "&sort=" + sort;
    if (!order.empty()) endpoint += "&order=" + order;
    
    auto response = api_get(endpoint);
    
    SearchResult result;
    result.total_count = response["total_count"];
    result.incomplete_results = response["incomplete_results"];
    result.items = response["items"];
    
    return result;
}

GitHubExtension::SearchResult GitHubExtension::search_code(const std::string& query, const std::string& owner, const std::string& repo, const std::string& language) {
    std::string search_query = query;
    if (!owner.empty()) search_query += "+user:" + owner;
    if (!repo.empty()) search_query += "+repo:" + owner + "/" + repo;
    if (!language.empty()) search_query += "+language:" + language;
    
    auto response = api_get("/search/code?q=" + search_query);
    
    SearchResult result;
    result.total_count = response["total_count"];
    result.incomplete_results = response["incomplete_results"];
    result.items = response["items"];
    
    return result;
}

GitHubExtension::SearchResult GitHubExtension::search_issues(const std::string& query, const std::string& owner, const std::string& repo, const std::string& state) {
    std::string search_query = query;
    if (!owner.empty()) search_query += "+user:" + owner;
    if (!repo.empty()) search_query += "+repo:" + owner + "/" + repo;
    if (!state.empty()) search_query += "+state:" + state;
    
    auto response = api_get("/search/issues?q=" + search_query);
    
    SearchResult result;
    result.total_count = response["total_count"];
    result.incomplete_results = response["incomplete_results"];
    result.items = response["items"];
    
    return result;
}

GitHubExtension::Gist GitHubExtension::create_gist(const std::string& description, const std::map<std::string, std::string>& files, bool is_public) {
    json data = {
        {"description", description},
        {"public", is_public},
        {"files", json::object()}
    };
    
    for (const auto& [filename, content] : files) {
        data["files"][filename] = {{"content", content}};
    }
    
    auto response = api_post("/gists", data);
    
    Gist gist;
    gist.id = response["id"];
    gist.description = response["description"];
    gist.is_public = response["public"];
    gist.owner = user_from_json(response["owner"]);
    gist.files = response["files"];
    gist.created_at = response["created_at"];
    gist.updated_at = response["updated_at"];
    gist.comments = response["comments"];
    gist.html_url = response["html_url"];
    gist.git_pull_url = response["git_pull_url"];
    gist.git_push_url = response["git_push_url"];
    
    return gist;
}

GitHubExtension::Gist GitHubExtension::get_gist(const std::string& gist_id) {
    auto response = api_get("/gists/" + gist_id);
    
    Gist gist;
    gist.id = response["id"];
    gist.description = response["description"];
    gist.is_public = response["public"];
    gist.owner = user_from_json(response["owner"]);
    gist.files = response["files"];
    gist.created_at = response["created_at"];
    gist.updated_at = response["updated_at"];
    gist.comments = response["comments"];
    gist.html_url = response["html_url"];
    gist.git_pull_url = response["git_pull_url"];
    gist.git_push_url = response["git_push_url"];
    
    return gist;
}

std::vector<GitHubExtension::Gist> GitHubExtension::list_user_gists(const std::string& username) {
    std::string endpoint = username.empty() ? "/gists" : "/users/" + username + "/gists";
    auto response = api_get(endpoint);
    
    std::vector<Gist> gists;
    for (const auto& item : response) {
        Gist gist;
        gist.id = item["id"];
        gist.description = item["description"];
        gist.is_public = item["public"];
        gist.owner = user_from_json(item["owner"]);
        gist.files = item["files"];
        gist.created_at = item["created_at"];
        gist.updated_at = item["updated_at"];
        gist.comments = item["comments"];
        gist.html_url = item["html_url"];
        gist.git_pull_url = item["git_pull_url"];
        gist.git_push_url = item["git_push_url"];
        gists.push_back(gist);
    }
    return gists;
}

bool GitHubExtension::delete_gist(const std::string& gist_id) {
    try {
        api_delete("/gists/" + gist_id);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

GitHubExtension::EnterpriseLicense GitHubExtension::get_enterprise_license(const std::string& enterprise) {
    auto response = api_get("/enterprise/" + enterprise + "/license");
    
    EnterpriseLicense license;
    license.seats = response["seats"];
    license.seats_used = response["seats_used"];
    license.seats_available = response["seats_available"];
    license.kind = response["kind"];
    license.expires_at = response["expires_at"];
    
    return license;
}

std::vector<GitHubExtension::GitHubUser> GitHubExtension::list_enterprise_users(const std::string& enterprise) {
    auto response = api_get("/enterprise/" + enterprise + "/users");
    
    std::vector<GitHubUser> users;
    for (const auto& item : response) {
        users.push_back(user_from_json(item));
    }
    return users;
}

std::string GitHubExtension::get_api_url(const std::string& endpoint) const {
    return config_.base_url + endpoint;
}

nlohmann::json GitHubExtension::api_get(const std::string& endpoint) {
    return json::parse(make_request("GET", get_api_url(endpoint)));
}

nlohmann::json GitHubExtension::api_post(const std::string& endpoint, const nlohmann::json& data) {
    return json::parse(make_request("POST", get_api_url(endpoint), data.dump()));
}

nlohmann::json GitHubExtension::api_put(const std::string& endpoint, const nlohmann::json& data) {
    return json::parse(make_request("PUT", get_api_url(endpoint), data.dump()));
}

nlohmann::json GitHubExtension::api_patch(const std::string& endpoint, const nlohmann::json& data) {
    return json::parse(make_request("PATCH", get_api_url(endpoint), data.dump()));
}

nlohmann::json GitHubExtension::api_delete(const std::string& endpoint) {
    return json::parse(make_request("DELETE", get_api_url(endpoint)));
}

std::string GitHubExtension::make_request(const std::string& method, const std::string& url, const std::string& data) {
    std::lock_guard<std::mutex> lock(api_mutex_);
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
    
    std::string response_string;
    std::string header_string;
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "User-Agent: GitHubExtension/1.0");
    headers = curl_slist_append(headers, "Accept: application/vnd.github.v3+json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    std::string auth_header = "Authorization: token " + config_.token;
    headers = curl_slist_append(headers, auth_header.c_str());
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* contents, size_t size, size_t nmemb, std::string* s) -> size_t {
        size_t new_length = size * nmemb;
        s->append(static_cast<char*>(contents), new_length);
        return new_length;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, +[](void* contents, size_t size, size_t nmemb, std::string* s) -> size_t {
        size_t new_length = size * nmemb;
        s->append(static_cast<char*>(contents), new_length);
        return new_length;
    });
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
    
    if (!data.empty()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    }
    
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config_.timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    CURLcode res = curl_easy_perform(curl);
    
    long response_code;
    curl_easy_getinfo(curl, CURLOPT_RESPONSE_CODE, &response_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
    }
    
    if (response_code >= 400) {
        handle_http_error(response_code, response_string);
    }
    
    update_rate_limits(header_string);
    
    return response_string;
}

void GitHubExtension::handle_http_error(int status_code, const std::string& response) {
    std::string error_message = "HTTP " + std::to_string(status_code);
    
    try {
        auto json_response = json::parse(response);
        if (json_response.contains("message")) {
            error_message += ": " + json_response["message"].get<std::string>();
        }
    } catch (...) {
        error_message += ": " + response;
    }
    
    throw std::runtime_error(error_message);
}

void GitHubExtension::update_rate_limits(const std::string& response_headers) {
    std::istringstream stream(response_headers);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.find("X-RateLimit-Limit:") == 0) {
            rate_limits_["core"].limit = std::stoi(line.substr(18));
        } else if (line.find("X-RateLimit-Remaining:") == 0) {
            rate_limits_["core"].remaining = std::stoi(line.substr(22));
        } else if (line.find("X-RateLimit-Reset:") == 0) {
            rate_limits_["core"].reset_time = std::stoi(line.substr(18));
        }
    }
}

void GitHubExtension::cache_set(const std::string& key, const nlohmann::json& value) {
    if (config_.enable_caching) {
        cache_[key] = value;
    }
}

std::optional<nlohmann::json> GitHubExtension::cache_get(const std::string& key) {
    if (config_.enable_caching && cache_.count(key)) {
        return cache_[key];
    }
    return std::nullopt;
}

void GitHubExtension::cache_clear() {
    cache_.clear();
}

GitHubExtension::GitHubUser GitHubExtension::user_from_json(const nlohmann::json& json) {
    GitHubUser user;
    user.login = json["login"];
    user.name = json.value("name", "");
    user.email = json.value("email", "");
    user.avatar_url = json["avatar_url"];
    user.type = json["type"];
    user.id = json["id"];
    user.url = json["url"];
    user.html_url = json["html_url"];
    user.followers = json.value("followers", 0);
    user.following = json.value("following", 0);
    user.created_at = json["created_at"];
    user.updated_at = json.value("updated_at", "");
    return user;
}

GitHubExtension::GitHubRepository GitHubExtension::repository_from_json(const nlohmann::json& json) {
    GitHubRepository repo;
    repo.name = json["name"];
    repo.full_name = json["full_name"];
    repo.description = json.value("description", "");
    repo.html_url = json["html_url"];
    repo.clone_url = json["clone_url"];
    repo.ssh_url = json["ssh_url"];
    repo.default_branch = json["default_branch"];
    repo.owner = user_from_json(json["owner"]);
    repo.is_private = json["private"];
    repo.is_fork = json["fork"];
    repo.is_archived = json["archived"];
    repo.is_template = json.value("is_template", false);
    repo.forks_count = json["forks_count"];
    repo.stargazers_count = json["stargazers_count"];
    repo.watchers_count = json["watchers_count"];
    repo.open_issues_count = json["open_issues_count"];
    repo.created_at = json["created_at"];
    repo.updated_at = json["updated_at"];
    repo.pushed_at = json["pushed_at"];
    repo.language = json.value("language", "");
    repo.permissions = json.value("permissions", json::object());
    return repo;
}

GitHubExtension::GitHubIssue GitHubExtension::issue_from_json(const nlohmann::json& json) {
    GitHubIssue issue;
    issue.number = json["number"];
    issue.title = json["title"];
    issue.body = json.value("body", "");
    issue.state = json["state"];
    issue.user = user_from_json(json["user"]);
    issue.created_at = json["created_at"];
    issue.updated_at = json["updated_at"];
    issue.closed_at = json.value("closed_at", "");
    issue.html_url = json["html_url"];
    
    if (json.contains("assignees")) {
        for (const auto& assignee : json["assignees"]) {
            issue.assignees.push_back(user_from_json(assignee));
        }
    }
    
    if (json.contains("labels")) {
        for (const auto& label : json["labels"]) {
            issue.labels.push_back(label["name"]);
        }
    }
    
    if (json.contains("closed_by") && !json["closed_by"].is_null()) {
        issue.closed_by = user_from_json(json["closed_by"]);
    }
    
    return issue;
}

GitHubExtension::GitHubPullRequest GitHubExtension::pull_request_from_json(const nlohmann::json& json) {
    GitHubPullRequest pr;
    pr.number = json["number"];
    pr.title = json["title"];
    pr.body = json.value("body", "");
    pr.state = json["state"];
    pr.head_branch = json["head"]["ref"];
    pr.base_branch = json["base"]["ref"];
    pr.user = user_from_json(json["user"]);
    pr.is_draft = json.value("draft", false);
    pr.is_merged = json.value("merged", false);
    pr.merge_commit_sha = json.value("merge_commit_sha", "");
    pr.created_at = json["created_at"];
    pr.updated_at = json["updated_at"];
    pr.closed_at = json.value("closed_at", "");
    pr.merged_at = json.value("merged_at", "");
    pr.html_url = json["html_url"];
    pr.additions = json.value("additions", 0);
    pr.deletions = json.value("deletions", 0);
    pr.changed_files = json.value("changed_files", 0);
    
    if (json.contains("assignees")) {
        for (const auto& assignee : json["assignees"]) {
            pr.assignees.push_back(user_from_json(assignee));
        }
    }
    
    if (json.contains("labels")) {
        for (const auto& label : json["labels"]) {
            pr.labels.push_back(label["name"]);
        }
    }
    
    if (json.contains("requested_reviewers")) {
        for (const auto& reviewer : json["requested_reviewers"]) {
            pr.requested_reviewers.push_back(user_from_json(reviewer));
        }
    }
    
    if (json.contains("merged_by") && !json["merged_by"].is_null()) {
        pr.merged_by = user_from_json(json["merged_by"]);
    }
    
    return pr;
}

GitHubExtension::GitHubRelease GitHubExtension::release_from_json(const nlohmann::json& json) {
    GitHubRelease release;
    release.tag_name = json["tag_name"];
    release.name = json.value("name", "");
    release.body = json.value("body", "");
    release.is_draft = json["draft"];
    release.is_prerelease = json["prerelease"];
    release.target_commitish = json["target_commitish"];
    release.created_at = json["created_at"];
    release.published_at = json.value("published_at", "");
    release.html_url = json["html_url"];
    release.tarball_url = json["tarball_url"];
    release.zipball_url = json["zipball_url"];
    
    if (json.contains("author")) {
        release.authors.push_back(user_from_json(json["author"]));
    }
    
    return release;
}

GitHubExtension::GitHubCodespace GitHubExtension::codespace_from_json(const nlohmann::json& json) {
    GitHubCodespace codespace;
    codespace.id = json["id"];
    codespace.name = json["name"];
    codespace.display_name = json.value("display_name", "");
    codespace.state = json["state"];
    codespace.repository_name = json["repository"]["full_name"];
    codespace.branch = json["git_status"]["ref"];
    codespace.git_status = json["git_status"]["ahead"] > 0 ? "ahead" : "clean";
    codespace.location = json["location"];
    codespace.machine_name = json["machine"]["name"];
    codespace.created_at = json["created_at"];
    codespace.last_used_at = json.value("last_used_at", "");
    codespace.retention_period_minutes = json.value("retention_period_minutes", 0);
    codespace.devcontainer_config = json.value("devcontainer_config", json::object());
    return codespace;
}