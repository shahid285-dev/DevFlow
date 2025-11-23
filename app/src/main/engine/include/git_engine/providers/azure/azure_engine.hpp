#ifndef AZURE_DEVOPS_EXTENSION_H
#define AZURE_DEVOPS_EXTENSION_H

#include "GitBase.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>

class AzureDevOpsExtension : public GitBase {
public:
    // Azure DevOps-specific data structures
    struct AzureUser {
        std::string id;
        std::string descriptor;
        std::string displayName;
        std::string uniqueName;
        std::string url;
        std::string imageUrl;
        bool isContainer;
    };

    struct AzureProject {
        std::string id;
        std::string name;
        std::string description;
        std::string url;
        std::string state; // "wellFormed", "createPending", "deleting", "new", "unchanged"
        int revision;
        std::string visibility; // "private", "public"
        std::string lastUpdateTime;
        AzureUser createdBy;
    };

    struct AzureRepository {
        std::string id;
        std::string name;
        std::string url;
        AzureProject project;
        std::string defaultBranch;
        std::string remoteUrl;
        std::string sshUrl;
        size_t size;
        std::string webUrl;
        bool isDisabled;
        bool isFork;
    };

    struct AzurePullRequest {
        int pullRequestId;
        int codeReviewId;
        std::string title;
        std::string description;
        std::string status; // "abandoned", "active", "completed"
        std::string mergeStatus; // "conflicts", "failure", "queued", "rejectedByPolicy", "succeeded", "succeededWithConflicts"
        std::string creationDate;
        std::string closedDate;
        std::string sourceRefName;
        std::string targetRefName;
        std::string mergeId;
        AzureUser createdBy;
        std::vector<AzureUser> reviewers;
        std::vector<std::string> labels;
        std::string url;
        bool supportsIterations;
        std::string completionOptions;
        std::string lastMergeSourceCommit;
        std::string lastMergeTargetCommit;
        std::string lastMergeCommit;
        std::vector<std::string> workItemRefs;
        bool isDraft;
    };

    struct AzureCommit {
        std::string commitId;
        std::string treeId;
        std::vector<std::string> parentIds;
        AzureUser author;
        AzureUser committer;
        std::string comment;
        std::string commentTruncated;
        std::string push;
        std::string url;
        std::vector<std::string> remoteUrl;
        std::map<std::string, std::string> _links;
    };

    struct AzureBranch {
        std::string name;
        std::string objectId;
        std::string creatorId;
        std::string url;
        AzureCommit commit;
        std::vector<std::string> aheadCount;
        std::vector<std::string> behindCount;
        bool isBaseVersion;
    };

    struct AzureBuild {
        int id;
        std::string buildNumber;
        std::string status; // "inProgress", "completed", "cancelling", "postponed", "notStarted", "all"
        std::string result; // "succeeded", "partiallySucceeded", "failed", "canceled"
        std::string queueTime;
        std::string startTime;
        std::string finishTime;
        std::string url;
        std::string definitionName;
        AzureProject project;
        std::string repository;
        std::string sourceBranch;
        std::string sourceVersion;
        std::vector<std::string> tags;
        std::map<std::string, std::string> properties;
        std::vector<std::string> requestedFor;
        std::string reason; // "manual", "individualCI", "batchedCI", "schedule", "gatedCheckIn", "pullRequest", "buildCompletion", "resourceTrigger", "triggered", "all"
    };

    struct AzureRelease {
        int id;
        std::string name;
        std::string status; // "abandoned", "active", "draft", "undefined"
        std::string createdOn;
        std::string modifiedOn;
        AzureUser createdBy;
        AzureUser modifiedBy;
        std::vector<std::string> environments;
        std::string url;
        std::string _links;
        std::vector<std::string> artifacts;
        std::string description;
        std::string reason; // "none", "manual", "continuousIntegration", "schedule", "pullRequest"
        std::string releaseNameFormat;
        bool keepForever;
        std::string logContainerUrl;
    };

    struct AzureWorkItem {
        int id;
        int rev;
        std::string url;
        std::map<std::string, std::string> fields;
        std::vector<std::string> relations;
        std::vector<std::string> _links;
    };

    struct AzurePipeline {
        int id;
        std::string name;
        std::string folder;
        int revision;
        AzureProject project;
        std::string url;
        std::map<std::string, std::string> _links;
    };

    struct AzureTestPlan {
        int id;
        std::string name;
        std::string description;
        AzureProject project;
        std::string area;
        std::string startDate;
        std::string endDate;
        std::string iteration;
        std::string state; // "inProgress", "closed", "draft"
        std::string rootSuite;
        std::string clientUrl;
        std::string webUrl;
    };

    struct AzureTestRun {
        int id;
        std::string name;
        std::string url;
        bool isAutomated;
        std::string iteration;
        std::string owner;
        std::string project;
        std::string startedDate;
        std::string completedDate;
        std::string state; // "unspecified", "notStarted", "inProgress", "completed", "aborted", "waiting"
        std::string plan;
        std::string postProcessState; // "none", "readyForPostProcessing", "postProcessingCompleted", "postProcessingFailed"
        int totalTests;
        int passedTests;
        int failedTests;
        int notApplicableTests;
    };

    struct AzureArtifact {
        std::string id;
        std::string name;
        std::string version;
        std::string type; // "maven", "npm", "nuget", "pypi", "universal", "docker", "cargo", "gradle", "helm"
        std::string description;
        std::string publisher;
        std::string downloadUrl;
        std::string feed;
        std::vector<std::string> versions;
    };

    struct AzureWiki {
        std::string id;
        std::string name;
        std::string projectId;
        std::string repositoryId;
        std::string type; // "projectWiki", "codeWiki"
        std::string url;
        std::string remoteUrl;
        std::string version;
        std::map<std::string, std::string> _links;
    };

    struct AzureWikiPage {
        std::string id;
        std::string path;
        std::string content;
        std::string url;
        std::string gitItemPath;
        bool isParentPage;
        int order;
        std::string subPages;
        std::string etag;
    };

    struct AzureBoard {
        std::string id;
        std::string name;
        std::string description;
        std::string url;
        std::map<std::string, std::string> _links;
    };

    struct AzureBoardColumn {
        std::string id;
        std::string name;
        std::string columnType; // "incoming", "inProgress", "outgoing"
        bool isSplit;
        std::string description;
        std::string itemLimit;
        std::string stateMappings;
    };

    struct AzureIteration {
        std::string id;
        std::string name;
        std::string path;
        std::string startDate;
        std::string finishDate;
        std::string url;
        std::map<std::string, std::string> attributes;
    };

    struct AzureArea {
        std::string id;
        std::string name;
        std::string path;
        std::string url;
    };

    struct AzurePolicy {
        std::string id;
        std::string type;
        std::string url;
        std::map<std::string, std::string> configuration;
        bool isEnabled;
        bool isBlocking;
        AzureUser createdBy;
        std::string createdDate;
    };

    struct AzureServiceEndpoint {
        std::string id;
        std::string name;
        std::string type;
        std::string url;
        std::map<std::string, std::string> authorization;
        bool isReady;
        std::string operationStatus;
        std::vector<std::string> owners;
    };

    struct AzureVariableGroup {
        std::string id;
        std::string name;
        std::string description;
        std::map<std::string, std::string> variables;
        std::string type; // "Vsts", "AzureKeyVault"
        bool isShared;
        std::vector<std::string> ownerReferences;
    };

    struct AzureDeploymentGroup {
        int id;
        std::string name;
        std::string description;
        AzureProject project;
        std::vector<std::string> machines;
        std::map<std::string, std::string> _links;
    };

    struct AzureTaskGroup {
        std::string id;
        std::string name;
        std::string description;
        std::string category;
        std::string author;
        std::string version;
        std::string visibility; // "build", "release"
        std::vector<std::string> tasks;
        std::map<std::string, std::string> inputs;
    };

    struct AzureQuery {
        std::string id;
        std::string name;
        std::string path;
        std::string wiql;
        bool isPublic;
        std::string queryType; // "flat", "tree", "oneHop"
        std::vector<std::string> columns;
        std::map<std::string, std::string> _links;
    };

    struct AzureNotification {
        std::string id;
        std::string type;
        std::string message;
        std::string createdDate;
        std::vector<std::string> subscribers;
        std::map<std::string, std::string> details;
    };

    // Authentication & Configuration
    struct AzureDevOpsConfig {
        std::string organization;
        std::string base_url = "https://dev.azure.com";
        std::string token;
        std::string project; // Default project
        int timeout_seconds = 30;
        int retry_attempts = 3;
        bool enable_caching = true;
        std::string api_version = "7.1";
    };

    // Constructor & Configuration
    AzureDevOpsExtension(const AzureDevOpsConfig& config);
    virtual ~AzureDevOpsExtension();

    void set_config(const AzureDevOpsConfig& config);
    AzureDevOpsConfig get_config() const;

    // Authentication & Rate Limiting
    bool authenticate();
    struct RateLimitInfo get_rate_limit();
    bool is_rate_limited();

    // Core Management
    AzureUser get_current_user();
    std::vector<AzureProject> list_projects(bool stateFilter = true, int top = 1000);
    AzureProject get_project(const std::string& project_id);
    AzureProject create_project(const std::string& name, const std::string& description = "",
                              const std::string& visibility = "private");
    bool delete_project(const std::string& project_id);
    AzureProject update_project(const std::string& project_id, const std::string& name = "",
                              const std::string& description = "", const std::string& visibility = "");

    // Git Repository Management
    AzureRepository create_repository(const std::string& project, const std::string& name,
                                    const std::string& default_branch = "refs/heads/main");
    AzureRepository get_repository(const std::string& project, const std::string& repo_id);
    std::vector<AzureRepository> list_repositories(const std::string& project = "");
    AzureRepository update_repository(const std::string& project, const std::string& repo_id,
                                    const std::string& name = "", const std::string& default_branch = "");
    bool delete_repository(const std::string& project, const std::string& repo_id);
    
    // Repository Operations with Azure DevOps enhancements
    void clone_azure_repository(const std::string& project, const std::string& repo_name,
                              const std::string& local_path,
                              const std::function<bool(size_t, size_t)>& progress_callback = {});

    // Branch Management
    std::vector<AzureBranch> list_branches(const std::string& project, const std::string& repo_id,
                                         const std::string& filter = "", bool includeStats = false);
    AzureBranch get_branch(const std::string& project, const std::string& repo_id, const std::string& branch_name);
    AzureBranch create_branch(const std::string& project, const std::string& repo_id,
                            const std::string& branch_name, const std::string& source_branch);
    bool delete_branch(const std::string& project, const std::string& repo_id, const std::string& branch_name);
    AzureBranch lock_branch(const std::string& project, const std::string& repo_id, const std::string& branch_name);
    AzureBranch unlock_branch(const std::string& project, const std::string& repo_id, const std::string& branch_name);

    // Commits Management
    AzureCommit get_commit(const std::string& project, const std::string& repo_id, const std::string& commit_id);
    std::vector<AzureCommit> list_commits(const std::string& project, const std::string& repo_id,
                                        const std::string& branch = "", const std::string& author = "",
                                        const std::string& since = "", const std::string& until = "",
                                        int top = 100);
    AzureCommit create_commit(const std::string& project, const std::string& repo_id,
                            const std::vector<std::string>& changes, const std::string& comment,
                            const std::string& branch);
    std::vector<std::string> get_commit_changes(const std::string& project, const std::string& repo_id,
                                              const std::string& commit_id);
    std::string get_commit_diff(const std::string& project, const std::string& repo_id, const std::string& commit_id);

    // Pull Request Management
    AzurePullRequest create_pull_request(const std::string& project, const std::string& repo_id,
                                       const std::string& title, const std::string& source_branch,
                                       const std::string& target_branch, const std::string& description = "",
                                       const std::vector<std::string>& reviewers = {}, bool is_draft = false,
                                       bool auto_complete = false, bool delete_source_branch = false);
    AzurePullRequest get_pull_request(const std::string& project, const std::string& repo_id, int pull_request_id);
    std::vector<AzurePullRequest> list_pull_requests(const std::string& project, const std::string& repo_id,
                                                   const std::string& status = "active",
                                                   const std::string& source_branch = "",
                                                   const std::string& target_branch = "");
    AzurePullRequest update_pull_request(const std::string& project, const std::string& repo_id, int pull_request_id,
                                       const std::string& title = "", const std::string& description = "",
                                       const std::string& status = "", const std::vector<std::string>& reviewers = {});
    bool abandon_pull_request(const std::string& project, const std::string& repo_id, int pull_request_id);
    bool complete_pull_request(const std::string& project, const std::string& repo_id, int pull_request_id,
                             const std::string& merge_commit_message = "", bool delete_source_branch = false);
    std::vector<AzureCommit> list_pull_request_commits(const std::string& project, const std::string& repo_id, int pull_request_id);
    std::vector<std::string> get_pull_request_changes(const std::string& project, const std::string& repo_id, int pull_request_id);
    std::vector<AzureWorkItem> list_pull_request_work_items(const std::string& project, const std::string& repo_id, int pull_request_id);

    // Work Item Tracking
    AzureWorkItem create_work_item(const std::string& project, const std::string& work_item_type,
                                 const std::map<std::string, std::string>& fields);
    AzureWorkItem get_work_item(const std::string& project, int work_item_id, const std::vector<std::string>& fields = {});
    std::vector<AzureWorkItem> list_work_items(const std::string& project, const std::vector<int>& work_item_ids,
                                             const std::vector<std::string>& fields = {});
    AzureWorkItem update_work_item(const std::string& project, int work_item_id,
                                 const std::map<std::string, std::string>& fields);
    bool delete_work_item(const std::string& project, int work_item_id);
    std::vector<AzureWorkItem> query_work_items(const std::string& project, const std::string& wiql);
    std::vector<AzureWorkItem> get_work_item_revisions(const std::string& project, int work_item_id);

    // Build & Pipeline Management
    AzureBuild queue_build(const std::string& project, int definition_id,
                         const std::string& source_branch = "", const std::string& source_version = "",
                         const std::map<std::string, std::string>& parameters = {});
    AzureBuild get_build(const std::string& project, int build_id);
    std::vector<AzureBuild> list_builds(const std::string& project, const std::string& definition_id = "",
                                      const std::string& status = "", const std::string& result = "",
                                      int top = 100);
    AzureBuild update_build(const std::string& project, int build_id, const std::string& status = "",
                          const std::string& result = "");
    bool delete_build(const std::string& project, int build_id);
    std::vector<std::string> get_build_logs(const std::string& project, int build_id);
    std::vector<AzurePipeline> list_pipelines(const std::string& project);
    AzurePipeline get_pipeline(const std::string& project, int pipeline_id);
    AzurePipeline create_pipeline(const std::string& project, const std::string& name,
                                const std::string& configuration, const std::string& folder = "");

    // Release Management
    AzureRelease create_release(const std::string& project, int definition_id,
                              const std::string& description = "", const std::string& artifact_alias = "",
                              bool is_draft = false);
    AzureRelease get_release(const std::string& project, int release_id);
    std::vector<AzureRelease> list_releases(const std::string& project, const std::string& definition_id = "",
                                          const std::string& status = "", int top = 50);
    AzureRelease update_release(const std::string& project, int release_id, const std::string& status = "",
                              const std::string& description = "");
    bool delete_release(const std::string& project, int release_id);
    AzureRelease deploy_release(const std::string& project, int release_id, int environment_id,
                              const std::map<std::string, std::string>& variables = {});

    // Test Management
    AzureTestPlan create_test_plan(const std::string& project, const std::string& name,
                                 const std::string& description = "", const std::string& area = "",
                                 const std::string& iteration = "");
    std::vector<AzureTestPlan> list_test_plans(const std::string& project);
    AzureTestPlan get_test_plan(const std::string& project, int plan_id);
    bool delete_test_plan(const std::string& project, int plan_id);
    AzureTestRun create_test_run(const std::string& project, const std::string& name,
                               const std::string& test_plan = "", const std::string& point = "",
                               bool is_automated = true);
    std::vector<AzureTestRun> list_test_runs(const std::string& project, const std::string& build_uri = "");
    AzureTestRun get_test_run(const std::string& project, int run_id);
    bool delete_test_run(const std::string& project, int run_id);

    // Artifacts Management
    AzureArtifact get_artifact(const std::string& project, const std::string& feed_id,
                             const std::string& package_id, const std::string& version = "");
    std::vector<AzureArtifact> list_artifacts(const std::string& project, const std::string& feed_id = "");
    AzureArtifact create_artifact(const std::string& project, const std::string& feed_id,
                                const std::string& name, const std::string& version,
                                const std::string& type, const std::string& description = "");
    bool delete_artifact(const std::string& project, const std::string& feed_id,
                       const std::string& package_id, const std::string& version = "");
    std::string download_artifact(const std::string& project, const std::string& feed_id,
                                const std::string& package_id, const std::string& version,
                                const std::string& download_path);

    // Wiki Management
    AzureWiki create_wiki(const std::string& project, const std::string& name,
                        const std::string& repository_id = "", const std::string& type = "projectWiki");
    std::vector<AzureWiki> list_wikis(const std::string& project);
    AzureWiki get_wiki(const std::string& project, const std::string& wiki_id);
    bool delete_wiki(const std::string& project, const std::string& wiki_id);
    AzureWikiPage create_wiki_page(const std::string& project, const std::string& wiki_id,
                                 const std::string& path, const std::string& content);
    AzureWikiPage get_wiki_page(const std::string& project, const std::string& wiki_id,
                              const std::string& path, const std::string& version = "");
    std::vector<AzureWikiPage> list_wiki_pages(const std::string& project, const std::string& wiki_id);
    AzureWikiPage update_wiki_page(const std::string& project, const std::string& wiki_id,
                                 const std::string& path, const std::string& content);
    bool delete_wiki_page(const std::string& project, const std::string& wiki_id, const std::string& path);

    // Board Management
    std::vector<AzureBoard> list_boards(const std::string& project, const std::string& team = "");
    AzureBoard get_board(const std::string& project, const std::string& team, const std::string& board_id);
    std::vector<AzureBoardColumn> list_board_columns(const std::string& project, const std::string& team,
                                                   const std::string& board_id);
    std::vector<AzureWorkItem> list_board_work_items(const std::string& project, const std::string& team,
                                                   const std::string& board_id, const std::string& column_id = "");

    // Iteration & Area Management
    std::vector<AzureIteration> list_iterations(const std::string& project, const std::string& team = "");
    AzureIteration get_iteration(const std::string& project, const std::string& team, const std::string& iteration_id);
    AzureIteration create_iteration(const std::string& project, const std::string& team,
                                  const std::string& name, const std::string& start_date = "",
                                  const std::string& finish_date = "");
    std::vector<AzureArea> list_areas(const std::string& project, const std::string& team = "");
    AzureArea get_area(const std::string& project, const std::string& team, const std::string& area_id);
    AzureArea create_area(const std::string& project, const std::string& team, const std::string& name);

    // Policy Management
    AzurePolicy create_policy(const std::string& project, const std::string& repository_id,
                            const std::string& type, const std::map<std::string, std::string>& configuration,
                            bool is_enabled = true, bool is_blocking = true);
    std::vector<AzurePolicy> list_policies(const std::string& project, const std::string& repository_id = "");
    AzurePolicy get_policy(const std::string& project, const std::string& policy_id);
    AzurePolicy update_policy(const std::string& project, const std::string& policy_id,
                            const std::map<std::string, std::string>& configuration = {},
                            bool is_enabled = true, bool is_blocking = true);
    bool delete_policy(const std::string& project, const std::string& policy_id);

    // Service Endpoints
    AzureServiceEndpoint create_service_endpoint(const std::string& project, const std::string& name,
                                               const std::string& type, const std::map<std::string, std::string>& authorization,
                                               const std::map<std::string, std::string>& data = {});
    std::vector<AzureServiceEndpoint> list_service_endpoints(const std::string& project);
    AzureServiceEndpoint get_service_endpoint(const std::string& project, const std::string& endpoint_id);
    bool delete_service_endpoint(const std::string& project, const std::string& endpoint_id);

    // Variable Groups
    AzureVariableGroup create_variable_group(const std::string& project, const std::string& name,
                                           const std::map<std::string, std::string>& variables,
                                           const std::string& description = "", bool is_shared = false);
    std::vector<AzureVariableGroup> list_variable_groups(const std::string& project);
    AzureVariableGroup get_variable_group(const std::string& project, const std::string& group_id);
    AzureVariableGroup update_variable_group(const std::string& project, const std::string& group_id,
                                           const std::map<std::string, std::string>& variables = {},
                                           const std::string& description = "", bool is_shared = false);
    bool delete_variable_group(const std::string& project, const std::string& group_id);

    // Deployment Groups
    AzureDeploymentGroup create_deployment_group(const std::string& project, const std::string& name,
                                              const std::string& description = "");
    std::vector<AzureDeploymentGroup> list_deployment_groups(const std::string& project);
    AzureDeploymentGroup get_deployment_group(const std::string& project, const std::string& group_id);
    bool delete_deployment_group(const std::string& project, const std::string& group_id);

    // Queries
    AzureQuery create_query(const std::string& project, const std::string& name, const std::string& wiql,
                          const std::string& query_type = "flat", bool is_public = false);
    std::vector<AzureQuery> list_queries(const std::string& project, const std::string& folder = "");
    AzureQuery get_query(const std::string& project, const std::string& query_id);
    std::vector<AzureWorkItem> execute_query(const std::string& project, const std::string& query_id);
    bool delete_query(const std::string& project, const std::string& query_id);

    // Notifications
    std::vector<AzureNotification> list_notifications(const std::string& project = "");
    AzureNotification get_notification(const std::string& notification_id);
    bool mark_notification_read(const std::string& notification_id);

    // Utility Methods
    std::string get_api_url(const std::string& endpoint) const;
    nlohmann::json api_get(const std::string& endpoint);
    nlohmann::json api_post(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_put(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_patch(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_delete(const std::string& endpoint);

private:
    AzureDevOpsConfig config_;
    std::mutex api_mutex_;
    std::map<std::string, nlohmann::json> cache_;
    
    // HTTP client implementation
    std::string make_request(const std::string& method, const std::string& url, 
                           const std::string& data = "");
    void handle_http_error(int status_code, const std::string& response);
    void update_rate_limits(const std::string& response_headers);
    
    // Cache management
    void cache_set(const std::string& key, const nlohmann::json& value);
    std::optional<nlohmann::json> cache_get(const std::string& key);
    void cache_clear();
    
    // Rate limiting
    struct RateLimit {
        int limit;
        int remaining;
        int reset_time;
    };
    
    std::map<std::string, RateLimit> rate_limits_;
    
    // Helper methods for data conversion
    AzureUser user_from_json(const nlohmann::json& json);
    AzureProject project_from_json(const nlohmann::json& json);
    AzureRepository repository_from_json(const nlohmann::json& json);
    AzurePullRequest pull_request_from_json(const nlohmann::json& json);
    AzureCommit commit_from_json(const nlohmann::json& json);
    AzureBranch branch_from_json(const nlohmann::json& json);
    AzureBuild build_from_json(const nlohmann::json& json);
    AzureRelease release_from_json(const nlohmann::json& json);
    AzureWorkItem work_item_from_json(const nlohmann::json& json);
    AzurePipeline pipeline_from_json(const nlohmann::json& json);
    AzureTestPlan test_plan_from_json(const nlohmann::json& json);
    AzureTestRun test_run_from_json(const nlohmann::json& json);
    AzureArtifact artifact_from_json(const nlohmann::json& json);
    AzureWiki wiki_from_json(const nlohmann::json& json);
    AzureWikiPage wiki_page_from_json(const nlohmann::json& json);
    AzureBoard board_from_json(const nlohmann::json& json);
    AzureBoardColumn board_column_from_json(const nlohmann::json& json);
    AzureIteration iteration_from_json(const nlohmann::json& json);
    AzureArea area_from_json(const nlohmann::json& json);
    AzurePolicy policy_from_json(const nlohmann::json& json);
    AzureServiceEndpoint service_endpoint_from_json(const nlohmann::json& json);
    AzureVariableGroup variable_group_from_json(const nlohmann::json& json);
    AzureDeploymentGroup deployment_group_from_json(const nlohmann::json& json);
    AzureTaskGroup task_group_from_json(const nlohmann::json& json);
    AzureQuery query_from_json(const nlohmann::json& json);
    AzureNotification notification_from_json(const nlohmann::json& json);
};

#endif // AZURE_DEVOPS_EXTENSION_H