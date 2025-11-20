export const CDNResolver = (function() {
    let config = null;
    let preferredCDN = null;
    
    async function loadConfig() {
        const res = await fetch("config/cdn_providers.json");
        config = await res.json();
        preferredCDN = config.preferred;
    }
    
    async function searchLibraries(query) {
        if (!config) await loadConfig();
        const provider = config.providers[preferredCDN];
        if (!provider) throw new Error(`Preferred CDN "${preferredCDN}" not found`);
        
        const searchUrl = provider.search.replace("{query}", encodeURIComponent(query));
        const res = await fetch(searchUrl);
        const data = await res.json();
        
        if (preferredCDN === "cdnjs") return data.results.map(lib => ({
            name: lib.name,
            version: lib.version,
            latestFile: lib.latest
        }));
        else return data.objects.map(obj => ({
            name: obj.package.name,
            version: obj.package.version,
            description: obj.package.description
        }));
    }
    
    async function getLibraryFiles(pkg, version = null) {
        if (!config) await loadConfig();
        const provider = config.providers[preferredCDN];
        if (!version) version = provider.default_version;
        
        const metadataUrl = provider.metadata
            .replace("{package}", pkg)
            .replace("{version}", version);
        
        const res = await fetch(metadataUrl);
        const data = await res.json();
        
        let files = [];
        if (preferredCDN === "cdnjs") {
            files = data.assets.flatMap(asset => asset.files || []);
        } else if (preferredCDN === "jsdelivr") {
            const traverse = f => {
                let arr = [];
                if (f.files) {
                    f.files.forEach(sub => arr.push(...traverse(sub)));
                } else if (f.name) {
                    arr.push(f.name);
                }
                return arr;
            };
            files = traverse(data.files);
        } else if (preferredCDN === "unpkg") {
            files = Object.keys(data.files || {});
        }
        return files;
    }
    
    function resolveFile(files, type = "js") {
        const rules = config.providers[preferredCDN].default_file_rules.filter(r => r.type === type);
        for (const rule of rules) {
            const pattern = new RegExp(rule.pattern.replace("*", ".*"));
            const match = files.find(f => pattern.test(f));
            if (match) return match;
        }
        return rules.length && rules[0].fallback ? rules[0].fallback : files[0];
    }
    
    async function downloadLibrary(pkg, type = "js", version = null) {
        const files = await getLibraryFiles(pkg, version);
        const fileToDownload = resolveFile(files, type);
        
        const provider = config.providers[preferredCDN];
        const url = provider.url_pattern
            .replace("{package}", pkg)
            .replace("{version}", version || provider.default_version)
            .replace("{file}", fileToDownload);
        
        const res = await fetch(url);
        const content = await res.text();
        
        const path = `/project/libs/${fileToDownload.split("/").pop()}`;
        await NativeFS.writeFile(path, content);
        
        if (typeof CDNAutoInjector !== "undefined") {
            CDNAutoInjector.inject(path, type);
        }
        
        return { path, url };
    }
    
    return {
        setup: loadConfig,
        search: searchLibraries,
        fetch: downloadLibrary
    };
})();