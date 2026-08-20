use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const DEFAULT_TYPE_MAPS_PATH: &str = "./type-maps.yaml";

#[derive(Deserialize)]
struct Config {
    #[allow(dead_code)]
    protocol_version: String,
    type_maps: BTreeMap<String, TypeMapConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TypeMapConfig {
    #[serde(default)]
    communication_types: BTreeMap<String, u16>,
    #[serde(default)]
    data_types: BTreeMap<String, u16>,
}

#[derive(Deserialize)]
struct ReservedManifest {
    #[serde(rename = "firstUserTypeId")]
    first_user_type_id: u16,
    communication: Vec<ManifestEntry>,
    data: Vec<ManifestEntry>,
}

#[derive(Deserialize)]
struct ManifestEntry {
    name: String,
    id: u16,
}

fn reserved_manifest() -> &'static ReservedManifest {
    static MANIFEST: OnceLock<ReservedManifest> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        serde_yaml::from_str(include_str!("reserved.json"))
            .expect("type-map/reserved.json must be valid JSON/YAML")
    })
}

fn first_user_type_id() -> u16 {
    reserved_manifest().first_user_type_id
}

fn all_reserved_comm_types() -> &'static [ManifestEntry] {
    &reserved_manifest().communication
}

fn generated_reserved_comm_types() -> Vec<&'static ManifestEntry> {
    all_reserved_comm_types()
        .iter()
        .filter(|entry| cfg!(feature = "pipes") || !entry.name.starts_with("Pipe"))
        .collect()
}

fn all_reserved_data_types() -> &'static [ManifestEntry] {
    &reserved_manifest().data
}

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let multi_version = std::env::var("CARGO_FEATURE_REGISTRY").is_ok();

    println!("cargo:rerun-if-env-changed=MTP_TYPE_MAPS");
    println!("cargo:rerun-if-changed=reserved.json");
    validate_reserved_manifest();

    let loaded = match std::env::var_os("MTP_TYPE_MAPS") {
        Some(config_path) => load_config(&PathBuf::from(config_path)),
        None => {
            let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
            let default_path = manifest_dir.join(DEFAULT_TYPE_MAPS_PATH);
            if default_path.exists() {
                load_config(&default_path)
            } else {
                println!(
                    "cargo:warning=MTP_TYPE_MAPS not set; generating types with reserved entries only"
                );
                LoadedConfig {
                    config: Config {
                        protocol_version: String::new(),
                        type_maps: BTreeMap::new(),
                    },
                    path: None,
                    content: String::new(),
                }
            }
        }
    };

    validate_config(&loaded);
    let code = generate(&loaded.config, multi_version);
    std::fs::write(out.join("types.rs"), code).unwrap();
}

fn validate_reserved_manifest() {
    assert!(first_user_type_id() > 0);
    for (category, entries) in [
        ("communication", all_reserved_comm_types()),
        ("data", all_reserved_data_types()),
    ] {
        let mut names = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for entry in entries {
            assert!(
                entry.id < first_user_type_id(),
                "reserved {category} type {} has a user-range ID {}",
                entry.name,
                entry.id
            );
            assert!(
                names.insert(entry.name.as_str()),
                "duplicate reserved {category} type name {}",
                entry.name
            );
            assert!(
                ids.insert(entry.id),
                "duplicate reserved {category} type ID {}",
                entry.id
            );
        }
    }
}

struct LoadedConfig {
    config: Config,
    path: Option<PathBuf>,
    content: String,
}

fn load_config(path: &Path) -> LoadedConfig {
    let path = path.canonicalize().unwrap_or_else(|error| {
        panic!(
            "failed to resolve type-map file {}: {error}",
            path.display()
        )
    });
    println!("cargo:rerun-if-changed={}", path.display());

    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read type-map file {}: {error}", path.display()));
    let config = serde_yaml::from_str(&content).unwrap_or_else(|error| {
        if let Some(location) = error.location() {
            panic!(
                "{}:{}:{}: failed to parse type-map YAML: {error}",
                path.display(),
                location.line(),
                location.column()
            );
        }
        panic!("{}: failed to parse type-map YAML: {error}", path.display());
    });

    LoadedConfig {
        config,
        path: Some(path),
        content,
    }
}

fn validate_config(loaded: &LoadedConfig) {
    if loaded.path.is_none() {
        return;
    }

    validate_version(
        loaded,
        "protocol_version",
        &loaded.config.protocol_version,
        &[],
        "protocol_version",
    );
    for (version, type_map) in &loaded.config.type_maps {
        validate_version(
            loaded,
            "type_maps version",
            version,
            &["type_maps"],
            version,
        );
        validate_ids(
            loaded,
            version,
            "CommunicationTypes",
            &type_map.communication_types,
            all_reserved_comm_types(),
        );
        validate_ids(
            loaded,
            version,
            "DataTypes",
            &type_map.data_types,
            all_reserved_data_types(),
        );
    }
}

fn validate_version(
    loaded: &LoadedConfig,
    kind: &str,
    version: &str,
    parents: &[&str],
    yaml_key: &str,
) {
    if parse_version(version).is_none() {
        validation_error(
            loaded,
            parents,
            yaml_key,
            format!("invalid {kind} {version:?}; expected '<u16>.<u16>'"),
        );
    }
}

fn validate_ids(
    loaded: &LoadedConfig,
    version: &str,
    category: &str,
    entries: &BTreeMap<String, u16>,
    reserved: &[ManifestEntry],
) {
    let mut names_by_id = BTreeMap::new();
    for (name, id) in entries {
        if reserved.iter().any(|entry| entry.name == *name) {
            validation_error(
                loaded,
                &["type_maps", version, category],
                name,
                format!(
                    "{category}.{name} in type-map version {version} uses reserved name {name:?}"
                ),
            );
        }
        if *id < first_user_type_id() {
            validation_error(
                loaded,
                &["type_maps", version, category],
                name,
                format!(
                    "{category}.{name} in type-map version {version} uses reserved id {id}; user ids must be {} or greater",
                    first_user_type_id()
                ),
            );
        }

        if let Some(previous_name) = names_by_id.insert(*id, name) {
            validation_error(
                loaded,
                &["type_maps", version, category],
                name,
                format!(
                    "duplicate id {id} in {category} for type-map version {version}: {previous_name} and {name}"
                ),
            );
        }
    }
}

fn validation_error(loaded: &LoadedConfig, parents: &[&str], yaml_key: &str, message: String) -> ! {
    let path = loaded
        .path
        .as_deref()
        .expect("validated configs have a path");
    let line = yaml_key_line(&loaded.content, parents, yaml_key).unwrap_or(1);
    panic!("{}:{line}: {message}", path.display());
}

fn yaml_key_line(content: &str, parents: &[&str], key: &str) -> Option<usize> {
    let mut stack: Vec<(usize, &str)> = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let Some((indent, candidate)) = yaml_line_key(line) else {
            continue;
        };
        while stack.last().is_some_and(|(level, _)| *level >= indent) {
            stack.pop();
        }
        if candidate == key
            && stack.len() == parents.len()
            && stack
                .iter()
                .map(|(_, parent)| *parent)
                .eq(parents.iter().copied())
        {
            return Some(index + 1);
        }
        stack.push((indent, candidate));
    }
    None
}

fn yaml_line_key(line: &str) -> Option<(usize, &str)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    let line = line.get(indent..)?.split('#').next()?.trim_end();
    if line.is_empty() {
        return None;
    }
    let (key, _) = line.split_once(':')?;
    Some((indent, key.trim().trim_matches(['\'', '"'])))
}

fn parse_version(version: &str) -> Option<(u16, u16)> {
    let (major, minor) = version.split_once('.')?;
    if major.is_empty() || minor.is_empty() || minor.contains('.') {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn sorted_versions(config: &Config) -> Vec<(String, u16, u16)> {
    let mut versions: Vec<(String, u16, u16)> = config
        .type_maps
        .keys()
        .filter_map(|k| {
            let parts: Vec<&str> = k.split('.').collect();
            if parts.len() == 2 {
                let major = parts[0].parse::<u16>().ok()?;
                let minor = parts[1].parse::<u16>().ok()?;
                Some((k.clone(), major, minor))
            } else {
                None
            }
        })
        .collect();
    versions.sort_by_key(|(_, major, minor)| (*major, *minor));
    versions
}

fn generate(config: &Config, multi_version: bool) -> String {
    let mut out = String::new();
    writeln!(
        out,
        "// Auto-generated by type-map/build.rs, this file should not be edited manually"
    )
    .unwrap();
    writeln!(out).unwrap();

    let (all_comm_names, all_data_names, sorted) = if multi_version {
        let mut all_comm_names: BTreeSet<&str> = BTreeSet::new();
        let mut all_data_names: BTreeSet<&str> = BTreeSet::new();
        for tm in config.type_maps.values() {
            for name in tm.communication_types.keys() {
                all_comm_names.insert(name.as_str());
            }
            for name in tm.data_types.keys() {
                all_data_names.insert(name.as_str());
            }
        }
        let sorted = sorted_versions(config);
        (all_comm_names, all_data_names, sorted)
    } else {
        let mut all_comm_names: BTreeSet<&str> = BTreeSet::new();
        let mut all_data_names: BTreeSet<&str> = BTreeSet::new();
        if let Some(tm) = config.type_maps.get(&config.protocol_version) {
            for name in tm.communication_types.keys() {
                all_comm_names.insert(name.as_str());
            }
            for name in tm.data_types.keys() {
                all_data_names.insert(name.as_str());
            }
        }
        (all_comm_names, all_data_names, vec![])
    };

    generate_protocol_version(&mut out, config);
    generate_comm_type_enum(&mut out, &all_comm_names);
    generate_data_type_enum(&mut out, &all_data_names);
    generate_latest_method(&mut out, config);

    if multi_version {
        generate_versioned_constructors(&mut out, &sorted);
        generate_builtin_type_maps(&mut out, &sorted);
        generate_lookup_methods(&mut out, config, &sorted);
        generate_all_types_methods(&mut out, config, &sorted);
    } else {
        generate_single_version_lookup(&mut out, config);
        generate_all_types_methods_single(&mut out, config);
    }

    generate_enum_conversion_methods(&mut out);
    generate_id_display_impls(&mut out);

    out
}

fn generate_protocol_version(out: &mut String, config: &Config) {
    let (major, minor) = parse_protocol_version(&config.protocol_version);
    writeln!(
        out,
        "pub const PROTOCOL_VERSION: Version = Version({}, {});",
        major, minor
    )
    .unwrap();
    writeln!(out).unwrap();
}

fn generate_latest_method(out: &mut String, config: &Config) {
    let (major, minor) = parse_protocol_version(&config.protocol_version);
    writeln!(out, "impl TypeMap {{").unwrap();
    writeln!(out, "    pub fn latest() -> Self {{").unwrap();
    writeln!(
        out,
        "        Self {{ version: Version({}, {}) }}",
        major, minor
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl TypeMap {{").unwrap();
    writeln!(
        out,
        "    pub fn communication_type_name(&self, id: u16) -> Option<&'static str> {{"
    )
    .unwrap();
    writeln!(
        out,
        "        self.comm_enum_id(id).map(CommunicationType::name)"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(
        out,
        "    pub fn data_type_name(&self, id: u16) -> Option<&'static str> {{"
    )
    .unwrap();
    writeln!(out, "        self.data_enum_id(id).map(DataType::name)").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn parse_protocol_version(version: &str) -> (u16, u16) {
    let Some((major, minor)) = version.split_once('.') else {
        return (0, 0);
    };

    (
        major.parse::<u16>().unwrap_or(0),
        minor.parse::<u16>().unwrap_or(0),
    )
}

fn generate_comm_type_enum(out: &mut String, user_names: &BTreeSet<&str>) {
    writeln!(
        out,
        "#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]"
    )
    .unwrap();
    writeln!(out, "#[allow(clippy::enum_variant_names)]").unwrap();
    writeln!(out, "pub enum CommunicationType {{").unwrap();

    for entry in generated_reserved_comm_types() {
        writeln!(out, "    {},", entry.name).unwrap();
    }
    for name in user_names {
        writeln!(out, "    {},", name).unwrap();
    }

    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl CommunicationType {{").unwrap();
    writeln!(out, "    pub fn name(self) -> &'static str {{").unwrap();
    writeln!(out, "        match self {{").unwrap();

    for entry in generated_reserved_comm_types() {
        writeln!(
            out,
            "            CommunicationType::{} => \"{}\",",
            entry.name, entry.name
        )
        .unwrap();
    }
    for name in user_names {
        writeln!(
            out,
            "            CommunicationType::{} => \"{}\",",
            name, name
        )
        .unwrap();
    }

    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl CommunicationType {{").unwrap();
    writeln!(out, "    pub fn from_name(s: &str) -> Option<Self> {{").unwrap();
    writeln!(out, "        match s {{").unwrap();

    for entry in generated_reserved_comm_types() {
        writeln!(
            out,
            "            \"{}\" => Some(CommunicationType::{}),",
            entry.name, entry.name
        )
        .unwrap();
    }
    for name in user_names {
        writeln!(
            out,
            "            \"{}\" => Some(CommunicationType::{}),",
            name, name
        )
        .unwrap();
    }

    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl std::fmt::Display for CommunicationType {{").unwrap();
    writeln!(
        out,
        "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{"
    )
    .unwrap();
    writeln!(out, "        f.write_str(self.name())").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn generate_data_type_enum(out: &mut String, user_names: &BTreeSet<&str>) {
    writeln!(out, "/// Data type identifier; compile-time checked.").unwrap();
    writeln!(
        out,
        "#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]"
    )
    .unwrap();
    writeln!(out, "#[allow(clippy::enum_variant_names)]").unwrap();
    writeln!(out, "pub enum DataType {{").unwrap();

    for entry in all_reserved_data_types() {
        writeln!(out, "    {},", entry.name).unwrap();
    }
    for name in user_names {
        writeln!(out, "    {},", name).unwrap();
    }

    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl DataType {{").unwrap();
    writeln!(out, "    pub fn name(self) -> &'static str {{").unwrap();
    writeln!(out, "        match self {{").unwrap();

    for entry in all_reserved_data_types() {
        writeln!(
            out,
            "            DataType::{} => \"{}\",",
            entry.name, entry.name
        )
        .unwrap();
    }
    for name in user_names {
        writeln!(out, "            DataType::{} => \"{}\",", name, name).unwrap();
    }

    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl DataType {{").unwrap();
    writeln!(out, "    pub fn from_name(s: &str) -> Option<Self> {{").unwrap();
    writeln!(out, "        match s {{").unwrap();

    for entry in all_reserved_data_types() {
        writeln!(
            out,
            "            \"{}\" => Some(DataType::{}),",
            entry.name, entry.name
        )
        .unwrap();
    }
    for name in user_names {
        writeln!(out, "            \"{}\" => Some(DataType::{}),", name, name).unwrap();
    }

    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl std::fmt::Display for DataType {{").unwrap();
    writeln!(
        out,
        "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{"
    )
    .unwrap();
    writeln!(out, "        f.write_str(self.name())").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn generate_versioned_constructors(out: &mut String, sorted_versions: &[(String, u16, u16)]) {
    for (version_key, _major, _minor) in sorted_versions {
        let version_ident = version_key.replace('.', "_");

        writeln!(out, "impl TypeMap {{").unwrap();
        writeln!(out, "    pub fn v{}() -> Self {{", version_ident).unwrap();

        let parts: Vec<&str> = version_key.split('.').collect();
        let major = parts[0];
        let minor = parts[1];
        writeln!(
            out,
            "        Self {{ version: Version({}, {}) }}",
            major, minor
        )
        .unwrap();
        writeln!(out, "    }}").unwrap();
        writeln!(out, "}}").unwrap();
        writeln!(out).unwrap();
    }
}

fn generate_lookup_methods(
    out: &mut String,
    config: &Config,
    sorted_versions: &[(String, u16, u16)],
) {
    writeln!(out, "#[allow(unreachable_patterns, unused_variables)]").unwrap();
    writeln!(out, "impl TypeMap {{").unwrap();
    writeln!(
        out,
        "    pub fn comm_id_enum(&self, ct: CommunicationType) -> Option<u16> {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    for (version_key, major, minor) in sorted_versions {
        let tm_cfg = &config.type_maps[version_key];
        writeln!(
            out,
            "            Version({}, {}) => match ct {{",
            major, minor
        )
        .unwrap();
        for entry in generated_reserved_comm_types() {
            writeln!(
                out,
                "                CommunicationType::{} => Some({}),",
                entry.name, entry.id
            )
            .unwrap();
        }
        for (name, id) in &tm_cfg.communication_types {
            writeln!(
                out,
                "                CommunicationType::{} => Some({}),",
                name, id
            )
            .unwrap();
        }
        writeln!(out, "                _ => None,").unwrap();
        writeln!(out, "            }},").unwrap();
    }
    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "    #[allow(unused_variables)]").unwrap();
    writeln!(
        out,
        "    pub fn data_id_enum(&self, dt: DataType) -> Option<u16> {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    for (version_key, major, minor) in sorted_versions {
        let tm_cfg = &config.type_maps[version_key];
        writeln!(
            out,
            "            Version({}, {}) => match dt {{",
            major, minor
        )
        .unwrap();
        for entry in all_reserved_data_types() {
            writeln!(
                out,
                "                DataType::{} => Some({}),",
                entry.name, entry.id
            )
            .unwrap();
        }
        for (name, id) in &tm_cfg.data_types {
            writeln!(out, "                DataType::{} => Some({}),", name, id).unwrap();
        }
        writeln!(out, "                _ => None,").unwrap();
        writeln!(out, "            }},").unwrap();
    }
    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // Reverse lookups: wire ID → enum variant (version-aware)
    writeln!(
        out,
        "    pub fn comm_enum_id(&self, id: u16) -> Option<CommunicationType> {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    for (version_key, major, minor) in sorted_versions {
        let tm_cfg = &config.type_maps[version_key];
        writeln!(
            out,
            "            Version({}, {}) => match id {{",
            major, minor
        )
        .unwrap();
        for entry in generated_reserved_comm_types() {
            writeln!(
                out,
                "                {} => Some(CommunicationType::{}),",
                entry.id, entry.name
            )
            .unwrap();
        }
        for (name, id) in &tm_cfg.communication_types {
            writeln!(
                out,
                "                {} => Some(CommunicationType::{}),",
                id, name
            )
            .unwrap();
        }
        writeln!(out, "                _ => None,").unwrap();
        writeln!(out, "            }},").unwrap();
    }
    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    pub fn data_enum_id(&self, id: u16) -> Option<DataType> {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    for (version_key, major, minor) in sorted_versions {
        let tm_cfg = &config.type_maps[version_key];
        writeln!(
            out,
            "            Version({}, {}) => match id {{",
            major, minor
        )
        .unwrap();
        for entry in all_reserved_data_types() {
            writeln!(
                out,
                "                {} => Some(DataType::{}),",
                entry.id, entry.name
            )
            .unwrap();
        }
        for (name, id) in &tm_cfg.data_types {
            writeln!(out, "                {} => Some(DataType::{}),", id, name).unwrap();
        }
        writeln!(out, "                _ => None,").unwrap();
        writeln!(out, "            }},").unwrap();
    }
    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn generate_single_version_lookup(out: &mut String, config: &Config) {
    let tm_cfg = config.type_maps.get(&config.protocol_version);

    writeln!(out, "#[allow(unreachable_patterns, unused_variables)]").unwrap();
    writeln!(out, "impl TypeMap {{").unwrap();
    writeln!(
        out,
        "    pub fn comm_id_enum(&self, ct: CommunicationType) -> Option<u16> {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    writeln!(out, "            PROTOCOL_VERSION => match ct {{").unwrap();
    for entry in generated_reserved_comm_types() {
        writeln!(
            out,
            "                CommunicationType::{} => Some({}),",
            entry.name, entry.id
        )
        .unwrap();
    }
    if let Some(tm_cfg) = tm_cfg {
        for (name, id) in &tm_cfg.communication_types {
            writeln!(
                out,
                "                CommunicationType::{} => Some({}),",
                name, id
            )
            .unwrap();
        }
    }
    writeln!(out, "                _ => None,").unwrap();
    writeln!(out, "            }},").unwrap();
    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "    #[allow(unused_variables)]").unwrap();
    writeln!(
        out,
        "    pub fn data_id_enum(&self, dt: DataType) -> Option<u16> {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    writeln!(out, "            PROTOCOL_VERSION => match dt {{").unwrap();
    for entry in all_reserved_data_types() {
        writeln!(
            out,
            "                DataType::{} => Some({}),",
            entry.name, entry.id
        )
        .unwrap();
    }
    if let Some(tm_cfg) = tm_cfg {
        for (name, id) in &tm_cfg.data_types {
            writeln!(out, "                DataType::{} => Some({}),", name, id).unwrap();
        }
    }
    writeln!(out, "                _ => None,").unwrap();
    writeln!(out, "            }},").unwrap();
    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // Reverse lookups: wire ID → enum variant (single version)
    writeln!(
        out,
        "    pub fn comm_enum_id(&self, id: u16) -> Option<CommunicationType> {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    writeln!(out, "            PROTOCOL_VERSION => match id {{").unwrap();
    for entry in generated_reserved_comm_types() {
        writeln!(
            out,
            "                {} => Some(CommunicationType::{}),",
            entry.id, entry.name
        )
        .unwrap();
    }
    if let Some(tm_cfg) = tm_cfg {
        for (name, id) in &tm_cfg.communication_types {
            writeln!(
                out,
                "                {} => Some(CommunicationType::{}),",
                id, name
            )
            .unwrap();
        }
    }
    writeln!(out, "                _ => None,").unwrap();
    writeln!(out, "            }},").unwrap();
    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    pub fn data_enum_id(&self, id: u16) -> Option<DataType> {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    writeln!(out, "            PROTOCOL_VERSION => match id {{").unwrap();
    for entry in all_reserved_data_types() {
        writeln!(
            out,
            "                {} => Some(DataType::{}),",
            entry.id, entry.name
        )
        .unwrap();
    }
    if let Some(tm_cfg) = tm_cfg {
        for (name, id) in &tm_cfg.data_types {
            writeln!(out, "                {} => Some(DataType::{}),", id, name).unwrap();
        }
    }
    writeln!(out, "                _ => None,").unwrap();
    writeln!(out, "            }},").unwrap();
    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn generate_builtin_type_maps(out: &mut String, sorted_versions: &[(String, u16, u16)]) {
    writeln!(out, "pub fn builtin_type_maps() -> Vec<TypeMap> {{").unwrap();
    writeln!(out, "    vec![").unwrap();
    for (version_key, _major, _minor) in sorted_versions {
        let ident = version_key.replace('.', "_");
        writeln!(out, "        TypeMap::v{}(),", ident).unwrap();
    }
    writeln!(out, "    ]").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn generate_enum_conversion_methods(out: &mut String) {
    writeln!(out, "impl CommunicationType {{").unwrap();
    writeln!(
        out,
        "    pub fn try_to_id(self, tm: &TypeMap) -> Option<CommunicationTypeId> {{"
    )
    .unwrap();
    writeln!(
        out,
        "        tm.comm_id_enum(self).map(CommunicationTypeId)"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(
        out,
        "    #[deprecated(since = \"0.2.0\", note = \"use try_to_id to handle types absent from a TypeMap version\")]"
    )
    .unwrap();
    writeln!(
        out,
        "    pub fn to_id(self, tm: &TypeMap) -> CommunicationTypeId {{"
    )
    .unwrap();
    writeln!(
        out,
        "        CommunicationTypeId(tm.comm_id_enum(self).expect(\"CommunicationType not found in this TypeMap version\"))"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl DataType {{").unwrap();
    writeln!(
        out,
        "    pub fn try_to_id(self, tm: &TypeMap) -> Option<DataTypeId> {{"
    )
    .unwrap();
    writeln!(out, "        tm.data_id_enum(self).map(DataTypeId)").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(
        out,
        "    #[deprecated(since = \"0.2.0\", note = \"use try_to_id to handle types absent from a TypeMap version\")]"
    )
    .unwrap();
    writeln!(out, "    pub fn to_id(self, tm: &TypeMap) -> DataTypeId {{").unwrap();
    writeln!(
        out,
        "        DataTypeId(tm.data_id_enum(self).expect(\"DataType not found in this TypeMap version\"))"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn generate_all_types_methods(
    out: &mut String,
    config: &Config,
    sorted_versions: &[(String, u16, u16)],
) {
    writeln!(out, "#[allow(unreachable_patterns)]").unwrap();
    writeln!(out, "impl TypeMap {{").unwrap();
    writeln!(
        out,
        "    pub fn all_comm_types(&self) -> &'static [CommunicationType] {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    for (version_key, major, minor) in sorted_versions {
        let tm_cfg = &config.type_maps[version_key];
        write!(out, "            Version({}, {}) => &[", major, minor).unwrap();
        let mut first = true;
        for entry in generated_reserved_comm_types() {
            if !first {
                write!(out, ", ").unwrap();
            }
            write!(out, "CommunicationType::{}", entry.name).unwrap();
            first = false;
        }
        for name in tm_cfg.communication_types.keys() {
            if !first {
                write!(out, ", ").unwrap();
            }
            write!(out, "CommunicationType::{}", name).unwrap();
            first = false;
        }
        writeln!(out, "],").unwrap();
    }
    writeln!(out, "            _ => &[],").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    pub fn all_data_types(&self) -> &'static [DataType] {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    for (version_key, major, minor) in sorted_versions {
        let tm_cfg = &config.type_maps[version_key];
        write!(out, "            Version({}, {}) => &[", major, minor).unwrap();
        let mut first = true;
        for entry in all_reserved_data_types() {
            if !first {
                write!(out, ", ").unwrap();
            }
            write!(out, "DataType::{}", entry.name).unwrap();
            first = false;
        }
        for name in tm_cfg.data_types.keys() {
            if !first {
                write!(out, ", ").unwrap();
            }
            write!(out, "DataType::{}", name).unwrap();
            first = false;
        }
        writeln!(out, "],").unwrap();
    }
    writeln!(out, "            _ => &[],").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn generate_all_types_methods_single(out: &mut String, config: &Config) {
    let tm_cfg = config.type_maps.get(&config.protocol_version);

    writeln!(out, "#[allow(unreachable_patterns)]").unwrap();
    writeln!(out, "impl TypeMap {{").unwrap();
    writeln!(
        out,
        "    pub fn all_comm_types(&self) -> &'static [CommunicationType] {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    write!(out, "            PROTOCOL_VERSION => &[").unwrap();
    let mut first = true;
    for entry in generated_reserved_comm_types() {
        if !first {
            write!(out, ", ").unwrap();
        }
        write!(out, "CommunicationType::{}", entry.name).unwrap();
        first = false;
    }
    if let Some(tm_cfg) = tm_cfg {
        for name in tm_cfg.communication_types.keys() {
            if !first {
                write!(out, ", ").unwrap();
            }
            write!(out, "CommunicationType::{}", name).unwrap();
            first = false;
        }
    }
    writeln!(out, "],").unwrap();
    writeln!(out, "            _ => &[],").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    pub fn all_data_types(&self) -> &'static [DataType] {{"
    )
    .unwrap();
    writeln!(out, "        match self.version {{").unwrap();
    write!(out, "            PROTOCOL_VERSION => &[").unwrap();
    let mut first = true;
    for entry in all_reserved_data_types() {
        if !first {
            write!(out, ", ").unwrap();
        }
        write!(out, "DataType::{}", entry.name).unwrap();
        first = false;
    }
    if let Some(tm_cfg) = tm_cfg {
        for name in tm_cfg.data_types.keys() {
            if !first {
                write!(out, ", ").unwrap();
            }
            write!(out, "DataType::{}", name).unwrap();
            first = false;
        }
    }
    writeln!(out, "],").unwrap();
    writeln!(out, "            _ => &[],").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn generate_id_display_impls(out: &mut String) {
    writeln!(out, "impl std::fmt::Display for CommunicationTypeId {{").unwrap();
    writeln!(
        out,
        "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{"
    )
    .unwrap();
    writeln!(out, "        write!(f, \"CommTypeId({{}})\", self.0)").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl std::fmt::Display for DataTypeId {{").unwrap();
    writeln!(
        out,
        "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{"
    )
    .unwrap();
    writeln!(out, "        write!(f, \"DataTypeId({{}})\", self.0)").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}
