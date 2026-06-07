import json
from pathlib import Path

def generate_id(category: str, filename: str) -> str:
    """Generate clean ID (e.g. lua_p2jb, pl_kstuff)"""
    stem = Path(filename).stem.lower()
    stem = stem.replace(" ", "_").replace("-", "_").replace(".", "_")
    prefix = category.lower()
    return f"{prefix}_{stem}" if not stem.startswith(prefix) else stem

def get_display_name(filename: str) -> str:
    """Generate nice display name"""
    name = Path(filename).stem
    name = name.replace("_", " ").replace("-", " ").strip()
    return name.title()

def scan_directory(directory: str, category: str):
    entries = []
    base_path = Path(directory).resolve()  # Use resolve() for absolute path
    
    if not base_path.exists():
        print(f"⚠️ Directory {directory} not found, skipping...")
        return entries
        
    for file in sorted(base_path.rglob("*")):
        if file.is_file():
            # Get relative path from repo root safely
            repo_root = Path.cwd().resolve()
            rel_path = file.resolve().relative_to(repo_root)
            
            entry = {
                "id": generate_id(category, file.name),
                "name": get_display_name(file.name),
                "file": str(rel_path).replace("\\", "/")
            }
            entries.append(entry)
    
    return entries

def main():
    manifest = {
        "luac0re": scan_directory("LuaC0re", "lua"),
        "y2jb": scan_directory("Y2JB", "y2"),
        "lua": scan_directory("LUA", "lu"),
        "Yarp2jb": scan_directory("YarP2JB", "py"),
        "payloads": scan_directory("Payloads", "pl")
    }

    with open("manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    
    print("✅ manifest.json successfully generated!")
    print(f"   luac0re: {len(manifest['luac0re'])} entries")
    print(f"   y2jb:    {len(manifest['y2jb'])} entries")
    print(f"   payloads: {len(manifest['payloads'])} entries")

if __name__ == "__main__":
    main()
