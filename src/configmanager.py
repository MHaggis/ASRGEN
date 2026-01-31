"""
Configuration Manager - Save/Load ASR Configurations
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class ConfigManager:
    """Manage saving and loading ASR configurations"""
    
    CONFIG_DIR = Path(".asrgen_configs")
    
    @classmethod
    def ensure_config_dir(cls) -> None:
        """Ensure config directory exists"""
        cls.CONFIG_DIR.mkdir(exist_ok=True)
    
    @classmethod
    def save_config(
        cls,
        config: Dict[str, Dict],
        name: str,
        description: str = ""
    ) -> str:
        """
        Save a configuration to disk
        
        Args:
            config: ASR configuration dict
            name: Friendly name for the config
            description: Optional description
            
        Returns:
            Path to saved file
        """
        cls.ensure_config_dir()
        
        # Sanitize filename
        safe_name = "".join(c for c in name if c.isalnum() or c in (' ', '_', '-')).strip()
        filename = f"{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = cls.CONFIG_DIR / filename
        
        config_data = {
            "name": name,
            "description": description,
            "created": datetime.now().isoformat(),
            "config": config
        }
        
        with open(filepath, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        return str(filepath)
    
    @classmethod
    def load_config(cls, filepath: str) -> Optional[Dict]:
        """
        Load a configuration from disk
        
        Args:
            filepath: Path to config file
            
        Returns:
            Configuration dict or None if not found
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return data.get("config")
        except (FileNotFoundError, json.JSONDecodeError):
            return None
    
    @classmethod
    def list_configs(cls) -> List[Dict]:
        """
        List all saved configurations
        
        Returns:
            List of config metadata (name, description, path, created)
        """
        cls.ensure_config_dir()
        
        configs = []
        for filepath in sorted(cls.CONFIG_DIR.glob("*.json"), reverse=True):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                configs.append({
                    "name": data.get("name", filepath.stem),
                    "description": data.get("description", ""),
                    "created": data.get("created", "Unknown"),
                    "path": str(filepath),
                    "filename": filepath.name
                })
            except json.JSONDecodeError:
                continue
        
        return configs
    
    @classmethod
    def delete_config(cls, filepath: str) -> bool:
        """
        Delete a saved configuration
        
        Args:
            filepath: Path to config file
            
        Returns:
            True if deleted, False if not found
        """
        try:
            Path(filepath).unlink()
            return True
        except FileNotFoundError:
            return False
    
    @classmethod
    def export_config_as_json(cls, config: Dict[str, Dict]) -> str:
        """
        Export config as JSON string (for copying/pasting)
        
        Args:
            config: Configuration dict
            
        Returns:
            JSON string
        """
        return json.dumps(config, indent=2)
    
    @classmethod
    def import_config_from_json(cls, json_str: str) -> Optional[Dict]:
        """
        Import config from JSON string
        
        Args:
            json_str: JSON string to import
            
        Returns:
            Configuration dict or None if invalid
        """
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return None
