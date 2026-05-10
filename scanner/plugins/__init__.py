import os
import importlib.util
from typing import List, Dict

class PluginBase:
    """
    Base class for all OWASP Mini-Scanner plugins.
    Custom checks should inherit from this class and implement the run() method.
    """
    def run(self, report_data: dict) -> List[Dict]:
        """
        Execute plugin check. 
        :param report_data: Dictionary containing 'url', 'status_code', 'headers', 'body', 'cookies', 'forms'
        :return: List of Finding dictionaries
        """
        raise NotImplementedError("Plugins must implement the run() method.")

def load_plugins() -> List[PluginBase]:
    """
    Discovers Python files in scanner/plugins/ directory,
    imports them dynamically, and instantiates PluginBase subclasses.
    """
    plugins = []
    
    # Get the directory of this __init__.py file
    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    
    for filename in os.listdir(plugin_dir):
        if filename.endswith(".py") and filename != "__init__.py":
            module_name = f"scanner.plugins.{filename[:-3]}"
            file_path = os.path.join(plugin_dir, filename)
            
            try:
                # Load the module dynamically
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Find and instantiate classes inheriting from PluginBase
                    for attribute_name in dir(module):
                        attribute = getattr(module, attribute_name)
                        
                        # Check if it's a class, inherits from PluginBase, but isn't PluginBase itself
                        if isinstance(attribute, type) and issubclass(attribute, PluginBase) and attribute is not PluginBase:
                            # Instantiate the plugin and add to list
                            plugins.append(attribute())
            except Exception as e:
                # We log or print exception in real-world, but for now we continue
                print(f"Error loading plugin {filename}: {e}")
                
    return plugins
