import os
from PyInstaller.__main__ import run

if __name__ == "__main__":
    
    script_path = r"C:\your\path\to\main.py"
    
    if not os.path.isfile(script_path):
        print(f"ERROR: The script '{script_path}' is not existing.")
    else:
        script_dir = os.path.dirname(script_path)
        
        opts = ['--onefile', '--noconsole', '--distpath', script_dir, script_path]

        run(opts)
