import os
from PyInstaller.__main__ import run

if __name__ == "__main__":
    # Pfad zum Python-Skript
    script_path = r"C:\Users\proCom\Desktop\decryptesfmfile\esfm_decryption.py"

    # Überprüfe, ob das Skript existiert
    if not os.path.isfile(script_path):
        print(f"Fehler: Das Skript '{script_path}' existiert nicht.")
    else:
        # Verzeichnis des Skripts
        script_dir = os.path.dirname(script_path)
        
        # Führe PyInstaller aus, um die ausführbare Datei zu erstellen
        opts = ['--onefile', '--noconsole', '--distpath', script_dir, script_path]

        run(opts)
