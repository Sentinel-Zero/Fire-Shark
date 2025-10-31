import subprocess
import time
import platform
import webbrowser

IS_WINDOWS = platform.system() == "Windows"


def main():
    if IS_WINDOWS:
        # Terminal 1: activate venv + run uvicorn
        backend_cmd = (
            'start "FireShark Backend" cmd /k '
            '"call .\\fires_env\\Scripts\\activate && '
            'python -m uvicorn app.app:app --reload --host 0.0.0.0 --port 8000"'
        )
        subprocess.Popen(backend_cmd, shell=True)

        time.sleep(2)

        # Terminal 2: run frontend static server
        frontend_cmd = (
            'start "FireShark Frontend" cmd /k ' '"python -m http.server 8080"'
        )
        subprocess.Popen(frontend_cmd, shell=True)

        time.sleep(2)
        # Open browser to frontend
        webbrowser.open("http://localhost:8080/upload.html")
    else:
        print("This script is designed for Windows terminals.")


if __name__ == "__main__":
    main()
