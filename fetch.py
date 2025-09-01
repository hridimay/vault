#!/usr/bin/env python3
"""
FileDrop CLI: File Access Client


A command-line interface for file downloads and management from a remote repository.
"""


import sys
import signal
import hashlib
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple

try:
    import requests
except ImportError:
    print("Required library 'requests' not found. Attempting to install...")
    try:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
        # Re-import after installation
        import requests
    except Exception as e:
        print(f"Fatal Error: Could not install 'requests'. Please install it manually: pip install requests")
        print(f"Error details: {e}")
        sys.exit(1)


# --- Dependency Check ---
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
        BarColumn,
        DownloadColumn,
        TransferSpeedColumn,
        TimeRemainingColumn,
    )
    from rich.text import Text
    from rich.live import Live
    from rich import box
    from rich.align import Align
    from rich.status import Status
    from rich.theme import Theme
except ImportError:
    print("Required library 'rich' not found. Attempting to install...")
    try:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "rich"])
        # Re-import after installation
        from rich.console import Console
        from rich.panel import Panel
        from rich.prompt import Prompt, Confirm
        from rich.table import Table
        from rich.progress import (
            Progress,
            SpinnerColumn,
            TextColumn,
            BarColumn,
            DownloadColumn,
            TransferSpeedColumn,
            TimeRemainingColumn,
        )
        from rich.text import Text
        from rich.live import Live
        from rich import box
        from rich.align import Align
        from rich.status import Status
        from rich.theme import Theme
    except Exception as e:
        print(f"Fatal Error: Could not install 'rich'. Please install it manually: pip install rich")
        print(f"Error details: {e}")
        sys.exit(1)


# --- Global Configuration ---
custom_theme = Theme({
    "info": "bright_cyan",
    "warning": "bright_yellow",
    "danger": "bright_red",
    "success": "bright_green",
    "primary": "bright_blue",
    "secondary": "bright_magenta",
    "accent": "bright_white",
    "subtle": "dim white"
})
console = Console(theme=custom_theme)


# --- Utility Functions ---
def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception:
        return ""


def read_hash_file(hash_file_path: Path) -> Optional[str]:
    """Read hash from .sha256 file."""
    try:
        if hash_file_path.exists():
            with open(hash_file_path, 'r') as f:
                content = f.read().strip()
                # Hash might be in format: "hash  filename" or just "hash"
                if content:
                    return content.split()[0].lower()
    except Exception:
        pass
    return None


def get_target_directory(filename: str, base_dir: Path) -> Path:
    """Get target directory based on filename (first part before first dot)."""
    dir_name = filename.split('.')[0] if '.' in filename else filename
    return base_dir / dir_name


# --- API Client ---
class FileDropAPIClient:
    """An API client for interacting with the file repository."""
    def __init__(self, base_url: str, timeout: int = 15):
        self.base_url = base_url.rstrip('/')
        self.token: Optional[str] = None
        self.username: Optional[str] = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'FileDropCLI/1.0',
            'Accept': 'application/json'
        })
        self.is_authenticated = False
        self.timeout = timeout


    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Centralized method for making HTTP requests."""
        url = f"{self.base_url}{endpoint}"
        if self.token:
            headers = kwargs.get('headers', {})
            headers['Authorization'] = f'Bearer {self.token}'
            kwargs['headers'] = headers
        try:
            response = self.session.request(method, url, timeout=self.timeout, **kwargs)
            response.raise_for_status()
            if response.headers.get('Content-Type', '').startswith('application/json'):
                return {'success': True, 'data': response.json()}
            return {'success': True, 'data': {'message': response.text or "Success"}}
        except requests.exceptions.HTTPError as e:
            error_data = e.response.json() if 'application/json' in e.response.headers.get('Content-Type', '') else {}
            error_msg = error_data.get('error', e.response.text)
            return {'success': False, 'error': f"HTTP Error {e.response.status_code}: {error_msg}"}
        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': f'Connection failed: {e}'}
        except Exception as e:
            return {'success': False, 'error': f'An unexpected error occurred: {e}'}


    def authenticate(self, username: str, password: str) -> bool:
        """Authenticates the user and stores the session token."""
        with Status("[info]Authenticating...", console=console, spinner="dots12"):
            result = self._make_request('POST', '/auth', json={'username': username, 'password': password})
        if result['success'] and 'token' in result['data']:
            self.token = result['data']['token']
            self.username = username
            self.is_authenticated = True
            expires = result['data'].get('expiresIn', 1800)
            
            welcome_content = f"[accent]User:[/] [secondary]{username}[/] • [accent]Session:[/] [info]{expires // 60} minutes[/]"
            
            console.print(Panel(
                Align.center(welcome_content),
                title="[success]✓ Login Successful[/]",
                border_style="bright_green",
                box=box.ROUNDED,
                padding=(0, 1)
            ))
            return True
        else:
            error = result.get('error', 'Authentication failed. Please check your credentials.')
            console.print(Panel(
                f"[danger]✗ Login Failed[/]\n[subtle]{error}[/]",
                title_align="left",
                border_style="bright_red",
                box=box.ROUNDED,
                padding=(0, 1)
            ))
            self.is_authenticated = False
            return False


    def logout(self) -> bool:
        """Logs the user out and clears session data."""
        if not self.is_authenticated:
            return True
        with Status("[info]Logging out...", console=console, spinner="dots12"):
            self._make_request('POST', '/logout')
        self.token = None
        self.username = None
        self.is_authenticated = False
        
        console.print(Panel(
            Align.center("[success]✓ You have been logged out.[/]"),
            title_align="left",
            border_style="bright_green",
            box=box.ROUNDED,
            padding=(0, 1)
        ))
        return True


    def list_files(self) -> Optional[Dict[str, List[str]]]:
        """Retrieves the list of available files."""
        if not self.is_authenticated:
            console.print("[danger]✗ Authentication required. Please login first.[/danger]")
            return None
        with Status("[info]Fetching file list...", console=console, spinner="dots12"):
            result = self._make_request('GET', '/list')
        if result['success']:
            return result['data']
        else:
            console.print(f"[danger]✗ Error: {result.get('error', 'Could not retrieve file list.')}[/]")
            return None


    def get_download_url(self, filename: str) -> Optional[str]:
        """Gets a download URL for a specific file."""
        if not self.is_authenticated:
            return None
        result = self._make_request('POST', '/fetch', json={'file': filename})
        if result['success']:
            return result['data'].get('downloadUrl')
        else:
            console.print(f"[danger]✗ Error fetching URL for '{filename}': {result.get('error')}[/]")
            return None


# --- Main CLI Application ---
class FileDropCLI:
    """The main CLI application controller."""
    def __init__(self, api_url: str):
        self.client = FileDropAPIClient(api_url)
        self.download_dir = Path(".")
        self.file_cache: Optional[Dict[str, List[str]]] = None
        self.skipped_files: List[str] = []  # Track skipped files
        # Set up a global, robust exit handler for Ctrl+C
        signal.signal(signal.SIGINT, self._signal_handler)


    def _signal_handler(self, signum: int, frame: Any):
        """Handles Ctrl+C to ensure a clean, graceful exit from anywhere."""
        console.print("\n[warning]⚠  Operation cancelled. Shutting down...[/warning]")
        self.shutdown()


    def shutdown(self):
        """Performs cleanup operations before exiting."""
        if self.client.is_authenticated:
            self.client.logout()
        console.print("[secondary]👋 Goodbye![/]")
        sys.exit(0)


    def show_banner(self):
        """Displays a clean, minimal banner."""
        banner_text = Text("FileDrop CLI", style="bold bright_cyan", justify="center")
        subtitle_text = Text("File Access & Management Tool", style="subtle", justify="center")
        
        banner_content = f"{banner_text}\n{subtitle_text}"
        
        console.print(Panel(
            Align.center(banner_content),
            box=box.DOUBLE_EDGE,
            border_style="bright_cyan",
            padding=(0, 2)
        ))


    def login(self) -> bool:
        """Handles the user login workflow."""
        auth_panel = Panel(
            "[secondary]🔐 Authentication Required[/]",
            box=box.ROUNDED,
            border_style="bright_blue",
            padding=(0, 1)
        )
        console.print(auth_panel)
        
        for attempt in range(3):
            try:
                username = Prompt.ask("[primary]👤 Username[/]")
                password = Prompt.ask("[primary]🔑 Password[/]", password=True)
                if not username or not password:
                    console.print("[danger]✗ Username and password cannot be empty.[/danger]")
                    continue
                if self.client.authenticate(username, password):
                    return True
                else:
                    remaining = 2 - attempt
                    if remaining > 0:
                        console.print(f"[warning]⚠  Login failed. {remaining} attempts remaining.[/warning]")
            except (KeyboardInterrupt, EOFError):
                console.print("\n[warning]⚠  Login cancelled.[/warning]")
                return False
        console.print("[danger]✗ Maximum login attempts exceeded.[/danger]")
        return False


    def show_help(self):
        """Displays the command reference."""
        table = Table(
            title="[secondary]📖 Command Reference[/]",
            box=box.ROUNDED,
            padding=(0, 1),
            show_header=True,
            header_style="accent",
            border_style="bright_blue"
        )
        table.add_column("Command", style="primary", width=22)
        table.add_column("Alias", style="info", width=12)
        table.add_column("Description", style="accent", min_width=35)
        
        commands = [
            ("help", "?", "Displays this help message."),
            ("list", "ls", "Lists all available files."),
            ("download <file|all>", "get", "Downloads one or all files (e.g., 'all metadata')."),
            ("verify <file|all>", "vf", "Verifies SHA256 hash of file(s)."),
            ("status", "st", "Shows current session status."),
            ("clear", "cls", "Clears the console screen."),
            ("exit", "quit, q", "Logs out and exits the application."),
        ]
        
        for cmd, alias, desc in commands:
            table.add_row(cmd, alias, desc)
            
        console.print(table)


    def show_status(self):
        """Displays the current session status."""        
        if self.client.is_authenticated:
            status_content = f"[accent]Auth:[/] [success]✓ Active[/] • [accent]User:[/] [secondary]{self.client.username}[/]\n[accent]API:[/] [info]{self.client.base_url}[/]\n[accent]Downloads:[/] [info]{self.download_dir}[/]"
            
            panel = Panel(
                status_content,
                title="[success]📊 Session Status[/]",
                border_style="bright_green",
                box=box.ROUNDED,
                padding=(0, 1)
            )
        else:
            status_content = "[accent]Auth:[/] [danger]✗ Not Active[/]\n[subtle]Use 'login' command to authenticate.[/]"
            
            panel = Panel(
                status_content,
                title="[danger]📊 Session Status[/]",
                border_style="bright_red",
                box=box.ROUNDED,
                padding=(0, 1)
            )
            
        console.print(panel)


    def display_file_list(self):
        """Fetches and displays the file list."""
        self.file_cache = self.client.list_files()
        if not self.file_cache:
            return
            
        table = Table(
            title="[secondary]📁 Available Files[/]",
            box=box.ROUNDED,
            show_header=True,
            header_style="accent",
            border_style="bright_blue",
            padding=(0, 1)
        )
        table.add_column("File Name", style="primary", min_width=25)
        table.add_column("Category", style="info", justify="center", width=12)
        
        metadata_files = self.file_cache.get('metadata', [])
        data_files = self.file_cache.get('files', [])
        
        if not metadata_files and not data_files:
            console.print(Panel(
                "[warning]⚠  No files available in the repository.[/]",
                border_style="bright_yellow",
                box=box.ROUNDED,
                padding=(0, 1)
            ))
            return
            
        for f in sorted(metadata_files):
            table.add_row(f, "[info]📄 Metadata[/]")
            
        if metadata_files and data_files:
            table.add_section()
            
        for f in sorted(data_files):
            table.add_row(f, "[accent]📊 Data[/]")
            
        console.print(table)
        console.print(f"[accent]Total files:[/] [secondary]{len(metadata_files) + len(data_files)}[/]")


    def check_existing_file(self, filename: str, target_dir: Path) -> Tuple[bool, bool, str]:
        """Check if file exists and verify hash for .gpg files.
        Returns: (file_exists, should_download, skip_reason)
        """
        file_path = target_dir / filename
        
        if not file_path.exists():
            return False, True, ""
        
        # For .json files
        if filename.endswith('.json'):
            # Use console directly outside of progress context
            replace = Confirm.ask(f"\n[warning]⚠  File '{filename}' already exists. Replace?[/]", default=False, console=console)
            if replace:
                try:
                    file_path.unlink()
                except Exception:
                    pass
                return True, True, ""
            else:
                return True, False, "already exists"
        
        # For .gpg files
        if filename.endswith('.gpg'):
            hash_file = target_dir / f"{filename}.sha256"
            expected_hash = read_hash_file(hash_file)
            
            if expected_hash:
                actual_hash = calculate_sha256(file_path)
                if actual_hash and (expected_hash == actual_hash.lower()):
                    return True, False, "already present"
                else:
                    # Use console directly outside of progress context
                    replace = Confirm.ask(f"\n[warning]⚠  Hash doesn't match for '{filename}'. Replace?[/]", default=False, console=console)
                    if replace:
                        try:
                            file_path.unlink()
                        except Exception:
                            pass
                        return True, True, ""
                    else:
                        return True, False, "hash mismatch kept"
            else:
                # No hash file
                replace = Confirm.ask(f"\n[warning]⚠  No hash file available '{filename}'. Replace?[/]", default=False, console=console)

                if replace:
                    try:
                        file_path.unlink()
                    except Exception:
                        pass
                    return True, True, ""
                else:
                    return True, False, "hash missing kept"
        
        # For other files, skip if exists
        return True, False, "already exists"


    def verify_downloaded_file(self, filename: str, file_path: Path) -> tuple[bool, str]:
        """Verify hash of downloaded .gpg file.
        Returns: (success, status_message)
        """
        if not filename.endswith('.gpg'):
            return True, "verified"
            
        hash_file = file_path.parent / f"{filename}.sha256"
        expected_hash = read_hash_file(hash_file)
        
        if not expected_hash:
            return False, "no_hash_file"
        
        if file_path.exists():
            actual_hash = calculate_sha256(file_path)
            if actual_hash and (expected_hash == actual_hash.lower()):
                return True, "hash_matched"
            else:
                return False, "hash_mismatch"
        
        return False, "file_missing"



    def download_worker(self, filename: str, progress: Progress, task_id: Any, pre_check: Tuple[bool, str]) -> bool:
        """The download logic for a single file."""
        should_download, skip_reason = pre_check
        
        if not should_download:
            progress.update(task_id, description=f"[info]⏭  Skipped: {filename} ({skip_reason})[/]", total=1, completed=1)
            return True
        
        # Determine target directory
        target_dir = get_target_directory(filename, self.download_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        
        download_url = self.client.get_download_url(filename)
        if not download_url:
            progress.update(task_id, description=f"[danger]✗ Failed: {filename} (URL error)[/]", total=1, completed=1)
            return False
        
        try:
            response = requests.get(download_url, stream=True, timeout=30)
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            progress.update(task_id, total=total_size)
            progress.start_task(task_id)
            file_path = target_dir / filename
            
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    progress.update(task_id, advance=len(chunk))
            
            # Verify hash for .gpg files after download
            if filename.endswith('.gpg'):
                verified, status = self.verify_downloaded_file(filename, file_path)
                if status == "hash_matched":
                    progress.update(task_id, description=f"[success]✓ Done: {filename} (hash verified)[/]")
                elif status == "no_hash_file":
                    progress.update(task_id, description=f"[warning]✓ Done: {filename} (no hash file)[/]")
                elif status == "hash_mismatch":
                    progress.update(task_id, description=f"[warning]✓ Done: {filename} (hash NOT matched!)[/]")
                else:
                    progress.update(task_id, description=f"[success]✓ Done: {filename}[/]")
            else:
                progress.update(task_id, description=f"[success]✓ Done: {filename}[/]")

            return True
        except requests.exceptions.RequestException:
            progress.update(task_id, description=f"[danger]✗ Failed: {filename} (Network error)[/]")
            return False
        except IOError:
            progress.update(task_id, description=f"[danger]✗ Failed: {filename} (IO error)[/]")
            return False


    def download_files(self, args: List[str]):
        """Handles sequential file downloads."""
        if not args:
            console.print("[danger]✗ Download command requires an argument (e.g., 'download <filename>' or 'download all').[/]")
            return
        
        if not self.file_cache:
            self.file_cache = self.client.list_files()
        if not self.file_cache:
            return
            
        files_to_download: List[str] = []
        all_known_files = self.file_cache.get('metadata', []) + self.file_cache.get('files', [])
        
        # Build list of files to download
        if args[0].lower() == 'all':
            mode = args[1].lower() if len(args) > 1 else 'all'
            if mode in ['all', 'files']:
                files_to_download.extend(self.file_cache.get('files', []))
            if mode in ['all', 'metadata']:
                files_to_download.extend(self.file_cache.get('metadata', []))
        else:
            filename = " ".join(args)
            if filename in all_known_files:
                files_to_download.append(filename)
            else:
                console.print(f"[danger]✗ File not found: '{filename}'. Use 'list' to see available files.[/danger]")
                return
        
        # Add corresponding .sha256 files for .gpg files
        sha_files = []
        for f in files_to_download[:]:  # Use slice to avoid modifying list during iteration
            if f.endswith('.gpg'):
                sha_file = f"{f}.sha256"
                if sha_file in all_known_files and sha_file not in files_to_download:
                    sha_files.append(sha_file)
        
        files_to_download.extend(sha_files)
        
        if not files_to_download:
            console.print("[warning]⚠ No files match your request.[/warning]")
            return
            
        self.download_dir.mkdir(exist_ok=True)
        
        # Pre-check files before starting progress (for prompts)
        file_checks = {}
        for filename in files_to_download:
            target_dir = get_target_directory(filename, self.download_dir)
            target_dir.mkdir(parents=True, exist_ok=True)
            _, should_download, skip_reason = self.check_existing_file(filename, target_dir)
            file_checks[filename] = (should_download, skip_reason)
        
        # Count files that will actually be downloaded
        actual_downloads = sum(1 for check in file_checks.values() if check[0])
        skipped_count = len(files_to_download) - actual_downloads
        
        console.print(Panel(
            f"[info]📥 Processing[/] [secondary]{len(files_to_download)}[/] [info]file(s)[/] • [info]Downloading:[/] [secondary]{actual_downloads}[/] • [info]Skipping:[/] [secondary]{skipped_count}[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(0, 1)
        ))
        
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="bright_green", finished_style="bright_green"),
            "•",
            DownloadColumn(binary_units=True),
            "•",
            TransferSpeedColumn(),
            "•",
            TimeRemainingColumn(),
            console=console,
            expand=True
        )

        successful, failed = 0, 0
        with Live(progress, refresh_per_second=6):
            for filename in files_to_download:
                task_id = progress.add_task(f"[info]⏳ Processing: {filename}[/]", start=False)
                if self.download_worker(filename, progress, task_id, file_checks[filename]):
                    successful += 1
                else:
                    failed += 1
        
        # Post-download hash verification messages
        for filename in files_to_download:
            if filename.endswith('.gpg') and file_checks[filename][0]:  # Was downloaded
                target_dir = get_target_directory(filename, self.download_dir)
                file_path = target_dir / filename
                if file_path.exists():
                    verified, status = self.verify_downloaded_file(filename, file_path)
                    if status == "hash_matched":
                        console.print(f"[success]✓ Hash matched: {filename}[/]")
                    elif status == "no_hash_file":
                        console.print(f"[warning]⚠  No hash file available: {filename}[/]")
                    elif status == "hash_mismatch":
                        console.print(f"[danger]⚠  Hash NOT matched: {filename}[/]")

        
        summary_content = f"[success]✓ Successful:[/] [secondary]{successful}[/] • [danger]✗ Failed:[/] [secondary]{failed}[/]"
        
        console.print(Panel(
            summary_content,
            title="[secondary]📊 Download Summary[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(0, 1)
        ))


    def verify_files(self, args: List[str]):
        """Verify SHA256 hashes of downloaded files."""
        if not args:
            console.print("[danger]✗ Verify command requires an argument (e.g., 'verify <filename>' or 'verify all').[/]")
            return
        
        files_to_verify: List[Path] = []
        
        if args[0].lower() == 'all':
            # Find all .gpg files in download directories
            if self.download_dir.exists():
                for dir_path in self.download_dir.iterdir():
                    if dir_path.is_dir():
                        files_to_verify.extend(dir_path.glob("*.gpg"))
        else:
            filename = " ".join(args)
            if filename.endswith('.gpg'):
                target_dir = get_target_directory(filename, self.download_dir)
                file_path = target_dir / filename
                if file_path.exists():
                    files_to_verify.append(file_path)
                else:
                    console.print(f"[danger]✗ File not found: '{filename}'[/]")
                    return
            else:
                console.print(f"[warning]⚠ Only .gpg files can be verified.[/]")
                return
        
        if not files_to_verify:
            console.print("[warning]⚠  No files to verify.[/]")
            return
        
        console.print(Panel(
            f"[info]🔍 Verifying[/] [secondary]{len(files_to_verify)}[/] [info]file(s)[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(0, 1)
        ))
        
        passed, failed, missing = 0, 0, 0
        
        for file_path in files_to_verify:
            hash_file = file_path.parent / f"{file_path.name}.sha256"
            
            if not hash_file.exists():
                console.print(f"[warning]⚠  Hash file missing: {file_path.name}[/]")
                missing += 1
                continue
            
            expected_hash = read_hash_file(hash_file)
            if expected_hash:
                actual_hash = calculate_sha256(file_path)
                if actual_hash and (expected_hash == actual_hash.lower()):
                    console.print(f"[success]✓ Verified: {file_path.name}[/]")
                    passed += 1
                else:
                    console.print(f"[danger]✗ Hash mismatch: {file_path.name}[/]")
                    console.print(f"  [subtle]Expected: {expected_hash}[/]")
                    console.print(f"  [subtle]Actual:   {actual_hash.lower() if actual_hash else 'ERROR'}[/]")
                    failed += 1
            else:
                console.print(f"[warning]⚠  Cannot read hash: {file_path.name}[/]")
                missing += 1
        
        summary_content = f"[success]✓ Passed:[/] [secondary]{passed}[/] • [danger]✗ Failed:[/] [secondary]{failed}[/] • [warning]⚠  Missing:[/] [secondary]{missing}[/]"
        
        console.print(Panel(
            summary_content,
            title="[secondary]🔍 Verification Summary[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(0, 1)
        ))


    def run_command(self, command_line: str):
        """Parses and executes user commands."""
        if not command_line:
            return
        parts = command_line.strip().split()
        command = parts[0].lower()
        args = parts[1:]
        
        cmd_map = {
            "help": self.show_help, "?": self.show_help,
            "list": self.display_file_list, "ls": self.display_file_list,
            "status": self.show_status, "st": self.show_status,
            "clear": lambda: console.clear() or self.show_banner(), 
            "cls": lambda: console.clear() or self.show_banner(),
            "logout": self.shutdown, "lo": self.shutdown,
            "exit": self.shutdown, "quit": self.shutdown, "q": self.shutdown,
        }
        
        if command in cmd_map:
            cmd_map[command]()
        elif command in ["download", "get"]:
            self.download_files(args)
        elif command in ["verify", "vf"]:
            self.verify_files(args)
        else:
            console.print(f"[danger]✗ Unknown command: '{command}'. Type 'help' for a list of commands.[/danger]")


    def start(self):
        """The main entry point and application loop."""
        console.clear()
        self.show_banner()
        
        if not self.login():
            console.print("[danger]✗ Authentication failed. Exiting.[/danger]")
            sys.exit(1)
            
        welcome_content = f"[accent]Welcome,[/] [secondary]{self.client.username}[/][accent]![/] • [subtle]Type[/] [primary]help[/] [subtle]for commands or[/] [primary]exit[/] [subtle]to quit.[/]"
        
        console.print(Panel(
            welcome_content,
            title="[success]🚀 Session Started[/]",
            border_style="bright_green",
            box=box.ROUNDED,
            padding=(0, 1)
        ))
        
        while True:
            try:
                prompt_text = Text(f"┌─ {self.client.username}@filedrop\n└─> ", style="secondary")
                command = Prompt.ask(prompt_text)
                self.run_command(command)
            except (KeyboardInterrupt, EOFError):
                self.shutdown()
                break


def main():
    """Application entry point."""
    API_URL = "https://weathered-art-36f8.hridimay.workers.dev"
    try:
        cli = FileDropCLI(api_url=API_URL)
        cli.start()
    except Exception as e:
        console.print(f"[danger]✗ A fatal, unhandled error occurred: {e}[/]")
        sys.exit(1)


if __name__ == "__main__":
    main()