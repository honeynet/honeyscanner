from contextlib import contextmanager
import sys
from typing import Generator, Optional

try:
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskID,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class ProgressManager:
    """
    Central progress and console manager for Honeyscanner.
    Sends all visual progress bars, spinners, and log output to sys.stderr,
    preserving stdout exclusively for machine-readable JSON output.
    """

    def __init__(self) -> None:
        self.disabled: bool = False
        if RICH_AVAILABLE:
            self.console = Console(stderr=True, highlight=False)
            self._progress: Optional[Progress] = None
        else:
            self.console = None
            self._progress = None
        self._overall_task_id: Optional[TaskID] = None
        self._active_session: bool = False

    def is_enabled(self) -> bool:
        """Check if visual progress reporting is active and supported."""
        if not RICH_AVAILABLE or self.disabled or self.console is None:
            return False
        return self.console.is_terminal

    def start_session(self, total_stages: int = 6, disabled: bool = False) -> None:
        """
        Start an overarching progress session.

        Args:
            total_stages (int): Number of high-level stages to track.
            disabled (bool): If True, disable all visual progress rendering.
        """
        self.disabled = disabled or (not sys.stderr.isatty())
        if not self.is_enabled():
            self._active_session = True
            return

        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30, complete_style="green", finished_style="bold green"),
            TaskProgressColumn(),
            TextColumn("[dim yellow]({task.completed}/{task.total})[/dim yellow]"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
            auto_refresh=True,
        )
        self._progress.start()
        self._overall_task_id = self._progress.add_task(
            "[bold white]Overall Scan Progress[/bold white]",
            total=total_stages,
            completed=0,
        )
        self._active_session = True

    def stop_session(self) -> None:
        """Stop the active progress session and clean up the terminal view."""
        if self._progress is not None:
            try:
                self._progress.stop()
            except Exception:
                pass
            self._progress = None
        self._overall_task_id = None
        self._active_session = False

    def advance_overall(self, step: int = 1, description: Optional[str] = None) -> None:
        """Advance the master/overall stage progress bar."""
        if self._progress is not None and self._overall_task_id is not None:
            if description:
                self._progress.update(
                    self._overall_task_id,
                    description=f"[bold white]{description}[/bold white]",
                )
            self._progress.advance(self._overall_task_id, step)

    def log(self, message: str) -> None:
        """
        Log a message to stderr without corrupting active progress bars.
        """
        if self._progress is not None and self._progress.live.is_started:
            self._progress.console.print(message)
        elif self.console is not None:
            self.console.print(message)
        else:
            sys.stderr.write(f"{message}\n")
            sys.stderr.flush()

    @contextmanager
    def task_progress(
        self, description: str, total: int
    ) -> Generator[Optional[TaskID], None, None]:
        """
        Context manager to create, track, and close a subtask progress bar.

        Args:
            description (str): Description of the task.
            total (int): Total number of items/steps.
        """
        if not self.is_enabled() or self._progress is None:
            yield None
            return

        task_id = self._progress.add_task(description, total=total, completed=0)
        try:
            yield task_id
        finally:
            if self._progress is not None:
                self._progress.remove_task(task_id)

    def update_task(
        self,
        task_id: Optional[TaskID],
        advance: int = 1,
        completed: Optional[int] = None,
        description: Optional[str] = None,
    ) -> None:
        """Update or advance an active subtask."""
        if task_id is None or self._progress is None:
            return
        kwargs = {}
        if description is not None:
            kwargs["description"] = description
        if completed is not None:
            kwargs["completed"] = completed
        else:
            kwargs["advance"] = advance
        self._progress.update(task_id, **kwargs)

    @contextmanager
    def spinner(self, description: str) -> Generator[None, None, None]:
        """
        Context manager displaying an animated spinner for indeterminate tasks.

        Args:
            description (str): The label displayed next to the spinner.
        """
        if not self.is_enabled():
            self.log(f"[bold blue][~][/bold blue] {description}")
            yield
            return

        if self._progress is not None:
            # Use progress task with no total for indeterminate spinner
            spinner_task = self._progress.add_task(description, total=None)
            try:
                yield
            finally:
                if self._progress is not None:
                    self._progress.remove_task(spinner_task)
        else:
            with self.console.status(f"[bold cyan]{description}[/bold cyan]"):
                yield


# Global singleton instance
progress_manager = ProgressManager()


@contextmanager
def progress_session(
    total_stages: int = 6, disabled: bool = False
) -> Generator[ProgressManager, None, None]:
    """
    Context manager for wrapping an entire Honeyscanner run with progress tracking.
    """
    progress_manager.start_session(total_stages=total_stages, disabled=disabled)
    try:
        yield progress_manager
    finally:
        progress_manager.stop_session()
