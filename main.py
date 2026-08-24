"""Security Scanner TUI

Combines three scanners into one Textual-based terminal UI:
  - Secrets / dangerous-code regex scanner
  - SQL injection AST scanner
  - Hash-based malware signature scanner

Run with:  python main.py
"""

import os

from rich.panel import Panel
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    RadioButton,
    RadioSet,
    RichLog,
    TabbedContent,
    TabPane,
)

from scanners import secrets_scanner, sql_scanner, malware_scanner
from scanners.common import parse_exclude
from scanners.malware_scanner import DEFAULT_DB_PATH


SEVERITY_STYLE = {
    "Critical": "bold red",
    "High": "bold yellow",
    "Medium": "yellow",
    "unknown": "white",
}


class ScanTab(VerticalScroll):
    """Runs the three scanners against a folder/file and shows results."""

    def compose(self) -> ComposeResult:
        yield Label("검사 대상 경로")
        yield Input(placeholder="예: . 또는 /path/to/project", id="scan_path", value=".")

        yield Label("제외할 파일/폴더 (쉼표 또는 공백 구분)")
        yield Input(placeholder="예: .git, node_modules, venv", id="exclude")

        with Horizontal(id="scan_checks"):
            yield Checkbox("민감정보/시크릿", value=True, id="chk_secrets")
            yield Checkbox("SQL 인젝션", value=True, id="chk_sql")
            yield Checkbox("악성코드(해시)", value=True, id="chk_malware")

        yield Label("악성코드 시그니처 DB 경로")
        yield Input(value=DEFAULT_DB_PATH, id="db_path")

        yield Checkbox("상세 결과 보기 (verbose)", value=False, id="chk_verbose")

        yield Button("스캔 시작", id="start_scan", variant="primary")

        yield Label("결과", id="results_label")
        yield RichLog(id="scan_output", wrap=True, highlight=True, markup=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_scan":
            self.run_scan()

    @work(thread=True, exclusive=True)
    def run_scan(self) -> None:
        log = self.query_one("#scan_output", RichLog)
        log.clear()

        path = self.query_one("#scan_path", Input).value.strip() or "."
        exclude = parse_exclude(self.query_one("#exclude", Input).value)
        verbose = self.query_one("#chk_verbose", Checkbox).value
        do_secrets = self.query_one("#chk_secrets", Checkbox).value
        do_sql = self.query_one("#chk_sql", Checkbox).value
        do_malware = self.query_one("#chk_malware", Checkbox).value
        db_path = self.query_one("#db_path", Input).value.strip() or DEFAULT_DB_PATH

        if not os.path.exists(path):
            self.app.call_from_thread(
                log.write, f"[bold red]경로를 찾을 수 없습니다: {path}[/bold red]"
            )
            return

        self.app.call_from_thread(
            log.write, f"[bold blue]검사 대상 폴더: {path}[/bold blue]\n"
        )

        if do_secrets:
            self._run_secrets(log, path, exclude, verbose)
        if do_sql:
            self._run_sql(log, path, exclude, verbose)
        if do_malware:
            self._run_malware(log, path, exclude, db_path)

        self.app.call_from_thread(log.write, "[bold green]스캔 완료.[/bold green]")

    def _run_secrets(self, log, path, exclude, verbose):
        matches = secrets_scanner.scan(path, exclude)
        self.app.call_from_thread(
            log.write, Panel("[bold yellow]민감정보 / 위험 코드 패턴[/bold yellow]", border_style="yellow")
        )
        if not matches:
            self.app.call_from_thread(log.write, "[green]발견된 항목이 없습니다.[/green]\n")
            return

        grouped = {}
        for item in matches:
            grouped.setdefault(item["name"], []).append(item)

        for category, findings in grouped.items():
            self.app.call_from_thread(log.write, f"[bold]{category}[/bold] ({len(findings)}건)")
            for f in findings:
                style = SEVERITY_STYLE.get(f["severity"], "white")
                value = f["secret"]
                if not verbose and len(value) > 80:
                    value = value[:80] + "..."
                self.app.call_from_thread(
                    log.write,
                    f"  [magenta]{f['file_path']}:{f['line_number']}[/magenta] "
                    f"[{style}]({f['severity']})[/{style}] '{value}'",
                )
        self.app.call_from_thread(log.write, "")

    def _run_sql(self, log, path, exclude, verbose):
        results, warnings = sql_scanner.scan(path, exclude)
        self.app.call_from_thread(
            log.write, Panel("[bold yellow]SQL 인젝션 (AST 분석)[/bold yellow]", border_style="yellow")
        )
        if verbose:
            for w in warnings:
                self.app.call_from_thread(log.write, f"[dim]{w}[/dim]")

        if not results:
            self.app.call_from_thread(log.write, "[green]발견된 항목이 없습니다.[/green]\n")
            return

        for filepath, issues in results.items():
            self.app.call_from_thread(log.write, f"[bold]{filepath}[/bold]")
            for line, msg in issues:
                text = msg if (verbose or len(msg) <= 80) else msg[:80] + "..."
                self.app.call_from_thread(log.write, f"  [magenta]Line {line}:[/magenta] {text}")
        self.app.call_from_thread(log.write, "")

    def _run_malware(self, log, path, exclude, db_path):
        self.app.call_from_thread(
            log.write, Panel("[bold yellow]악성코드 시그니처 (해시 대조)[/bold yellow]", border_style="yellow")
        )

        if not os.path.exists(db_path):
            self.app.call_from_thread(
                log.write, f"[red]DB 파일을 찾을 수 없습니다: {db_path} ('악성코드 DB 관리' 탭에서 먼저 구축하세요)[/red]\n"
            )
            return

        conn = malware_scanner.init_db(db_path)
        try:
            result = malware_scanner.scan(conn, path, exclude)
        finally:
            conn.close()

        if "error" in result:
            self.app.call_from_thread(log.write, f"[red]{result['error']}[/red]\n")
            return

        detections = result["detections"]
        total = result["total"]

        if not detections:
            self.app.call_from_thread(
                log.write, f"[green]총 {total}개 파일 검사 완료, 알려진 악성코드 시그니처 없음.[/green]\n"
            )
            return

        for d in detections:
            style = SEVERITY_STYLE.get(d["severity"], "bold red")
            self.app.call_from_thread(
                log.write,
                f"  [bold red]⚠ 탐지:[/bold red] {d['file_path']} -> "
                f"{d['malware_name']} [{style}]({d['severity']})[/{style}]",
            )
        self.app.call_from_thread(
            log.write, f"\n[bold]총 {total}개 파일 중 {len(detections)}개에서 시그니처 탐지됨.[/bold]\n"
        )


class DBTab(VerticalScroll):
    """Build / maintain the malware signature database."""

    def compose(self) -> ComposeResult:
        yield Label("시그니처 DB 경로")
        yield Input(value=DEFAULT_DB_PATH, id="db_path2")

        yield Label("등록 방식")
        with RadioSet(id="mode"):
            yield RadioButton("폴더 일괄 등록", value=True, id="mode_dir")
            yield RadioButton("CSV 가져오기 (MalwareBazaar 형식)", id="mode_csv")
            yield RadioButton("수동 입력", id="mode_manual")

        yield Label("-- 폴더 일괄 등록 --")
        yield Input(placeholder="등록할 폴더 경로", id="dir_path")
        yield Input(placeholder="이름 접두사 (기본: Unknown)", id="name_prefix")
        yield Input(placeholder="위험도 (기본: unknown)", id="severity_dir")

        yield Label("-- CSV 가져오기 --")
        yield Input(placeholder="CSV 파일 경로", id="csv_path")
        yield Input(placeholder="가져올 최대 개수 (비우면 전체 가져오기)", id="csv_limit")

        yield Label("-- 수동 입력 --")
        yield Input(placeholder="SHA256 (필수)", id="man_sha256")
        yield Input(placeholder="MD5 (선택)", id="man_md5")
        yield Input(placeholder="SHA1 (선택)", id="man_sha1")
        yield Input(placeholder="악성코드 이름", id="man_name")
        yield Input(placeholder="위험도 (기본: unknown)", id="man_severity")

        yield Button("등록 실행", id="register", variant="primary")
        yield RichLog(id="db_output", wrap=True, highlight=True, markup=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "register":
            self.run_register()

    @work(thread=True, exclusive=True)
    def run_register(self) -> None:
        log = self.query_one("#db_output", RichLog)
        log.clear()

        db_path = self.query_one("#db_path2", Input).value.strip() or DEFAULT_DB_PATH
        mode_set = self.query_one("#mode", RadioSet)
        pressed = mode_set.pressed_button.id if mode_set.pressed_button else "mode_dir"

        conn = malware_scanner.init_db(db_path)
        try:
            if pressed == "mode_dir":
                dir_path = self.query_one("#dir_path", Input).value.strip()
                prefix = self.query_one("#name_prefix", Input).value.strip() or "Unknown"
                severity = self.query_one("#severity_dir", Input).value.strip() or "unknown"

                self.app.call_from_thread(log.write, f"[bold blue]대상 폴더: {dir_path}[/bold blue]")
                result = malware_scanner.build_db_from_directory(conn, dir_path, prefix, severity)

                if "error" in result:
                    self.app.call_from_thread(log.write, f"[red]{result['error']}[/red]")
                else:
                    self.app.call_from_thread(
                        log.write,
                        f"[bold]등록 {result['registered']}건 / 중복 스킵 {result['skipped']}건 / "
                        f"읽기 실패 {result['failed']}건[/bold]",
                    )

            elif pressed == "mode_csv":
                csv_path = self.query_one("#csv_path", Input).value.strip()
                limit_raw = self.query_one("#csv_limit", Input).value.strip()
                limit = int(limit_raw) if limit_raw.isdigit() else None

                self.app.call_from_thread(log.write, f"[bold blue]CSV 파일: {csv_path}[/bold blue]")
                result = malware_scanner.setup_database_from_csv(conn, csv_path, limit=limit)

                if "error" in result:
                    self.app.call_from_thread(log.write, f"[red]{result['error']}[/red]")
                else:
                    self.app.call_from_thread(
                        log.write, f"[green]{result['imported']}개의 악성 해시 데이터를 DB에 등록했습니다.[/green]"
                    )

            else:  # manual
                sha256 = self.query_one("#man_sha256", Input).value
                md5 = self.query_one("#man_md5", Input).value
                sha1 = self.query_one("#man_sha1", Input).value
                name = self.query_one("#man_name", Input).value or "Unknown"
                severity = self.query_one("#man_severity", Input).value or "unknown"

                result = malware_scanner.add_signature_manual(conn, sha256, md5, sha1, name, severity)
                if result.get("warning"):
                    self.app.call_from_thread(log.write, f"[yellow]{result['warning']}[/yellow]")
                color = "green" if result["ok"] else "yellow"
                self.app.call_from_thread(log.write, f"[{color}]{result['message']}[/{color}]")
        finally:
            conn.close()


class SecurityScannerApp(App):
    """Main TUI application."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #scan_checks {
        height: auto;
        margin-bottom: 1;
    }
    RichLog {
        height: 1fr;
        min-height: 12;
        border: round $primary;
        margin-top: 1;
    }
    Label {
        margin-top: 1;
    }
    """

    BINDINGS = [("q", "quit", "종료")]
    TITLE = "Security Scanner"

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("취약점 스캔", id="tab_scan"):
                yield ScanTab()
            with TabPane("악성코드 DB 관리", id="tab_db"):
                yield DBTab()
        yield Footer()


if __name__ == "__main__":
    SecurityScannerApp().run()
