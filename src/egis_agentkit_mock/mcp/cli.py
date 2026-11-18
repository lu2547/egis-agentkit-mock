"""启动四个独立 Mock 服务，并统一管理启动失败和退出清理。"""

import argparse
import json
import signal
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

import uvicorn

from .oauth import create_oauth_app
from .server import create_mcp_app
from .settings import DEFAULT_CONFIG, load_settings
from .tls import generate_certificates


def _serve_all(config, settings):
    """父进程管理子服务，任一服务退出时收尾其余子进程。"""
    stopping = False

    def stop(signum, frame):
        nonlocal stopping
        stopping = True

    processes = []
    with ExitStack() as cleanup:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous = signal.signal(signum, stop)
            cleanup.callback(signal.signal, signum, previous)
        try:
            for instance in settings.instances:
                for service in ("oauth", "mcp"):
                    process = subprocess.Popen(
                        [
                            sys.executable,
                            "-m",
                            "egis_agentkit_mock.mcp",
                            "--config",
                            str(config),
                            "serve",
                            "--instance",
                            instance.name,
                            "--service",
                            service,
                        ]
                    )
                    processes.append(process)
            while not stopping and all(process.poll() is None for process in processes):
                time.sleep(settings.process_poll_seconds)
            if not stopping:
                raise SystemExit("一个 Mock 子服务意外退出，请检查上面的启动日志")
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=settings.shutdown_timeout_seconds)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("certificates", help="生成本地 HTTPS 证书")
    commands.add_parser("connectors", help="输出管理员登记连接器的 JSON")
    serve = commands.add_parser("serve", help="启动两套 MCP 和 OAuth 服务")
    serve.add_argument("--instance", choices=["reports", "directory"])
    serve.add_argument("--service", choices=["oauth", "mcp"])
    args = parser.parse_args()
    settings = load_settings(args.config)
    if args.command == "certificates":
        generate_certificates(settings)
        print(f"开发 CA 已写入 {settings.tls.ca_certificate.resolve()}")
        return
    if args.command == "connectors":
        print(
            json.dumps(
                [instance.connector() for instance in settings.instances],
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    if bool(args.instance) != bool(args.service):
        parser.error("--instance 和 --service 必须同时指定")
    if not settings.tls.certificate.is_file() or not settings.tls.private_key.is_file():
        parser.error("请先执行 agentkit-mock-mcp certificates 生成 HTTPS 证书")
    if args.instance is None:
        _serve_all(args.config.resolve(), settings)
        return
    instance = next(item for item in settings.instances if item.name == args.instance)
    app = (
        create_oauth_app(settings, instance)
        if args.service == "oauth"
        else create_mcp_app(settings, instance)
    )
    port = instance.oauth_port if args.service == "oauth" else instance.mcp_port
    uvicorn.run(
        app,
        host=settings.host,
        port=port,
        ssl_certfile=str(settings.tls.certificate),
        ssl_keyfile=str(settings.tls.private_key),
        log_level=settings.log_level,
        access_log=False,
        timeout_graceful_shutdown=settings.shutdown_timeout_seconds,
    )
