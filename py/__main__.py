"""
Entry point: python -m py [demo|interactive|serve]
"""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="python -m py",
        description="ANCHOR DEX — Fully On-Chain Bitcoin DEX Simulation",
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="demo",
        choices=["demo", "interactive", "serve"],
        help="demo (default): run all test scenarios; "
             "interactive: command-line REPL; "
             "serve: start Flask API",
    )
    parser.add_argument("--host", default="127.0.0.1", help="API host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="API port (default 5000)")
    parser.add_argument("--db", default="anchor_dex.db", help="SQLite path (default anchor_dex.db)")

    args = parser.parse_args()

    if args.mode == "demo":
        from .demo import run_demo
        run_demo()

    elif args.mode == "interactive":
        from .persistence import PersistentDEX
        from .demo import interactive_mode
        pdex = PersistentDEX(args.db)
        interactive_mode(pdex)

    elif args.mode == "serve":
        from .persistence import PersistentDEX
        from .api.flask_app import create_flask_app
        pdex = PersistentDEX(args.db)
        app = create_flask_app(pdex)
        print(f"  ANCHOR DEX API on http://{args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
