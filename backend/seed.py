"""
Seed PortWatch Pro with realistic demo data.

Creates a demo user, a few projects, and a spread of scans (including repeat
scans of the same target so the diff and trend features have data), plus a
schedule and a notification channel. Runs in simulation mode so it never needs
nmap or a live target.

Usage:
    cd backend && python seed.py
    # then log in with demo@portwatch.io / demopass123
"""

import os

os.environ.setdefault("PORTWATCH_SIMULATE", "1")
os.environ.setdefault("PORTWATCH_SCHEDULER", "0")
os.environ["PORTWATCH_NO_DEFAULT_APP"] = "1"

from datetime import timedelta

from app import create_app  # sets up sys.path for the short-name imports below
from core.config import Config, utcnow
from models.db import db, User, Project, Schedule, NotificationChannel
import scan_service


class SeedConfig(Config):
    SIMULATE_SCANS = True
    SCHEDULER_ENABLED = False
    SCAN_JOBS_INLINE = True


DEMO_EMAIL = "demo@portwatch.io"
DEMO_PASSWORD = "demopass123"

PROJECTS = [
    ("Acme Corp - External Perimeter", "Internet-facing production hosts and edge services",
     ["api.acme.com", "shop.acme.com", "vpn.acme.com", "mail.acme.com"], "*.acme.com"),
    ("Internal Lab Network", "Segmented internal test range",
     ["10.0.4.11", "10.0.4.22", "db.internal.lab"], ""),
    ("Client B - Web Estate", "Managed WordPress and marketing sites",
     ["www.clientb.io", "blog.clientb.io"], "*.clientb.io"),
]


def run():
    app = create_app(SeedConfig)
    with app.app_context():
        # Idempotent: wipe demo user's data if re-run.
        existing = User.query.filter_by(email=DEMO_EMAIL).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()

        user = User(email=DEMO_EMAIL, name="Demo Analyst", role="admin")
        user.set_password(DEMO_PASSWORD)
        db.session.add(user)
        db.session.commit()
        print(f"Created user {DEMO_EMAIL} / {DEMO_PASSWORD} (role: {user.role})")

        first_project = None
        for name, desc, targets, allowlist in PROJECTS:
            project = Project(user_id=user.id, name=name, description=desc,
                              allowed_targets=allowlist)
            db.session.add(project)
            db.session.commit()
            first_project = first_project or project
            print(f"  Project: {name}")

            for i, target in enumerate(targets):
                profile = "deep" if i == 0 else "standard"
                cred = i == 0
                scan = scan_service.perform_scan(
                    project, target, profile=profile,
                    credential_checks=cred, trigger="manual",
                    authorised=True, requested_by=user,
                )
                # Backdate the timestamp so the trend chart shows history.
                scan.timestamp = utcnow() - timedelta(days=len(targets) - i, hours=i)
                db.session.commit()
                print(f"    scan {target:22s} -> {scan.risk_grade} ({scan.risk_score}/100)")

            # A repeat scan of the first target → gives diff + trend movement.
            repeat = scan_service.perform_scan(
                project, targets[0], profile="deep",
                credential_checks=True, trigger="scheduled",
                authorised=True, requested_by=user,
            )
            print(f"    scan {targets[0]:22s} -> {repeat.risk_grade} ({repeat.risk_score}/100) [repeat/scheduled]")

        # A live schedule on the first project.
        sched = Schedule(
            user_id=user.id, project_id=first_project.id,
            target="api.acme.com", profile="standard",
            interval_hours=24, enabled=True, authorised=True,
            next_run=utcnow() + timedelta(hours=24),
        )
        db.session.add(sched)

        # A notification channel.
        channel = NotificationChannel(
            user_id=user.id, kind="email", target="soc@acme.com",
            min_grade="C", enabled=True,
        )
        db.session.add(channel)
        db.session.commit()

        totals = {
            "projects": Project.query.filter_by(user_id=user.id).count(),
            "scans": sum(len(p.scans) for p in user.projects),
        }
        print(f"\nSeed complete: {totals['projects']} projects, {totals['scans']} scans, "
              f"1 schedule, 1 notification channel.")
        print(f"Log in at http://localhost:5000 with {DEMO_EMAIL} / {DEMO_PASSWORD}")


if __name__ == "__main__":
    run()
