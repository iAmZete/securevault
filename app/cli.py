"""Management commands: ``flask --app run.py <command>``.

    init               create directories, master key and database
    create-admin       create the first Admin account (interactive)
    seed-demo          create demo accounts and synthetic documents
    rotate-master-key  re-wrap every DEK under a new master key
"""
from __future__ import annotations

import os
import shutil
from datetime import datetime
from pathlib import Path

import click
from flask import Flask, current_app

from .extensions import db
from .models import Role, StoredFile, User
from .security.crypto import (CryptoService, _write_secret, encode_master_key,
                              generate_master_key_file, load_master_key)
from .security.passwords import hash_password
from .security.validation import ValidationError, validate_password_strength, validate_username

DEMO_PASSWORD = "Demo-Passw0rd!2026"


def register_cli(app: Flask) -> None:
    @app.cli.command("init")
    def init_cmd():
        """Create directories, the master key (if absent) and the database."""
        key_file = Path(current_app.config["MASTER_KEY_FILE"])
        if key_file.exists():
            click.echo(f"Master key already present: {key_file}")
        else:
            generate_master_key_file(key_file)
            click.secho(f"Generated new 256-bit master key: {key_file} (mode 600)", fg="green")
            click.secho("Back this file up securely. Losing it makes all files unrecoverable.",
                        fg="yellow")
        key, version = load_master_key(key_file, current_app.config["MASTER_KEY_ENFORCE_PERMISSIONS"])
        current_app.extensions["securevault_crypto"] = CryptoService(key, key_version=version)
        db.create_all()
        click.secho("Database ready.", fg="green")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.password_option(prompt="Password", confirmation_prompt=True)
    def create_admin_cmd(username: str, password: str):
        """Create an Admin account."""
        try:
            username = validate_username(username)
            validate_password_strength(password, username)
        except ValidationError as exc:
            raise click.ClickException(str(exc))
        if db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none():
            raise click.ClickException("User already exists.")
        db.session.add(User(username=username, role=Role.ADMIN.value,
                            password_hash=hash_password(password), must_change_password=False))
        db.session.commit()
        click.secho(f"Admin '{username}' created.", fg="green")

    @app.cli.command("seed-demo")
    def seed_demo_cmd():
        """Create demo accounts (synthetic data only) for the presentation."""
        accounts = [
            ("admin", Role.ADMIN), ("alice", Role.STAFF), ("bob", Role.STAFF), ("auditor", Role.AUDITOR),
        ]
        for username, role in accounts:
            if db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none():
                click.echo(f"  - {username} already exists")
                continue
            db.session.add(User(username=username, role=role.value,
                                password_hash=hash_password(DEMO_PASSWORD), must_change_password=False))
            click.echo(f"  + {username} ({role.value})")
        db.session.commit()

        from .security.validation import validate_upload
        from .services import storage

        alice = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
        if alice.files.count() == 0:
            samples = {
                "intake-form-client-0001.txt": b"SYNTHETIC DATA - Intake form for test client 0001\n",
                "care-plan-client-0001.txt": b"SYNTHETIC DATA - Care plan: weekly check-ins.\n",
            }
            for name, content in samples.items():
                storage.save_encrypted(alice.id, validate_upload(name, content, 10 * 1024 * 1024))
            click.echo("  + 2 synthetic documents for alice")
        click.secho(f"Demo password for all demo accounts: {DEMO_PASSWORD}", fg="yellow")
        click.secho("Demo accounts are for local testing only. Never use them with real data.",
                    fg="yellow")

    @app.cli.command("rotate-master-key")
    @click.confirmation_option(prompt="Re-wrap all data-encryption keys under a NEW master key?")
    def rotate_master_key_cmd():
        """Generate a new master key and re-wrap every file's DEK.

        File ciphertext is untouched; only the small wrapped DEKs change. This
        is the main operational benefit of envelope encryption.
        """
        key_file = Path(current_app.config["MASTER_KEY_FILE"])
        old_service: CryptoService = current_app.extensions["securevault_crypto"]
        if old_service is None:
            raise click.ClickException("No current master key loaded.")

        records = db.session.execute(db.select(StoredFile)).scalars().all()
        new_version = max([r.key_version for r in records], default=old_service.key_version) + 1

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        new_key = AESGCM.generate_key(bit_length=256)
        new_service = CryptoService(new_key, key_version=new_version)
        try:
            for r in records:
                dek = old_service.unwrap_dek(r.wrapped_dek, r.dek_nonce, r.storage_name, r.owner_id,
                                             r.key_version)
                r.wrapped_dek, r.dek_nonce = new_service.wrap_dek(dek, r.storage_name, r.owner_id)
                r.key_version = new_version
        except Exception as exc:
            db.session.rollback()
            raise click.ClickException(f"Rotation aborted, no changes made: {exc}")

        backup = key_file.with_name(f"{key_file.name}.{datetime.now():%Y%m%d%H%M%S}.bak")
        shutil.copy2(key_file, backup)
        if os.name == "posix":
            os.chmod(backup, 0o600)
        _write_secret(key_file, encode_master_key(new_key, new_version))
        db.session.commit()
        current_app.extensions["securevault_crypto"] = new_service
        click.secho(f"Rotated {len(records)} keys to version {new_version}.", fg="green")
        click.secho(f"Old key backed up to {backup}. Destroy it once backups are verified.",
                    fg="yellow")
