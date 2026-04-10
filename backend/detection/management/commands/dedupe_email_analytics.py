from django.core.management.base import BaseCommand
from django.db import transaction

from detection.models import EmailAnalysis


class Command(BaseCommand):
    help = (
        'Normalize and de-duplicate analytics identity by user_email so user metrics '
        'reflect people instead of installation IDs.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--fill-from-sender',
            action='store_true',
            help='Backfill empty user_email from sender_email for legacy records.',
        )
        parser.add_argument(
            '--delete-duplicate-events',
            action='store_true',
            help='Delete exact duplicate analysis events for same user_email and fingerprint.',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would change without writing to the database.',
        )

    def _normalized(self, value):
        return (value or '').strip().lower()

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        fill_from_sender = options['fill_from_sender']
        delete_duplicates = options['delete_duplicate_events']

        before_users = (
            EmailAnalysis.objects.exclude(user_email='')
            .values('user_email')
            .distinct()
            .count()
        )

        normalized_updates = 0
        installation_backfills = 0
        sender_backfills = 0

        rows = list(
            EmailAnalysis.objects.all().only(
                'id', 'installation_id', 'user_email', 'sender_email', 'subject', 'email_body', 'verdict', 'risk_score'
            )
        )

        # Build a map from installation_id -> known user_email from existing data.
        installation_to_email = {}
        for row in rows:
            normalized_email = self._normalized(row.user_email)
            if normalized_email and row.installation_id:
                installation_to_email[row.installation_id] = normalized_email

        ids_to_update = []
        ids_to_delete = []

        seen_fingerprints = set()
        for row in rows:
            original_email = row.user_email or ''
            normalized_email = self._normalized(original_email)

            if normalized_email != original_email:
                normalized_updates += 1

            if not normalized_email and row.installation_id in installation_to_email:
                normalized_email = installation_to_email[row.installation_id]
                installation_backfills += 1

            if not normalized_email and fill_from_sender:
                normalized_email = self._normalized(row.sender_email)
                if normalized_email:
                    sender_backfills += 1

            if normalized_email != original_email:
                row.user_email = normalized_email
                ids_to_update.append(row)

            if delete_duplicates and normalized_email:
                fingerprint = (
                    normalized_email,
                    (row.subject or '').strip(),
                    (row.email_body or '').strip(),
                    row.verdict,
                    float(row.risk_score or 0),
                )
                if fingerprint in seen_fingerprints:
                    ids_to_delete.append(row.id)
                else:
                    seen_fingerprints.add(fingerprint)

        if dry_run:
            self.stdout.write(self.style.WARNING('Dry run mode: no database writes were made.'))
        else:
            with transaction.atomic():
                if ids_to_update:
                    EmailAnalysis.objects.bulk_update(ids_to_update, ['user_email'])
                if ids_to_delete:
                    EmailAnalysis.objects.filter(id__in=ids_to_delete).delete()

        after_users = (
            EmailAnalysis.objects.exclude(user_email='')
            .values('user_email')
            .distinct()
            .count()
        )
        if dry_run:
            after_users = before_users if not ids_to_update else 'would change after apply'

        self.stdout.write(self.style.SUCCESS('Email analytics de-duplication summary'))
        self.stdout.write(f'- rows scanned: {len(rows)}')
        self.stdout.write(f'- normalized user_email values: {normalized_updates}')
        self.stdout.write(f'- backfilled via installation mapping: {installation_backfills}')
        self.stdout.write(f'- backfilled via sender_email: {sender_backfills}')
        self.stdout.write(f'- duplicate events deleted: {len(ids_to_delete)}')
        self.stdout.write(f'- unique users before: {before_users}')
        self.stdout.write(f'- unique users after: {after_users}')
