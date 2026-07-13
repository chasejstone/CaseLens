from __future__ import annotations

import os
import tempfile


os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["EVIDENCE_ROOT"] = tempfile.mkdtemp(prefix="caselens-test-")
os.environ["JWT_SECRET"] = "test-secret-with-more-than-24-characters"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "change-this-password"
