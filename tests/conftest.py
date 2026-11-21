"""
Cyber Hub Backend - shared test setup
Developed by Syed Muhammad Tayyab

Parts 17-20 talk to the desktop (toasts, run-at-sign-in entry). No test may pop up a real toast or write a
real start-up entry on the developer's PC, so both use their in-memory backends for the whole test run.
"""
import pytest


@pytest.fixture(autouse=True)
def _no_desktop_side_effects(monkeypatch):
    monkeypatch.setenv("CYBERHUB_TOAST_BACKEND", "memory")
    monkeypatch.setenv("CYBERHUB_DESKTOP_BACKEND", "memory")
