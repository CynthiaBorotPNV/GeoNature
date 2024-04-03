from flask import Response, current_app
from geonature.utils.config import config

from geonature.core.auth.providers import ExternalGNAuthProvider
from pypnusershub.auth import Authentication
from pypnusershub.db.models import User


class ExternalEcrinsAuthProvider(ExternalGNAuthProvider):
    login_url = "llalala"


class ExternalCBNAAuthProvider(ExternalGNAuthProvider):
    login_url = "llalala"


class CasINPNAuthentification(Authentication):
    login_url = config["URL_APPLICATION"]
    is_external = True
    logo = "lala"
    label = "lala"

    #  ...
    def authenticate(self, *args, **kwargs):
        pass


AUTHENTICATION_CLASS = [
    CasINPNAuthentification,
    ExternalEcrinsAuthProvider,
    ExternalCBNAAuthProvider,
]
