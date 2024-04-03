from flask import Response, current_app
from geonature.utils.config import config

from geonature.core.auth.providers import ExternalGNAuthProvider
from pypnusershub.auth import Authentication, AuthenticationMeta
from pypnusershub.db.models import User


class ExternalEcrinsAuthProvider(ExternalGNAuthProvider):
    login_url = "llalala"


class ExternalCBNAAuthProvider(ExternalGNAuthProvider):
    login_url = "llalala"


class CasINPNAuthentification(Authentication):
    login_url = config["URL_APPLICATION"]
    is_external = True
    logo = "lala"
    label = "CAS"

    #  ...
    def authenticate(self, *args, **kwargs):
        pass


# CasINPNAuthentification.lo


import datetime
import logging
from typing import Any, Union

import xmltodict

from flask import Response, current_app, jsonify, make_response, redirect, render_template, request
from geonature.utils import utilsrequests
from geonature.utils.errors import GeonatureApiError
from geonature.core.auth.providers import ExternalGNAuthProvider
from pypnusershub.auth import Authentication
from pypnusershub.db import db, models
from pypnusershub.db.tools import encode_token
from pypnusershub.routes import insert_or_update_organism, insert_or_update_role
from sqlalchemy import select

log = logging.getLogger()


class CasAuthentificationError(GeonatureApiError):
    pass


AUTHENTIFICATION_CONFIG = {
    "PROVIDER_NAME": "inpn",
    "EXTERNAL_PROVIDER": True,
}

CAS_AUTHENTIFICATION = True
PUB_URL = "https://ginco2-preprod.mnhn.fr/"
CAS_PUBLIC = dict(
    URL_LOGIN="https://inpn.mnhn.fr/auth/login",
    URL_LOGOUT="https://inpn.mnhn.fr/auth/logout",
    URL_VALIDATION="https://inpn.mnhn.fr/auth/serviceValidate",
)
from geonature.custom_bis import user_cs, pw

CAS_USER_WS = dict(
    URL="https://inpn.mnhn.fr/authentication/information",
    BASE_URL="https://inpn.mnhn.fr/authentication/",
    ID="",
    PASSWORD="",
)
USERS_CAN_SEE_ORGANISM_DATA = False


def get_user_from_id_inpn_ws(id_user):
    URL = f"https://inpn.mnhn.fr/authentication/rechercheParId/{id_user}"
    try:
        response = utilsrequests.get(
            URL,
            (
                CAS_USER_WS["ID"],
                CAS_USER_WS["PASSWORD"],
            ),
        )
        print("RESPPP", response.status_code)
        assert response.status_code == 200
        return response.json()
    except AssertionError:
        log.error("Error with the inpn authentification service")


def insert_user_and_org(info_user):
    organism_id = info_user["codeOrganisme"]
    if info_user["libelleLongOrganisme"] is not None:
        organism_name = info_user["libelleLongOrganisme"]
    else:
        organism_name = "Autre"

    user_login = info_user["login"]
    user_id = info_user["id"]
    try:
        assert user_id is not None and user_login is not None
    except AssertionError:
        log.error("'CAS ERROR: no ID or LOGIN provided'")
        raise CasAuthentificationError("CAS ERROR: no ID or LOGIN provided", status_code=500)
    # Reconciliation avec base GeoNature
    if organism_id:
        organism = {"id_organisme": organism_id, "nom_organisme": organism_name}
        insert_or_update_organism(organism)
    user_info = {
        "id_role": user_id,
        "identifiant": user_login,
        "nom_role": info_user["nom"],
        "prenom_role": info_user["prenom"],
        "id_organisme": organism_id,
        "email": info_user["email"],
        "active": True,
    }
    user_info = insert_or_update_role(user_info)
    user = db.session.get(models.User, user_id)
    # if not user.groups:
    #     if not current_app.config["CAS"]["USERS_CAN_SEE_ORGANISM_DATA"] or organism_id is None:
    #         # group socle 1
    #         group_id = current_app.config["BDD"]["ID_USER_SOCLE_1"]
    #     else:
    #         # group socle 2
    #         group_id = current_app.config["BDD"]["ID_USER_SOCLE_2"]
    #     group = db.session.get(models.User, group_id)
    #     user.groups.append(group)
    return user


class AuthenficationCASINPN(Authentication):
    id_provider = "cas_inpn"
    label = "CAS INPN"
    is_external = True
    is_uh = False

    @property
    def login_url(self):
        gn_api = current_app.config["API_ENDPOINT"]
        base_url = CAS_PUBLIC["URL_LOGIN"]
        return f"{CAS_PUBLIC['URL_LOGIN']}?service={gn_api+'/auth/login/cas_inpn'}"

    @property
    def logout_url(self):
        gn_api = current_app.config["API_ENDPOINT"]
        base_url = CAS_PUBLIC["URL_LOGOUT"]
        return f"{base_url}?service={gn_api}/auth/logout"

    def authenticate(self, *args, **kwargs) -> Union[Response, models.User]:
        print("ARGS AUTH", request.args)
        params = request.args
        if "ticket" in params:
            print("TOTOTOOOOOOI")
            base_url = current_app.config["API_ENDPOINT"] + "/auth/login/cas_inpn"
            url_validate = "{url}?ticket={ticket}&service={service}".format(
                url=CAS_PUBLIC["URL_VALIDATION"],
                ticket=params["ticket"],
                service=base_url,
            )

            response = utilsrequests.get(url_validate)
            user = None
            xml_dict = xmltodict.parse(response.content)
            resp = xml_dict["cas:serviceResponse"]
            if "cas:authenticationSuccess" in resp:
                user = resp["cas:authenticationSuccess"]["cas:user"]
            if user:
                ws_user_url = "{url}/{user}/?verify=false".format(url=CAS_USER_WS["URL"], user=user)
                try:
                    response = utilsrequests.get(
                        ws_user_url,
                        (
                            CAS_USER_WS["ID"],
                            CAS_USER_WS["PASSWORD"],
                        ),
                    )
                    assert response.status_code == 200
                except AssertionError:
                    log.error("Error with the inpn authentification service")
                    raise CasAuthentificationError(
                        "Error with the inpn authentification service", status_code=500
                    )
                info_user = response.json()
                user = insert_user_and_org(info_user)
                db.session.commit()
                organism_id = info_user["codeOrganisme"]
                if not organism_id:
                    organism_id = (
                        db.session.execute(
                            select(models.Organisme).filter_by(nom_organisme="Autre"),
                        )
                        .scalar_one()
                        .id_organisme,
                    )
                # user.id_organisme = organism_id
                return user
            else:
                log.info("Erreur d'authentification lié au CAS, voir log du CAS")
                log.error("Erreur d'authentification lié au CAS, voir log du CAS")
                return render_template(
                    "cas_login_error.html",
                    cas_logout=CAS_PUBLIC["URL_LOGOUT"],
                    url_geonature=current_app.config["URL_APPLICATION"],
                )
        return jsonify({"message": "Authentification error"}, 500)

    def revoke(self) -> Any:
        pass


# Accueil : https://ginco2-preprod.mnhn.fr/ (URL publique) + http://ginco2-preprod.patnat.mnhn.fr/ (URL privée)


AUTHENTICATION_CLASS = [
    AuthenficationCASINPN,
]
