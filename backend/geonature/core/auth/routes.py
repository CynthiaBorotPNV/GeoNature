"""
    Module d'identificiation provisoire pour test du CAS INPN
"""

import datetime
import xmltodict
import logging
from copy import copy


from flask import (
    Blueprint,
    request,
    make_response,
    redirect,
    current_app,
    jsonify,
    render_template,
    session,
    Response,
)
from sqlalchemy import select
from utils_flask_sqla.response import json_resp

from pypnusershub.db.models import User, Organisme, Application
from pypnusershub.db.tools import encode_token
from pypnusershub.routes import insert_or_update_organism, insert_or_update_role
from geonature.utils import utilsrequests
from geonature.utils.errors import CasAuthentificationError
from geonature.utils.env import db


routes = Blueprint("gn_auth", __name__, template_folder="templates")
log = logging.getLogger()


def get_user_from_id_inpn_ws(id_user):
    URL = f"https://inpn.mnhn.fr/authentication/rechercheParId/{id_user}"
    config_cas = current_app.config["CAS"]
    try:
        response = utilsrequests.get(
            URL,
            (
                config_cas["CAS_USER_WS"]["ID"],
                config_cas["CAS_USER_WS"]["PASSWORD"],
            ),
        )
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
    user = db.session.get(User, user_id)
    if not user.groups:
        if not current_app.config["CAS"]["USERS_CAN_SEE_ORGANISM_DATA"] or organism_id is None:
            # group socle 1
            group_id = current_app.config["BDD"]["ID_USER_SOCLE_1"]
        else:
            # group socle 2
            group_id = current_app.config["BDD"]["ID_USER_SOCLE_2"]
        group = db.session.get(User, group_id)
        user.groups.append(group)
    return user_info
