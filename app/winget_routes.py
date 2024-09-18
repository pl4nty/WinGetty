import os
import requests
from flask import (
    Blueprint,
    jsonify,
    render_template,
    request,
    redirect,
    url_for,
    current_app,
    send_from_directory,
    flash,
)
from flask_login import login_required
from functools import wraps
import jwt
from sqlalchemy import and_, or_
from werkzeug.http import parse_range_header
from werkzeug.utils import secure_filename

from app.utils import create_installer, save_file, basedir
from app import db, settings
from app.models import (
    InstallerSwitch,
    Package,
    PackageVersion,
    Installer,
    Setting,
    User,
)


winget = Blueprint("winget", __name__)

# Configuration for Entra
RESOURCE_ID = "6e757b7f-1817-4f8f-968e-d4237473eae7"
SCOPE = "user_impersonation"
OIDC_DISCOVERY_URL = (
    "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
)

# Fetch OIDC configuration
oidc_config = requests.get(OIDC_DISCOVERY_URL).json()
jwks_uri = oidc_config["jwks_uri"]
issuer = oidc_config["issuer"]

# Fetch public keys
jwks = requests.get(jwks_uri).json()
public_keys = {
    key["kid"]: jwt.algorithms.RSAAlgorithm.from_jwk(key) for key in jwks["keys"]
}


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"message": "Token is missing!"}), 403

        try:
            token = token.split(" ")[1]
            unverified_header = jwt.get_unverified_header(token)
            rsa_key = public_keys.get(unverified_header["kid"])
            # if not rsa_key:
            #     return jsonify({"message": "Token is invalid!"}), 403

            decoded_token = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=RESOURCE_ID,
                issuer=issuer,
            )
            if SCOPE not in decoded_token.get("scp", "").split():
                return (
                    jsonify({"message": "Token does not have the required scope!"}),
                    403,
                )
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid!"}), 403

        return f(*args, **kwargs)

    return decorated


@winget.route("/")
def index():
    return "WinGet API is running, see documentation for more information", 200


@winget.route("/information")
def information():
    return jsonify(
        {
            "Data": {
                "SourceIdentifier": Setting.get("REPO_NAME").get_value(),
                "ServerSupportedVersions": [
                    "1.4.0",
                    "1.5.0",
                    "1.6.0",
                    "1.7.0",
                    "1.8.0",
                ],
                "Authentication": {
                    "AuthenticationType": "microsoftEntraId",
                    "MicrosoftEntraIdAuthenticationInfo": {
                        "Resource": RESOURCE_ID,
                        "Scope": SCOPE,
                    },
                },
            }
        }
    )


@winget.route("/packageManifests/<name>", methods=["GET"])
@token_required
def get_package_manifest(name):
    package = Package.query.filter_by(identifier=name).first()
    if package is None:
        return jsonify({}), 204
    return jsonify(package.generate_output())


@winget.route("/manifestSearch", methods=["POST"])
@token_required
def manifest_search():
    request_data = request.get_json()
    current_app.logger.info(f"Received manifestSearch request: {request_data}")

    maximum_results = request_data.get("MaximumResults", 50)

    # Initialize the base query
    packages_query = Package.query

    # Process Filters and Inclusions
    combined_filters = request_data.get("Filters", []) + request_data.get(
        "Inclusions", []
    )
    filter_conditions = []

    # Handle the main query part
    if "Query" in request_data:
        main_query = request_data["Query"]
        keyword = main_query.get("KeyWord")
        match_type = main_query.get("MatchType")
        if match_type == "Exact":
            filter_conditions.append(
                or_(Package.name == keyword, Package.identifier == keyword)
            )

    for filter_entry in combined_filters:
        field = {
            "PackageName": Package.name,
            "PackageIdentifier": Package.identifier,
            "PackageFamilyName": Package.identifier,  # Update these mappings based on your schema
            "ProductCode": Package.name,  # Update these mappings based on your schema
            "Moniker": Package.name,  # Update these mappings based on your schema
        }.get(filter_entry.get("PackageMatchField"))

        if not field:
            current_app.logger.warning(
                f"Unsupported PackageMatchField: {filter_entry.get('PackageMatchField')}"
            )
            continue

        keyword = filter_entry.get("RequestMatch", {}).get("KeyWord", "")
        match_type = filter_entry.get("RequestMatch", {}).get("MatchType")

        if match_type == "Exact":
            filter_conditions.append(field == keyword)
        elif match_type in ["Partial", "Substring", "CaseInsensitive"]:
            filter_conditions.append(field.ilike(f"%{keyword}%"))
        else:
            current_app.logger.warning(f"Invalid match type: {match_type}")
            continue

    # Apply the filter conditions with or_
    if filter_conditions:
        packages_query = packages_query.filter(or_(*filter_conditions))

    # Apply limit and execute query
    packages_query = packages_query.limit(maximum_results)
    packages = packages_query.all()

    # Generate output data
    output_data = [
        package.generate_output_manifest_search()
        for package in packages
        if package.versions and any(version.installers for version in package.versions)
    ]
    if not output_data:
        current_app.logger.info("No packages found.")
        return jsonify({}), 204

    current_app.logger.info(f"Returning {len(output_data)} packages.")
    current_app.logger.info(f"Output Data: {output_data}")
    return jsonify({"Data": output_data})
