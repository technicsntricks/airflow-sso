import flask_login

from flask_login import current_user, logout_user, login_required, login_user

from flask import url_for, redirect, request, render_template, session, make_response
from urllib.parse import urlparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from airflow import models, configuration
from airflow.configuration import AirflowConfigException
from airflow.utils.db import provide_session
from airflow.utils.log.logging_mixin import LoggingMixin
from airflow.www.app import csrf

log = LoggingMixin().log


def get_config_param(param):
    return str(configuration.conf.get('saml_auth', param))


class SAMLUser(models.User):

    def __init__(self, user):
        self.user = user

    @property
    def is_active(self):
        """Required by flask_login"""
        return True

    @property
    def is_authenticated(self):
        """Required by flask_login"""
        return True

    @property
    def is_anonymous(self):
        """Required by flask_login"""
        return False

    def get_id(self):
        """Returns the current user id as required by flask_login"""
        return self.user.get_id()

    def data_profiling(self):
        """Provides access to data profiling tools"""
        return True

    def is_superuser(self):
        """Access all the things"""
        return True


class AuthenticationError(Exception):
    pass

class SAMLAuthBackend:

    def __init__(self):
        self.login_manager = flask_login.LoginManager()
        self.login_manager.login_view = 'airflow.login'
        self.login_manager.session_protection
        self.flask_app = None
        self.api_url = None

    def prepare_flask_request(self,request):
        # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
        url_data = urlparse(request.url)
        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'request_uri': '/saml/login',
            'server_port': url_data.port,
            'script_name': request.path,
            'get_data': request.args.copy(),
            # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
            # 'lowercase_urlencoding': True,
            'post_data': request.form.copy()
        }

    def init_saml_auth(self,req):
        auth = OneLogin_Saml2_Auth(req, custom_base_path=get_config_param('saml_path'))
        return auth

    def init_app(self, flask_app):
        self.flask_app = flask_app

        self.login_manager.init_app(self.flask_app)

        self.login_manager.user_loader(self.load_user)

        # metadata file route
        self.flask_app.add_url_rule('/saml/metadata.xml',
                            'metadata',
                            self.metadata)

        # sso login uri
        self.flask_app.add_url_rule('/saml/login',
                            'saml_login',
                            self.saml_login,methods=["GET","POST"])

    def login(self, request):
        return redirect(url_for('saml_login'),)

    def metadata(self):
        req = self.prepare_flask_request(request)
        auth = self.init_saml_auth(req)
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if len(errors) == 0:
            resp = make_response(metadata, 200)
            resp.headers['Content-Type'] = 'text/xml'
        else:
            resp = make_response(', '.join(errors), 500)
        return resp

    @provide_session
    @csrf.exempt
    def saml_login(self, session=None):
        req = self.prepare_flask_request(request)
        auth = self.init_saml_auth(req)
        errors = []
        error_reason = None
        not_auth_warn = False
        success_slo = False
        attributes = False
        paint_logout = False
        print(request.args)
        if 'sso' in request.args:
            return redirect(auth.login())
        elif ('sso2' in request.args or  len(request.args) == 0) and ( "Referer" not in request.headers ):
            return_to = '%sadmin/' % request.host_url
            return redirect(auth.login(return_to))
        elif 'slo' in request.args:
            name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
            if 'samlNameId' in session:
                name_id = session['samlNameId']
            if 'samlSessionIndex' in session:
                session_index = session['samlSessionIndex']
            if 'samlNameIdFormat' in session:
                name_id_format = session['samlNameIdFormat']
            if 'samlNameIdNameQualifier' in session:
                name_id_nq = session['samlNameIdNameQualifier']
            if 'samlNameIdSPNameQualifier' in session:
                name_id_spnq = session['samlNameIdSPNameQualifier']

            return redirect(auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq))
        elif 'acs' in request.args:
            auth.process_response()
            errors = auth.get_errors()
            not_auth_warn = not auth.is_authenticated()
            if len(errors) == 0:
                # stuff for flask_login
                username = auth.get_nameid()
                email = auth.get_nameid()
                user = session.query(models.User).filter(
                    models.User.username == username).first()
                if not user:
                    user = models.User(
                        username=username,
                        email=email,
                        is_superuser=True)
                    session.merge(user)
                else :
                    session.merge(user)
                session.commit()
                login_user(SAMLUser(user))
                session.commit()
                # end stuff for flask_login
                self_url = OneLogin_Saml2_Utils.get_self_url(req)
                if 'RelayState' in request.form and self_url != request.form['RelayState']:
                    log.info(len(request.args))
                    log.info(request.args)
                    if request.form['RelayState'] == '':
                        return_to = '%sadmin/' % request.host_url
                        return redirect(auth.login(return_to))
                    else :
                        return redirect(auth.redirect_to(request.form['RelayState']))
        elif 'sls' in request.args:
            request_id = None
            if 'LogoutRequestID' in session:
                request_id = session['LogoutRequestID']
            dscb = lambda: session.clear()
            url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
            errors = auth.get_errors()
            if len(errors) == 0:
                if url is not None:
                    return redirect(url)
                else:
                    success_slo = True
            elif auth.get_settings().is_debug_active():
                error_reason = auth.get_last_error_reason()
        elif "Referer" in request.headers and  len(request.args) == 0 :
            # return redirect(auth.get_slo_url()) # LOgout from one application but cookies will be used for furthur login
            return redirect("https://mpoddar.awsapps.com/start#/signout") # Logout from app completly

        if 'samlUserdata' in session:
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()


    @provide_session
    def load_user(self, userid, session=None):
        if not userid or userid == 'None':
            return None

        user = session.query(models.User).filter(
            models.User.id == int(userid)).first()
        return SAMLUser(user)

    


LOGIN_MANAGER =  SAMLAuthBackend()


def login(self, request):
    return LOGIN_MANAGER.login(request)