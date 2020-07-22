from django.contrib.auth.models import AnonymousUser
from rest_framework import authentication
from rest_framework.authentication import TokenAuthentication
from mozilla_django_oidc.auth import OIDCAuthenticationBackend


class AnonymousAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        """
        Authenticate the request for anyone!
        """
        return AnonymousUser(), None


class AnonymousOrAuthenticatedAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        """
        Authenticate the request for anyone or if a valid token is provided, a user.
        """
        try:
            return TokenAuthentication.authenticate(TokenAuthentication(), request)
        except:
            return AnonymousUser(), None


class KYAuthOIDCBackend(OIDCAuthenticationBackend):
    def create_user(self, claims):
        user = super().create_user(claims)

        user.email = claims.get('email')
        user.first_name = claims.get('given_name', '')
        user.last_name = claims.get('family_name', '')
        user.is_staff = claims.get('staff', False)
        user.is_superuser = claims.get('is_admin', False)
        user.save()

        return user

    def update_user(self, user, claims):
        user.email = claims.get('email')
        user.first_name = claims.get('given_name', '')
        user.last_name = claims.get('family_name', '')
        user.is_staff = claims.get('staff', False)
        user.is_superuser = claims.get('is_admin', False)
        user.save()

        return user
