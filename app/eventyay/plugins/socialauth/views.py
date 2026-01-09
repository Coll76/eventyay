import logging
from enum import StrEnum
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import SocialApp
from django.conf import settings
from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext_lazy as _
from django.views.generic import TemplateView, View
from pydantic import ValidationError

from eventyay.base.models import User
from eventyay.base.settings import GlobalSettingsObject
from eventyay.control.permissions import AdministratorPermissionRequiredMixin
from eventyay.eventyay_common.views.auth import process_login_and_set_cookie
from eventyay.helpers.urls import build_absolute_uri

from .schemas.login_providers import LoginProviders
from .schemas.oauth2_params import OAuth2Params

logger = logging.getLogger(__name__)
adapter = get_adapter()


class OAuthLoginView(View):
    def get(self, request: HttpRequest, provider: str) -> HttpResponse:
        self.set_oauth2_params(request)
        
        # Save next URL to session for post-login redirect
        next_url = request.GET.get('next', '')
        if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts=None):
            request.session['socialauth_next_url'] = next_url

        # Check provider preference and set keep_logged_in flag
        gs = GlobalSettingsObject()
        login_providers = gs.settings.get('login_providers', as_type=dict) or {}
        provider_settings = login_providers.get(provider, {})
        
        if provider_settings.get('preferred', False):
            request.session['socialauth_keep_logged_in'] = True
        else:
            request.session.pop('socialauth_keep_logged_in', None)

        client_id = provider_settings.get('client_id')
        provider_instance = adapter.get_provider(request, provider, client_id=client_id)

        base_url = provider_instance.get_login_url(request)
        query_params = {'next': build_absolute_uri('plugins:socialauth:social.oauth.return')}
        parsed_url = urlparse(base_url)
        updated_url = parsed_url._replace(query=urlencode(query_params))
        return redirect(urlunparse(updated_url))

    @staticmethod
    def set_oauth2_params(request: HttpRequest) -> None:
        """
        Extract and store OAuth2 params from 'next' URL for Talk module SSO integration.
        Only relative URLs are accepted for security.
        """
        next_url = request.GET.get('next', '')
        if not next_url:
            return

        parsed = urlparse(next_url)

        # Block absolute URLs
        if parsed.netloc or parsed.scheme:
            return

        params = parse_qs(parsed.query)
        sanitized_params = {k: v[0] for k, v in params.items() if k in OAuth2Params.model_fields.keys()}

        try:
            oauth2_params = OAuth2Params.model_validate(sanitized_params)
            request.session['oauth2_params'] = oauth2_params.model_dump()
        except ValidationError as e:
            logger.warning('Ignore invalid OAuth2 parameters: %s.', e)



class OAuthReturnView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        try:
            user = self.get_or_create_user(request)
            
            keep_logged_in = request.session.pop('socialauth_keep_logged_in', False)
            
            # Handle Talk module OAuth2 flow if params exist
            oauth2_params = request.session.pop('oauth2_params', {})
            if oauth2_params:
                try:
                    oauth2_params = OAuth2Params.model_validate(oauth2_params)
                    query_string = urlencode(oauth2_params.model_dump())
                    auth_url = reverse('eventyay_common:oauth2_provider.authorize')
                    # Clear socialauth_next_url since OAuth2 flow takes over
                    request.session.pop('socialauth_next_url', None)
                    response = process_login_and_set_cookie(request, user, keep_logged_in)
                    return redirect(f'{auth_url}?{query_string}')
                except ValidationError as e:
                    logger.warning('Ignore invalid OAuth2 parameters: %s.', e)
            
            # Re-validate next URL from session to prevent tampering
            next_url = request.session.pop('socialauth_next_url', None)
            if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts=None):
                request.session['socialauth_next_url'] = next_url
            
            response = process_login_and_set_cookie(request, user, keep_logged_in)
            return response
        except AttributeError as e:
            messages.error(request, _('Error while authorizing: no email address available.'))
            logger.error('Error while authorizing: %s', e)
            return redirect('eventyay_common:auth.login')

    @staticmethod
    def get_or_create_user(request: HttpRequest) -> User:
        """
        Get or create user from social auth data. Updates Wikimedia username if changed.
        """
        social_account = request.user.socialaccount_set.filter(
            provider='mediawiki'
        ).last()
        wikimedia_username = ''

        if social_account:
            extra_data = social_account.extra_data
            wikimedia_username = extra_data.get('username', extra_data.get('realname', ''))

        user, created = User.objects.get_or_create(
            email=request.user.email,
            defaults={
                'locale': getattr(request, 'LANGUAGE_CODE', settings.LANGUAGE_CODE),
                'timezone': getattr(request, 'timezone', settings.TIME_ZONE),
                'auth_backend': 'native',
                'password': '',
                'wikimedia_username': wikimedia_username,
            },
        )

        # Sync Wikimedia username for existing users or if it changed
        if not created and (not user.wikimedia_username or user.wikimedia_username != wikimedia_username):
            user.wikimedia_username = wikimedia_username
            user.save()

        return user


class SocialLoginView(AdministratorPermissionRequiredMixin, TemplateView):
    template_name = 'socialauth/social_auth_settings.html'

    class SettingState(StrEnum):
        ENABLED = 'enabled'
        DISABLED = 'disabled'
        CREDENTIALS = 'credentials'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.gs = GlobalSettingsObject()
        self.set_initial_state()

    def set_initial_state(self):
        """
        Set the initial state of the login providers
        If the login providers are not valid, set them to the default
        """

        def validate_login_providers(login_providers):
            try:
                validated_providers = LoginProviders.model_validate(login_providers)
                return validated_providers
            except ValidationError as e:
                logger.error('Error while validating login providers: %s', e)
                return None

        login_providers = self.gs.settings.get('login_providers', as_type=dict)
        if login_providers is None or validate_login_providers(login_providers) is None:
            self.gs.settings.set('login_providers', LoginProviders().model_dump())

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['login_providers'] = self.gs.settings.get('login_providers', as_type=dict)
        # tickets_domain is only used to append /github/..., so make sure we don't have
        # a trailing /
        context['tickets_domain'] = urljoin(settings.SITE_URL, settings.BASE_PATH).rstrip("/")
        return context

    def post(self, request, *args, **kwargs):
        login_providers = self.gs.settings.get('login_providers', as_type=dict)
        setting_state = request.POST.get('save_credentials', '').lower()

        # Handle preferred provider selection
        preferred_provider = request.POST.get('preferred_provider', '')

        # Reset all preferred flags first
        for provider in LoginProviders.model_fields.keys():
            if provider in login_providers:
                login_providers[provider]['preferred'] = False

        # Set the selected provider as preferred ONLY if it's enabled
        if preferred_provider and preferred_provider in login_providers:
            if login_providers[preferred_provider].get('state', False):
                login_providers[preferred_provider]['preferred'] = True
            else:
                # Log a warning if someone tries to set a disabled provider as preferred
                logger.warning(
                    'Attempted to set disabled provider "%s" as preferred. Ignoring.',
                    preferred_provider
                )

        for provider in LoginProviders.model_fields.keys():
            if setting_state == self.SettingState.CREDENTIALS:
                self.update_credentials(request, provider, login_providers)
            else:
                self.update_provider_state(request, provider, login_providers)

        # Final validation: ensure at least one login method is enabled
        any_enabled = any(
            settings.get('state', False) 
            for settings in login_providers.values()
        )

        if not any_enabled:
            messages.warning(
                request, 
                _('At least one login method must be enabled. Native login has been enabled automatically.')
            )
            login_providers['native']['state'] = True
            # If no other provider is preferred, make native preferred
            if not any(settings.get('preferred', False) for settings in login_providers.values()):
                login_providers['native']['preferred'] = True

        self.gs.settings.set('login_providers', login_providers)
        return redirect(self.get_success_url())

    def update_credentials(self, request, provider, login_providers):
        client_id_value = request.POST.get(f'{provider}_client_id', '')
        secret_value = request.POST.get(f'{provider}_secret', '')

        if client_id_value and secret_value:
            login_providers[provider]['client_id'] = client_id_value
            login_providers[provider]['secret'] = secret_value

            SocialApp.objects.update_or_create(
                provider=provider,
                defaults={
                    'client_id': client_id_value,
                    'secret': secret_value,
                },
            )

    def update_provider_state(self, request, provider, login_providers):
        setting_state = request.POST.get(f'{provider}_login', '').lower()
        if setting_state in [s.value for s in self.SettingState]:
            new_state = setting_state == self.SettingState.ENABLED
            login_providers[provider]['state'] = new_state

            # If disabling a provider that was preferred, unset preferred
            if not new_state and login_providers[provider].get('preferred', False):
                login_providers[provider]['preferred'] = False

                # If this was the only preferred provider and native is enabled,
                # make native the preferred provider
                any_other_preferred = any(
                    p != provider and settings.get('preferred', False)
                    for p, settings in login_providers.items()
                )
                if not any_other_preferred and login_providers.get('native', {}).get('state', False):
                    login_providers['native']['preferred'] = True

    def get_success_url(self) -> str:
        return reverse('plugins:socialauth:admin.global.social.auth.settings')
