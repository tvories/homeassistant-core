"""Config flow for Xcel Itron Smart Meter integration."""
from __future__ import annotations

import logging
import os
import selectors
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import selector, config_validation as cv

from .const import (
    CONF_CERTIFICATE,
    CONF_DEVICE_NAME,
    CONF_KEY,
    CONF_NOT_ON_NETWORK_STAGE_CHOICE,
    CONF_NOW_ON_NETWORK_CHOICE,
    CONF_SMART_METER_NETWORK_CHOICE,
    CONF_SMART_METER_NOT_ON_NETWORK,
    CONF_SMART_METER_ON_NETWORK,
    CONF_WAITING_ON_XCEL_CHOICE,
    DEFAULT_CERT_DIR,
    DEFAULT_DEVICE_NAME,
    DEFAULT_FILE_ENCODING,
    DEFAULT_GENERATED_CERT_FILENAME,
    DEFAULT_GENERATED_KEY_FILENAME,
    DEFAULT_PORT,
    DOMAIN,
)
from .helpers import generate_cert_and_key, get_lfdi, get_existing_cert_and_key

_LOGGER = logging.getLogger(__name__)

# TODO adjust the data schema to the data that you need
STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
    }
)

STEP_ON_NETWORK_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_DEVICE_NAME): str,
        vol.Required(CONF_HOST):  str,
        vol.Required(CONF_PORT): str,
        vol.Required(CONF_CERTIFICATE): str,
        vol.Required(CONF_KEY): str,
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    # If your PyPI package is not built with async, pass your methods
    # to the executor:
    # await hass.async_add_executor_job(
    #     your_validate_func, data["username"], data["password"]
    # )

    hub = PlaceholderHub(data["host"])

    if not await hub.authenticate(data["username"], data["password"]):
        raise InvalidAuth

    # If you cannot connect:
    # throw CannotConnect
    # If the authentication is wrong:
    # InvalidAuth

    # Return info that you want to store in the config entry.
    return {"title": "Name of the device"}


class XcelItronConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Xcel Itron Smart Meter."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> XcelItronOptionsFlowHandler:
        """Get the options flow for Xcel Itron handler."""
        return XcelItronOptionsFlowHandler(config_entry)

    def __init__(self) -> None:
        """Initialize Xcel Itron config flow."""
        self.discovered_meter: str | None = None
        self._errors = {}
        self.lfdi: str | None = None
        self.certificate: str | None = None
        self.key: str | None = None

        # TODO: place discovery info in here eventually

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle a flow initialized by the user."""
        # This is for backwards compatibility.
        return await self.async_step_init(user_input)

    # async def _get_discovered_meter(
    #         self, host: str, bridge_id: str | None = None
    # ) -> DiscoveredXcelItronMeter:
    #     """Return a discovered meter."""
    #     #TODO: write discovery handling
    #     pass

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle a flow start."""
        # Check if the user selects a meter NOT yet on the network
        if (
            user_input is not None
            and user_input[CONF_SMART_METER_NETWORK_CHOICE]
            == CONF_SMART_METER_NOT_ON_NETWORK
        ):
            return await self.async_step_not_on_network()
        if (
            user_input is not None
            and user_input[CONF_SMART_METER_NETWORK_CHOICE]
            == CONF_SMART_METER_ON_NETWORK
        ):
            return await self.async_step_on_network()

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SMART_METER_NETWORK_CHOICE,
                        default=CONF_SMART_METER_NOT_ON_NETWORK,
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=[
                                selector.SelectOptionDict(
                                    value=CONF_SMART_METER_NOT_ON_NETWORK,
                                    label="My smart meter is NOT yet on my network.",
                                ),
                                selector.SelectOptionDict(
                                    value=CONF_SMART_METER_ON_NETWORK,
                                    label="My smart meter is already on my network.",
                                ),
                            ],
                        ),
                    ),
                }
            ),
        )

    async def async_step_not_on_network(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle meter not yet on network setup."""
        # Check for existing cert and key files
        already_generated_files = get_existing_cert_and_key(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR)
        # This is likely the first time the user is setting up the integration so we generate the files
        if not already_generated_files and not self.lfdi and not self.certificate and not self.key:
            _LOGGER.info("Generating new certificate and key files")
            generated_files = generate_cert_and_key()
            self.lfdi = generated_files["lfdi"]
            self.certificate = generated_files["certificate"]
            self.key = generated_files["private_key"]
        elif not self.lfdi and not self.certificate and not self.key: # the user has already run the integration and we don't want to overrite the previously generated files
            _LOGGER.info("Generated files have been found, using them instead of regenerating")
            self.lfdi = already_generated_files["lfdi"]
            self.certificate = already_generated_files["certificate"]
            self.key = already_generated_files["private_key"]

        if (
            # we are still waiting on xcel to set up our device
            user_input is not None
            and user_input[CONF_NOT_ON_NETWORK_STAGE_CHOICE] == CONF_WAITING_ON_XCEL_CHOICE
        ):

            # Write the generated files to the default directory
            # Ensure the directory exists, create it if needed
            if not os.path.exists(os.path.join(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR)):
                os.makedirs(os.path.join(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR))
            cert_file_path = os.path.join(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR, DEFAULT_GENERATED_CERT_FILENAME)
            with open(cert_file_path, "w", encoding=DEFAULT_FILE_ENCODING) as cert_file:
                cert_file.write(self.certificate)

            # Write the key
            key_file_path = os.path.join(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR, DEFAULT_GENERATED_KEY_FILENAME)
            with open(key_file_path, "w", encoding=DEFAULT_FILE_ENCODING) as key_file:
                key_file.write(self.key)


            return self.async_abort(reason="waiting_on_xcel")
        if (
            # our device is now on the network
            user_input is not None
            and user_input[CONF_NOT_ON_NETWORK_STAGE_CHOICE] == CONF_NOW_ON_NETWORK_CHOICE
        ):
            return await self.async_step_on_network()

        if user_input is None:
            # Check for existing certificate and key files. By default, we save generated files
            # to the DEFAULT_CERT_DIR until the user specifies a different directory.


            return self.async_show_form(
                step_id="not_on_network",
                description_placeholders={
                    "lfdi": self.lfdi,
                    "certificate": self.certificate,
                    "key": self.key,
                },
                data_schema=vol.Schema(
                    {
                        vol.Required(
                        CONF_NOT_ON_NETWORK_STAGE_CHOICE,
                        default=CONF_WAITING_ON_XCEL_CHOICE,
                        ): selector.SelectSelector(
                            selector.SelectSelectorConfig(
                                options=[
                                    selector.SelectOptionDict(
                                        value=CONF_WAITING_ON_XCEL_CHOICE,
                                        label="I'm waiting for Xcel to add my device to their system.",
                                    ),
                                    selector.SelectOptionDict(
                                        value=CONF_NOW_ON_NETWORK_CHOICE,
                                        label="My device is now on my network.",
                                    ),
                                ],
                            ),
                        ),
                        # vol.Optional(CONF_CERT_DIR, default=os.path.join(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR)): str,
                    }
                ),
            )

    async def async_step_waiting_on_xcel(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle letting a user know they need to come back to the integration once their device is on the network."""
        if(user_input is not None):
            return self.async_abort(reason="waiting_on_xcel")

        return self.async_show_form(
            step_id="waiting_on_xcel",
            data_schema=vol.Schema({})
        )




        # if (
        #     user_input is not None
        #     and self.discovered_meter is not None
        #     and user_input["smart_meter_on_network"] in self.discovered_meter
        # )

        # errors: dict[str, str] = {}
        # if user_input is not None:
        #     try:
        #         info = await validate_input(self.hass, user_input)
        #     except CannotConnect:
        #         errors["base"] = "cannot_connect"
        #     except InvalidAuth:
        #         errors["base"] = "invalid_auth"
        #     except Exception:  # pylint: disable=broad-except
        #         _LOGGER.exception("Unexpected exception")
        #         errors["base"] = "unknown"
        #     else:
        #         return self.async_create_entry(title=info["title"], data=user_input)

        # return self.async_show_form(
        #     step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        # )

    async def async_step_on_network(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the integration with a meter on the network."""

        if self.certificate is None or self.key is None:
            # The integration is unaware of the cert or key so we check if there is are generated files
            _LOGGER.info("Checking for already generated files")
            already_generated_files = get_existing_cert_and_key(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR)
            if already_generated_files is not None:
                _LOGGER.info("Found existing files")
                self.certificate = already_generated_files["certificate"]
                self.key = already_generated_files["private_key"]
                self.lfdi = already_generated_files["lfdi"]
            else:
                _LOGGER.info("No existing files found, user must provide them")

        # if user_input is not None:
        #     return self.async_create_entry(title="", data=user_input)
        if user_input is not None:
            return self.async_abort(reason="on_network")

        if user_input is None:
            return self.async_show_form(
                step_id="on_network",
                data_schema=vol.Schema(
                    {
                    vol.Required(CONF_DEVICE_NAME, default=DEFAULT_DEVICE_NAME): str,
                    vol.Required(CONF_HOST):  str,
                    vol.Required(CONF_PORT, default=DEFAULT_PORT): str,
                    vol.Required(CONF_CERTIFICATE, default=self.certificate): selector.TextSelector(
                            selector.TextSelectorConfig(multiline=True)
                        ),
                    vol.Required(CONF_KEY, default=self.key): selector.TextSelector(
                            selector.TextSelectorConfig(multiline=True)
                        ),
                    },
                )
            )

class XcelItronOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle Xcel Itron options."""

    pass

    # def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
    #     """Initialize Xcel Itron options flow."""
    #     self.config_entry = config_entry

    # async def async_step_init(
    #     self, user_input: dict[str, Any] | None = None
    # ) -> FlowResult:
    #     """Manage the Xcel Itron options."""
    #     return await self.async_step_user()

    # async def async_step_user(
    #     self, user_input: dict[str, Any] | None = None
    # ) -> FlowResult:
    #     """Manage the Xcel Itron options."""
    #     errors: dict[str, str] = {}

    #     if user_input is not None:
    #         # TODO validate user input
    #         return self.async_create_entry(title="", data=user_input)

    #     return self.async_show_form(
    #         step_id="user", data_schema=vol.Schema({}), errors=errors
    #     )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
