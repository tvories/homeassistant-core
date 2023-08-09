"""Config flow for Xcel Itron Smart Meter integration."""
from __future__ import annotations

import logging
import os
import selectors
import shutil
from typing import Any
import aiohttp

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import selector, config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_CERTIFICATE,
    CONF_CERT_PATH,
    CONF_DEVICE_NAME,
    CONF_KEY,
    CONF_KEY_PATH,
    CONF_NOT_ON_NETWORK_STAGE_CHOICE,
    CONF_NOW_ON_NETWORK_CHOICE,
    CONF_SFDI,
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
from .xcel_itron import XcelItronSmartMeter

_LOGGER = logging.getLogger(__name__)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys provided by the user.
    """
    meter = XcelItronSmartMeter(
        host=data[CONF_HOST],
        port=data[CONF_PORT],
        cert_path=data[CONF_CERT_PATH],
        key_path=data[CONF_KEY_PATH],
    )
    try:
        await meter.connect()
    except (aiohttp.ClientConnectionError, TimeoutError):
        return {"base": "cannot_connect"}
    except Exception: # pylint: disable=broad-except
        _LOGGER.exception("Unexpected exception")
        return {"base": "unknown"}

    if not meter.sfdi:
        return {"base": "invalid_auth"}

    return {CONF_SFDI: meter.sfdi}


class XcelItronConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Xcel Itron Smart Meter."""

    VERSION = 1

    # @staticmethod
    # @callback
    # def async_get_options_flow(
    #     config_entry: config_entries.ConfigEntry,
    # ) -> XcelItronOptionsFlowHandler:
    #     """Get the options flow for Xcel Itron handler."""
    #     return XcelItronOptionsFlowHandler(config_entry)

    def __init__(self) -> None:
        """Initialize Xcel Itron config flow."""
        self.discovered_meter: str | None = None
        self._errors = {}
        self.lfdi: str | None = None
        self.cert_path: str | None = None
        self.key_path: str | None = None
        self.certificate: str | None = None
        self.key: str | None = None
        self.sfdi: str | None = None

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
            # Update path references
            self.cert_path = already_generated_files["cert_path"]
            self.key_path = already_generated_files["key_path"]

        if (
            # we are still waiting on xcel to set up our device
            user_input is not None
            and user_input[CONF_NOT_ON_NETWORK_STAGE_CHOICE] == CONF_WAITING_ON_XCEL_CHOICE
        ):

            # Write the generated files to the default directory
            # Ensure the directory exists, create it if needed
            self.cert_path = os.path.join(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR, DEFAULT_GENERATED_CERT_FILENAME)
            self.key_path = os.path.join(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR, DEFAULT_GENERATED_KEY_FILENAME)
            if not os.path.exists(os.path.join(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR)):
                os.makedirs(os.path.join(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR))
            with open(self.cert_path, "w", encoding=DEFAULT_FILE_ENCODING) as cert_file:
                cert_file.write(self.certificate)
            # Write the key
            with open(self.key_path, "w", encoding=DEFAULT_FILE_ENCODING) as key_file:
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
                        #TODO: Convert to single directory field and individual file names instead of the full path
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


    async def async_step_on_network(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the integration with a meter on the network."""

        if self.certificate is None or self.key is None:
            # The integration is unaware of the cert or key so we check if there is are generated files
            _LOGGER.info("Checking for already generated cert and key files")
            already_generated_files = get_existing_cert_and_key(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR)
            if already_generated_files is not None:
                _LOGGER.info("Found existing cert and key files")
                self.certificate = already_generated_files["certificate"]
                self.key = already_generated_files["private_key"]
                self.lfdi = already_generated_files["lfdi"]
                self.cert_path = already_generated_files["cert_path"]
                self.key_path = already_generated_files["key_path"]
            else:
                _LOGGER.info("No existing files found, user must provide them")
        if user_input is not None:
            # Create a temporary file to store the cert and key
            cert_file_path = user_input[CONF_CERT_PATH]
            key_file_path = user_input[CONF_KEY_PATH]
            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(cert_file_path), exist_ok=True)
            os.makedirs(os.path.dirname(key_file_path), exist_ok=True)
            with open(cert_file_path, "w", encoding=DEFAULT_FILE_ENCODING) as file:
                file.write(user_input[CONF_CERTIFICATE])
            with open(key_file_path, "w", encoding=DEFAULT_FILE_ENCODING) as file:
                file.write(user_input[CONF_KEY])

            meter = await validate_input(self.hass, user_input)
            unique_id = meter[CONF_SFDI]

            # We check if an existing xcel integration's cert and key files already exist
            # We do this because we don't actually delete cert and key files if someone removes their integration
            new_cert_path = os.path.join(os.path.dirname(cert_file_path), f'{unique_id}_xcel_itron_cert.pem')
            new_key_path = os.path.join(os.path.dirname(key_file_path), f'{unique_id}_xcel_itron_key.pem')
            existing_cert = os.path.exists(new_cert_path)
            existing_key = os.path.exists(new_key_path)

            if existing_cert or existing_key:
                _LOGGER.info("Existing cert and key files found for meter")
                with open(new_cert_path, "r", encoding=DEFAULT_FILE_ENCODING) as file:
                    existing_cert_contents = file.read()
                _LOGGER.info("Successfully opened existing certificate file")
                with open(new_key_path, "r", encoding=DEFAULT_FILE_ENCODING) as file:
                    existing_key_contents = file.read()
                _LOGGER.info("Successfully opened existing key file")

                if not existing_cert_contents == user_input[CONF_CERTIFICATE] and not existing_key_contents == user_input[CONF_KEY]:
                    # The cert and keys don't match, who knows what the hell happened here
                    self.async_abort(reason="existing_cert_and_key")
                else:
                    _LOGGER.info("Existing cert and key files match, we are good to continue")
            # We want to rename the cert and key files to the unique id of the meter
            _LOGGER.info("Moving cert and key files to match unique_id")

            shutil.move(cert_file_path, new_cert_path)
            shutil.move(key_file_path, new_key_path)

            self.cert_path = new_cert_path
            self.key_path = new_key_path

            _LOGGER.info("Meter unique id: %s", unique_id)

            if not unique_id:
                _LOGGER.info("Unable to determine unique id from meter response")
                self.async_abort(reason="no_unique_id")


            await self.async_set_unique_id(unique_id)
            self.sfdi = unique_id
            self._abort_if_unique_id_configured(updates={CONF_HOST: user_input[CONF_HOST]})

            # we don't need the actual certificate and keys added to the entity, so we remove them
            user_input.pop(CONF_CERTIFICATE)
            user_input.pop(CONF_KEY)

            return self.async_create_entry(title=user_input[CONF_HOST], data=user_input)


        if user_input is None:
            self.cert_path = os.path.join(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR, DEFAULT_GENERATED_CERT_FILENAME)
            self.key_path = os.path.join(self.hass.config.path(DOMAIN), DEFAULT_CERT_DIR, DEFAULT_GENERATED_KEY_FILENAME)
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
                        vol.Optional(CONF_CERT_PATH, default=self.cert_path): str,
                        vol.Optional(CONF_KEY_PATH, default=self.key_path): str,
                    },
                )
            )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
