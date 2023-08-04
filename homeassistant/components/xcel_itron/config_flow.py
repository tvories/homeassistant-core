"""Config flow for Xcel Itron Smart Meter integration."""
from __future__ import annotations

import logging
import selectors
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import selector

from .const import (
    CONF_CERT_DIR,
    CONF_LFDI,
    CONF_NOT_ON_NETWORK_STAGE_CHOICE,
    CONF_NOW_ON_NETWORK_CHOICE,
    CONF_SMART_METER_NETWORK_CHOICE,
    CONF_SMART_METER_NOT_ON_NETWORK,
    CONF_SMART_METER_ON_NETWORK,
    CONF_WAITING_ON_XCEL_CHOICE,
    DEFAULT_CERT_DIR,
    DOMAIN,
)
from .helpers import generate_cert_and_key

_LOGGER = logging.getLogger(__name__)

# TODO adjust the data schema to the data that you need
STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("host"): str,
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
                    vol.Required(CONF_LFDI, default=self.lfdi): selector.TextSelector(
                        selector.TextSelectorType.TEXT,
                    )
                }
            ),
        )

    async def async_step_not_on_network(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle meter not yet on network setup."""
        # Generate certificate and key files and pull LFDI
        generated_files = generate_cert_and_key()
        self.lfdi = generated_files["lfdi"]
        self.certificate = generated_files["certificate"]
        self.key = generated_files["private_key"]

        if user_input is None:
            return self.async_show_form(
                step_id="not_on_network",
                description_placeholders={"lfdi": self.lfdi},
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
                        vol.Required(CONF_CERT_DIR, default=DEFAULT_CERT_DIR): str,
                    }
                ),
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
