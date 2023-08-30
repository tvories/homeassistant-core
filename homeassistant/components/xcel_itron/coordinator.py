import logging

import async_timeout
from datetime import datetime

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import DOMAIN, UPDATE_INTERVAL, CONF_KEY_PATH, CONF_CERT_PATH
from .xcel_itron import XcelItronSmartMeter

_LOGGER = logging.getLogger(__name__)


class XcelItronCoordinator(DataUpdateCoordinator):
    """Gather data for the smart meter."""

    api: XcelItronSmartMeter

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
    ) -> None:
        """Initialize update coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL,
        )
        self.entry = entry
        self.api = XcelItronSmartMeter(
            host=self.entry.data[CONF_HOST],
            port=self.entry.data[CONF_PORT],
            cert_path=self.entry.data[CONF_CERT_PATH],
            key_path=self.entry.data[CONF_KEY_PATH],
            session=async_get_clientsession(self.hass),
        )

        # self.entry = entry
        # super().__init__(
        #     hass,
        #     _LOGGER,
        #     name=DOMAIN,
        #     update_interval=UPDATE_INTERVAL,
        # )
        # self.api = api
        # self._last_run: datetime | None = None

    # def update_last_run(self, last_run: datetime) -> None:
    #     """Notify coordinator of a sensor last update time."""
    #     # We want to fetch the data from the Xcel Itron Smart Meter since HA was last shutdown.
    #     # We retrieve from the sensor last updated.
    #     # This method is called from each sensor upon their state being restored.
    #     if self._last_run is None or last_run > self._last_run:
    #         self._last_run = last_run

    async def _async_update_data(self):
        """Fetch data from the meter."""
        # if self.api is None:
        #     api = XcelItronSmartMeter(
        #         host=self.entry.data[CONF_HOST],
        #         port=self.entry.data[CONF_PORT],
        #         cert_path=self.entry.data[CONF_CERT_PATH],
        #         key_path=self.entry.data[CONF_KEY_PATH],
        #         session=async_get_clientsession(self.hass),
        #     )
        return self.api.get_all_readings()
