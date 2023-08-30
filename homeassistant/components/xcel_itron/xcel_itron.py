from __future__ import annotations

import asyncio
import logging
import string
from collections.abc import Callable, Coroutine
from http import HTTPStatus
from typing import Any, TypeVar

import async_timeout
from aiohttp.client import ClientError, ClientResponseError, ClientSession
from aiohttp.hdrs import METH_DELETE, METH_GET, METH_PUT
import ssl
import warnings
import async_timeout
import xml.etree.ElementTree as ET

import aiohttp

CIPHERS = "ECDHE"
IEEE_PREFIX = "{urn:ieee:std:2030.5:ns}"
LOGGER = logging.getLogger(__name__)
T = TypeVar("T")


logging.basicConfig(level=logging.DEBUG)
warnings.filterwarnings("ignore", category=DeprecationWarning)

class CCM8Adapter(aiohttp.TCPConnector):
    """A TransportAdapter that re-enables ECDHE support in aiohttp."""

    def __init__(self, cert_path, key_path, *args, **kwargs) -> None:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2, purpose=ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        ssl_ctx.verify_mode = ssl.CERT_NONE  # Disabling SSL verification
        ssl_ctx.check_hostname = False
        ssl_ctx.set_ciphers(CIPHERS)
        kwargs["ssl"] = ssl_ctx
        super().__init__(*args, **kwargs)


class XcelItronSmartMeter:
    """Creates an Xcel Itron Smart Meter object that represents the physical hardware."""

    _host: str
    _cert_path: str
    _key_path: str
    _base_url: str
    _sfdi: str
    _port: int = 8081
    _request_timeout: int = 5
    _close_session: bool = False
    _connection: aiohttp.client.ClientSession | None = None
    _session: aiohttp.ClientSession | None = None

    def __init__(self, host, port, cert_path, key_path, session) -> None:
        """Initialize the Xcel Itron Smart Meter object.

        Args:
            host: The IP address or hostname of the meter.
            port: The port number for connecting to the meter.
            cert_path: The path to the certificate file used for authenticating to the meter.
            key_path: The path to the key file used for authenticating to the meter.
        """

        self._host = host
        self._port = port
        self._cert_path = cert_path
        self._key_path = key_path
        self._session = session
        self._base_url = f"https://{self._host}:{self._port}"

    async def request(self, path: str) -> Any:
        """Make a request to the API."""
        if self._session is None:
            self._session = aiohttp.ClientSession(connector=CCM8Adapter(self._cert_path, self._key_path))
            self._close_session = True
        else:
            # I haven't found a better way to leverage an existing connection, so we set a private _connection var to use the ssl context
            self._session._connector = CCM8Adapter(self._cert_path, self._key_path)

        url = f"{self._base_url}/{path}"

        LOGGER.debug(f"Requesting {url}")

        try:
            async with async_timeout.timeout(self._request_timeout):
                response = await self._session.request("GET", url)
                LOGGER.debug(f"Response from meter: {await response.text()}")
        except asyncio.TimeoutError as exception:
            raise aiohttp.ClientResponseError("Timeout connecting to meter.") from exception

        if response.status != HTTPStatus.OK:
            # Something went wrong
            raise aiohttp.ClientResponseError("API request error ({response.status})")
        return await response.text()

    @property
    def host(self) -> str:
        """Return the host of the meter.

        Returns:
            host: The used host
        """
        return self._host

    async def sfdi(self) -> str:
        """Return the sFDI of the meter.

        Returns:
            sFDI: The sFDI for the meter: https://github.com/Xcel-Energy/energy-launchpadsdk-client/blob/main/docs/Ieee2030dot5LibrariesUsageGuide.md#identifying-an-agent
        """
        response = await self.request("sdev")
        return ET.fromstring(response).find(f".//{IEEE_PREFIX}sFDI").text

    async def lfdi(self) -> str:
        """Return the lFDI of the meter.

        Returns:
            lFDI: The lFDI for the meter: https://github.com/Xcel-Energy/energy-launchpadsdk-client/blob/main/docs/Ieee2030dot5LibrariesUsageGuide.md#identifying-an-agent
        """
        response = await self.request("sdev/sdi")
        return ET.fromstring(response).find(f".//{IEEE_PREFIX}lFDI").text

    async def software_version(self) -> str:
        """Return the software version of the meter.

        Returns:
            software_version: The software version of the meter
        """
        response = await self.request("sdev/sdi")
        return ET.fromstring(response).find(f".//{IEEE_PREFIX}swVer").text

    async def mfid(self) -> str:
        """Return the mFID of the meter.

        Returns:
            mFDI: The mFID for the meter
        """
        response = await self.request("sdev/sdi")
        return ET.fromstring(response).find(f".//{IEEE_PREFIX}mfID").text

    async def get_device_info(self) -> dict[str, str]:
        """Return the device info of the meter.

        Returns:
            device_info: The device info for the meter as a dictionary
        """
        return {
            "sfdi": await self.sfdi(),
            "lfdi": await self.lfdi(),
            "mfid": await self.mfid(),
            "software_version": await self.software_version(),
        }

    async def get_active_power_w(self) -> int:
        """Return the current power usage in watts.

        Returns:
            power: The current power usage in watts
        """
        response = await self.request("upt/1/mr/1/r")
        return int(ET.fromstring(response).find(f".//{IEEE_PREFIX}value").text)

    async def get_total_power_import_kwh(self) -> float:
        """Return the power delivered in kWh increasing. This is the power delivered TO the meter.

        Returns:
            power: The power delivered in kWh (increasing)
        """
        response = await self.request("upt/1/mr/3/rs/1/r/1")
        return round(float(ET.fromstring(response).find(f".//{IEEE_PREFIX}value").text) * 0.001, 2)

    async def get_total_power_export_kwh(self) -> float:
        """Return the power received in kWh increasing. This is the power delivered FROM the meter.

        Returns:
            power: The power received in kWh (increasing)
        """
        response = await self.request("upt/1/mr/2/rs/1/r/1")
        return round(float(ET.fromstring(response).find(f".//{IEEE_PREFIX}value").text) * 0.001, 2)

    async def get_all_readings(self) -> dict[str, Any]:
        """Return all readings from the meter.

        Returns:
            readings: A dictionary of all readings from the meter
        """
        return {
            "active_power_w": await self.get_active_power_w(),
            "total_power_import_kwh": await self.get_total_power_import_kwh(),
            "total_power_export_kwh": await self.get_total_power_export_kwh(),
        }

    async def get_sensors(self) -> dict[str, Any]:
        """Return all sensors from the meter.

        Returns:
            sensors: A dictionary of all sensors from the meter
        """
        return {
            "sensors": {
                "active_power_w": await self.get_active_power_w(),
                "total_power_import_kwh": await self.get_total_power_import_kwh(),
                "total_power_export_kwh": await self.get_total_power_export_kwh(),
            }
        }

    async def close(self) -> None:
        """Close client session."""
        LOGGER.debug("Closing clientsession")
        if self._session and self._close_session:
            await self._session.close()

    async def __aenter__(self) -> XcelItronSmartMeter:
        """Async enter.

        Returns:
            The HomeWizardEnergy object.
        """
        LOGGER.debug("Entering Async and opening connection to meter")
        return self

    async def __aexit__(self, *_exc_info: Any) -> None:
        """Async exit.

        Args:
            _exc_info: Exec type.
        """
        LOGGER.debug("Closing connection to meter")
        await self.close()


# async def main():
#     async with XcelItronSmartMeter(host="192.168.50.64", port=8081, cert_path="./config/xcel_itron/certs/138049908710_xcel_itron_cert.pem", key_path="./config/xcel_itron/certs/138049908710_xcel_itron_key.pem", session=None) as meter:
#         print(f'Host: {meter.host}')
#         print(f'Device Info: {await meter.get_device_info()}')
#         print(f'Current Power: {await meter.get_active_power_w()} watts')
#         print(f'Power Delivered: {await meter.get_total_power_import_kwh()} kWh')
#         print(f'Power Received: {await meter.get_total_power_export_kwh()} kWh')
#         print(f'All Readings: {await meter.get_all_readings()}')

# loop = asyncio.get_event_loop()
# loop.run_until_complete(main())
