import asyncio
import logging
import ssl
from typing import Any
import warnings
import xml.etree.ElementTree as ET

import aiohttp

CIPHERS = "ECDHE"
IEEE_PREFIX = "{urn:ieee:std:2030.5:ns}"
LOGGER = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)
warnings.filterwarnings("ignore", category=DeprecationWarning)


class CCM8Adapter(aiohttp.TCPConnector):
    """A TransportAdapter that re-enables ECDHE support in aiohttp."""

    def __init__(self, *args, **kwargs) -> None:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2, purpose=ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(certfile=self._cert_path, keyfile=self._key_path)
        ssl_ctx.verify_mode = ssl.CERT_NONE  # Disabling SSL verification
        ssl_ctx.check_hostname = False
        ssl_ctx.set_ciphers(CIPHERS)
        kwargs["ssl"] = ssl_ctx
        super().__init__(*args, **kwargs)


class Connection:
    def __init__(self, cert_path: str, key_path: str) -> None:
        if self.cert_path is None:
            raise ValueError("cert_path cannot be None")
        if self.key_path is None:
            raise ValueError("key_path cannot be None")

        self._cert_path = cert_path
        self._key_path = key_path

    async def create_session(self) -> aiohttp.ClientSession:
        """Create a session for the connection."""
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2, purpose=ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(certfile=self._cert_path, keyfile=self._key_path)
        ssl_ctx.verify_mode = ssl.CERT_NONE  # Disabling SSL verification
        ssl_ctx.check_hostname = False
        ssl_ctx.set_ciphers(CIPHERS)
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        session = aiohttp.ClientSession(connector=connector)

        return session


class XcelItronSmartMeter:
    """Creates an Xcel Itron Smart Meter object that represents the physical hardware."""

    _host: str
    _cert_path: str
    _key_path: str
    _base_url: str
    _sfdi: str
    _port: int = 8081
    _request_timeout: int = 4
    _connection: aiohttp.client.ClientSession | None = None

    def __init__(self, host, port, cert_path, key_path) -> None:
        self._host = host
        self._port = port
        self._cert_path = cert_path
        self._key_path = key_path
        self._connection = Connection(cert_path, key_path)
        self._base_url = f"https://{self._host}:{self._port}"

    async def connect(self) -> None:
        """Establish a connection to the meter, sets and returns sFDI."""

        url = f"{self._base_url}/sdev"

        try:
            LOGGER.debug(f"Connecting to meter at {self._host}")
            async with await self._connection.create_session() as session:
                async with session.get(url, timeout=self._request_timeout) as response:
                    LOGGER.debug(f"Response from meter: {await response.text()}")
                    self._sfdi = (
                        ET.fromstring(await response.text())
                        .find(f".//{IEEE_PREFIX}sFDI")
                        .text
                    )

        except aiohttp.ClientError as err:
            raise ConnectionError("Error connecting to meter.") from err
        except asyncio.TimeoutError as err:
            raise TimeoutError("Timeout connecting to meter.") from err

    async def request(self, path: str) -> Any:
        """Make a request to the API."""
        if self._connection is None:
            self._connection = Connection(self._cert_path, self._key_path)

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
            sFDI: The used sFDI
        """
        async with await self._connection.create_session() as session:
            async with session.get(url, timeout=self._request_timeout) as response:
                LOGGER.debug(f"Response from meter: {await response.text()}")
                sfdi = (
                    ET.fromstring(await response.text())
                    .find(f".//{IEEE_PREFIX}sFDI")
                    .text
                )
        return sfdi


# async def main():
#     meter = XcelItronSmartMeter(host="192.168.50.64", port=8081, cert_path="./config/xcel_itron/certs/_generated_xcel_itron_cert.pem", key_path="./config/xcel_itron/certs/_generated_xcel_itron_key.pem")

#     await meter.connect()

#     print(f'Meter SFDI: {meter.sfdi}')

# loop = asyncio.get_event_loop()
# loop.run_until_complete(main())

# async def _setup_session(cert_path: str, key_path: str):
#         ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2, purpose=ssl.Purpose.CLIENT_AUTH)
#         ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
#         ssl_ctx.verify_mode = ssl.CERT_NONE  # Disabling SSL verification

#         class CCM8Adapter(aiohttp.TCPConnector):
#             """A TransportAdapter that re-enables ECDHE support in aiohttp."""
#             def __init__(self, *args, **kwargs) -> None:
#                 context = ssl_ctx
#                 context.check_hostname = False
#                 context.verify_mode = ssl.CERT_NONE  # Disabling SSL verification
#                 context.set_ciphers(CIPHERS)
#                 kwargs['ssl'] = context
#                 super().__init__(*args, **kwargs)

#             async def _create_connection(self, req, traces, timeout, client_error=None):
#                 return await super()._create_connection(req, traces, timeout)
#         return aiohttp.ClientSession(connector=CCM8Adapter(), trust_env=False)

# @dataclass(frozen=True)
# class DiscoveredXcelItronSmartMeter:
#     """Model for a discovered Xcel Itron Smart Meter."""
#     host: str
#     sfdi: str

# async def discover_meter(
#     host: str,
#     cert_path: str,
#     key_path: str,
#     port: int = 8081,
# ) -> DiscoveredXcelItronSmartMeter:
#     """Discover Xcel Itron Smart Meter details from given hostname/ip.

#     Raises exception from aiohttp if there is no meter alive on given ip/host.
#     """
#     session = await _setup_session(cert_path, key_path)

#     try:
#         sfdi = await get_sfdi(host, port, session)
#         return DiscoveredXcelItronSmartMeter(host, sfdi)
#     finally:
#         await session.close()

# async def get_sfdi(host: str, port: int, session: ClientSession) -> str:
#     """Get the SFDI from the meter."""
#     async with session.get(f"https://{host}:{port}/sdev", timeout=4) as response:
#         root = ET.fromstring(await response.text())

#         return root.find(f'.//{IEEE_PREFIX}sFDI').text

# @dataclass

# from .const import (
#     CIPHERS,
#     IEEE_PREFIX,
# )

# async def discover_meter(
#     host: str,
#     port: int = 8081,
#     cert_path: str,
#     key_path: str,
#     websession: ClientSession | None = None
# ) -> DiscoveredXcelItronSmartMeter:
#     """Discover Xcel Itron Smart Meter details from given hostname/ip.

#     Raises exception from aiohttp if there is no meter alive on given ip/host.
#     """
#     websession_provided = websession is not None
#     if websession is None:
#         websession = ClientSession()
#     try:
