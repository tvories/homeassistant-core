"""Support for Xcel Itron Smart Meter energy sensor."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast, Final

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    UnitOfPower,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import ATTR_CURRENT_POWER_W, DOMAIN


@dataclass
class XcelItronSensorEntityDescription(SensorEntityDescription):
    """Describes Xcel Itron sensor entity."""

    value: Callable | None = None


SENSORS: Final[tuple[XcelItronSensorEntityDescription, ...]] = (
    XcelItronSensorEntityDescription(
        key="active_power_w",
        translation_key="active_power_w",
        native_unit_of_measurement=UnitOfPower.WATT,
        device_class=SensorDeviceClass.POWER,
        state_class=SensorStateClass.MEASUREMENT,
    ),
)

#TODO: add the rest of the sensors


def async_emeter_from_device(
    device: SmartDevice,
    description: XcelItronSensorEntityDescription,
) -> float | None:
    """Map a sensor key to the device attribute."""
    if attr := description.emeter_attr:
        if (val := getattr(device.emeter_realtime, attr)) is None:
            return None
        return round(cast(float, val), description.precision)
    return 0.0


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensors."""
    hass.data[DOMAIN].devices[config_entry.entry_id]
