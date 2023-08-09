"""Constants for the Xcel Itron Smart Meter integration."""

from datetime import timedelta

DOMAIN = "xcel_itron"

UPDATE_INTERVAL = timedelta(seconds=5)

# Component configuration items
CONF_CERT_PATH = "cert_path"
CONF_KEY_PATH = "key_path"
CONF_DEVICE_NAME = "device_name"
CONF_CERTIFICATE = "certificate"
CONF_USE_EXISTING_FILES = "use_existing_files"
CONF_KEY = "key"
CONF_CERT_DIR = "cert_dir"
CONF_SMART_METER_ON_NETWORK = "smart_meter_on_network"
CONF_GENERATE_CHOICE = "generate_choice"
CONF_SMART_METER_NOT_ON_NETWORK = "smart_meter_not_on_network"
CONF_SMART_METER_NETWORK_CHOICE = "smart_meter_network_choice"
CONF_LFDI = "lfdi"
CONF_NOT_ON_NETWORK_STAGE_CHOICE = "not_on_network_stage_choice"
CONF_WAITING_ON_XCEL_CHOICE = "waiting_on_xcel_choice"
CONF_NOW_ON_NETWORK_CHOICE = "now_on_network_choice"
CONF_SFDI = "sfdi"

# Default values
DEFAULT_DEVICE_NAME = "Xcel Itron Smart Meter"
DEFAULT_CERT_DIR = "certs"
DEFAULT_CERT_FILENAME = "xcel_itron_cert.pem"
DEFAULT_KEY_FILENAME = "xcel_itron_key.pem"
DEFAULT_PORT = "8081"
CONF_GENERATE_FILES = "generate_files"
DEFAULT_USE_EXISTING_FILES = "Use existing certificate and key?"
DEFAULT_GENERATE_FILES = True
DEFAULT_GENERATE_CHOICE = "Generate certificate and key files"
DEFAULT_GENERATED_CERT_FILENAME = "_generated_xcel_itron_cert.pem"
DEFAULT_GENERATED_KEY_FILENAME = "_generated_xcel_itron_key.pem"
DEFAULT_FILE_ENCODING = "utf-8"

# Attributes
ATTR_CURRENT_POWER_W = "current_power_w"
