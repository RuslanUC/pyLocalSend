from __future__ import annotations
from typing import Literal

DeviceType = Literal["mobile", "desktop", "web", "headless", "server"]


class Device:
    __slots__ = (
        "ip", "alias", "version", "device_model", "device_type", "fingerprint", "port", "protocol", "download",
    )

    def __init__(
            self, ip: str | None, alias: str, version: str, deviceModel: str, deviceType: DeviceType | None,
            fingerprint: str, port: int, protocol: Literal["http", "https"], download: bool = False, **kwargs
    ):
        self.ip = ip
        self.alias = alias
        self.version = version
        self.device_model = deviceModel
        self.device_type = deviceType
        self.fingerprint = fingerprint
        self.port = port
        self.protocol = protocol
        self.download = download

    def update(self, device_info: Device | dict) -> None:
        if isinstance(device_info, dict):
            device_info = Device(ip=self.ip, **({"port": None, "protocol": None} | device_info))
        elif not isinstance(device_info, Device):
            return

        for field in self.__slots__:
            value = getattr(device_info, field)
            if field in {"ip", "port", "protocol"} and value is None:
                continue
            setattr(self, field, value)

    def info(self) -> dict:
        return {
            "alias": self.alias,
            "version": self.version,
            "deviceModel": self.device_model,
            "deviceType": self.device_type,
            "fingerprint": self.fingerprint,
            "port": self.port,
            "protocol": self.protocol,
            "download": self.download,
            "announcement": True,
            "announce": True,
        }
