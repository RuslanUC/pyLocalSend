from __future__ import annotations

import json
import socket
import struct
from asyncio import get_event_loop, DatagramProtocol, DatagramTransport, run_coroutine_threadsafe
from os import urandom, PathLike
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TypedDict, Awaitable, Callable, AsyncGenerator, Literal
from uuid import uuid4

from asgi_tools import Request, Response
from httpx import AsyncClient
from muffin import Application
from uvicorn import Config, Server

from localsend import Device, DeviceType, FileInfo, FileInfoMetadata
from localsend.certs import create_cert
from localsend.exceptions import LSPrepareUploadException, InvalidPin
from localsend.jwt import JWT


class CallbacksDict(TypedDict):
    discover: Callable[[Device], Awaitable[None]]
    prepare_upload: Callable[[Device, dict[str, FileInfo], str | None], Awaitable[None]]
    upload_start: Callable[[Device, FileInfo], Awaitable[None]]
    upload_complete: Callable[[Device, FileInfo], Awaitable[None]]


class LSMulticastUdp(DatagramProtocol):
    def __init__(self, localsend: LocalSend):
        super().__init__()
        self._localsend = localsend
        self._transport = None

    def connection_made(self, transport: DatagramTransport) -> None:
        self._transport = transport
        self._localsend.send_info_udp()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            device = Device(ip=addr[0], **json.loads(data.decode("utf8")))
        except ValueError as e:
            print(f"Failed to decode message: {data}, {e}")
            return

        run_coroutine_threadsafe(self._localsend.register_device(device), self._localsend.loop)


class LSHttpServer:
    def __init__(self, localsend: LocalSend):
        self._localsend = localsend
        self._app = Application()
        self._app.route("/api/localsend/v2/register", methods=("POST",))(self._register)
        self._app.route("/api/localsend/v2/prepare-upload", methods=("POST",))(self._prepare_upload)
        self._app.route("/api/localsend/v2/send-request", methods=("POST",))(self._prepare_upload)
        self._app.route("/api/localsend/v2/upload", methods=("POST",))(self._upload)

    @property
    def app(self) -> Application:
        return self._app

    @staticmethod
    def _get_ip(request: Request) -> str | None:
        return request.scope["client"][0] if "client" in request.scope else None

    async def _register(self, request: Request) -> dict:
        data = await request.json()
        await self._localsend.register_device(Device(ip=self._get_ip(request), **data))

        return self._localsend.info()

    async def _prepare_upload(self, request: Request) -> dict | Response:
        data = await request.json()

        device = Device(ip=self._get_ip(request), **data["info"])
        await self._localsend.register_device(device)
        files = {}
        for file_id, file in data["files"].items():
            file["metadata"] = FileInfoMetadata(**file["metadata"]) if file.get("metadata") is not None else None
            files[file_id] = FileInfo(id_=file_id, **file)

        try:
            return await self._localsend.create_uploads(device, files, request.query.get("pin"))
        except LSPrepareUploadException as e:
            return Response(e.BODY, status_code=e.CODE)

    async def _upload(self, request: Request) -> Response:
        sess_id = request.query.get("sessionId")
        file_id = request.query.get("fileId")
        file_token = request.query.get("token")
        if not sess_id or not file_id or not file_token:
            return Response("", status_code=400)

        await self._localsend.handle_upload(sess_id, file_id, file_token, request.stream())
        return Response("", status_code=200)


class UdpContainer:
    __slots__ = ("socket", "transport", "protocol")

    def __init__(self, sock: socket.socket, transport: DatagramTransport, protocol: DatagramProtocol):
        self.socket = sock
        self.transport = transport
        self.protocol = protocol


class LocalSend:
    MULTICAST_IP = "224.0.0.167"
    MULTICAST_PORT = 53317
    HTTP_PORT = 53317

    def __init__(
            self, device_name: str, device_model: str = "pyLocalSend", device_type: DeviceType = "mobile",
            udp_ip: str = MULTICAST_IP, udp_port: int = MULTICAST_PORT, http_port: int = HTTP_PORT,
            enable_encryption: bool = True, global_pin: str | None = None,
            download_directory: PathLike | str = "received",
    ):
        self._device_name = device_name
        self._device_model = device_model
        self._device_type = device_type
        self._udp_ip = udp_ip
        self._udp_port = udp_port
        self._http_port = http_port
        self._fingerprint = urandom(32).hex().upper()
        self._jwt_key = urandom(32)
        self._devices: dict[str, Device] = {}
        self._enable_encryption = enable_encryption
        self._global_pin = global_pin
        self._download_directory = Path(download_directory)

        self._callbacks: CallbacksDict = {
            "discover": self._discover_stub,
            "prepare_upload": self._prepare_upload_stub,
            "upload_start": self._upload_start_stub,
            "upload_complete": self._upload_complete_stub,
        }

        self._multicast_server: UdpContainer | None = None
        self._multicast_client: UdpContainer | None = None
        self.loop = get_event_loop()

    def info(self) -> dict:
        if self._fingerprint not in self._devices:
            self._devices[self._fingerprint] = Device(
                ip=self._multicast_client.socket.getsockname(),
                alias=self._device_name,
                version="2.1",
                deviceModel=self._device_model,
                deviceType=self._device_type,
                fingerprint=self._fingerprint,
                port=self._http_port,
                protocol="https" if self._enable_encryption else "http",
                download=False,
            )
        return self._devices[self._fingerprint].info()

    def send_info_udp(self) -> None:
        if self._multicast_client is None:
            return

        self._multicast_client.transport.sendto(
            json.dumps(self.info()).encode("utf8"), (self._udp_ip, self._udp_port),
        )

    async def register_device(self, device: Device) -> None:
        if device.fingerprint == self._fingerprint or device.protocol not in {"http", "https"}:
            return

        if device.fingerprint not in self._devices:
            self.send_info_udp()
            self._devices[device.fingerprint] = device
            await self._callbacks["discover"](device)

        self._devices[device.fingerprint].update(device)
        async with AsyncClient(verify=False) as cl:
            resp = await cl.post(
                f"{device.protocol}://{device.ip}:{device.port}/api/localsend/v2/register",
                json=self.info(),
            )
            self._devices[device.fingerprint].update(resp.json())

    async def _create_udp(self, server: bool) -> UdpContainer:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if server:
            sock.bind((self._udp_ip, self._udp_port))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            struct.pack("4sl", socket.inet_aton(self._udp_ip), socket.INADDR_ANY)
        )

        transport, protocol = await self.loop.create_datagram_endpoint(
            lambda: LSMulticastUdp(self) if server else DatagramProtocol(),
            sock=sock,
        )

        return UdpContainer(sock, transport, protocol)

    async def run(self) -> None:
        self._multicast_server = await self._create_udp(True)
        self._multicast_client = await self._create_udp(False)

        ls_server = LSHttpServer(self)
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            config = Config(
                app=ls_server.app,
                host="0.0.0.0",
                port=self._http_port,
                ws="none",
            )

            if self._enable_encryption:
                self._fingerprint = create_cert(tmp)
                config.ssl_certfile = tmp / "cert.pem"
                config.ssl_keyfile = str(tmp / "key.pem")
                config.ssl_ca_certs = str(tmp / "ca_cert.pem")

            self.send_info_udp()
            await Server(config).serve()

    async def create_uploads(self, device: Device, files: dict[str, FileInfo], pin: str | None) -> dict:
        if self._global_pin is not None and self._global_pin != pin:
            raise InvalidPin()

        await self._callbacks["prepare_upload"](device, files, pin)
        sess_id = str(uuid4())

        return {
            "sessionId": JWT.encode({"device": device.fingerprint, "id": sess_id}, self._jwt_key),
            "files": {
                file_id: JWT.encode(file.to_dict() | {"s": sess_id[:8]}, self._jwt_key)
                for file_id, file in files.items()
            },
        }

    async def handle_upload(self, session_id: str, file_id: str, file_token: str, stream: AsyncGenerator) -> None:
        if (session := JWT.decode(session_id, self._jwt_key)) is None:
            return
        if session["device"] not in self._devices:
            return
        if (token := JWT.decode(file_token, self._jwt_key)) is None:
            return
        if token["s"] != session["id"][:8] or file_id != token["id"]:
            return

        token["metadata"] = FileInfoMetadata(**token["metadata"]) if token["metadata"] is not None else None
        token["id_"] = token["id"]
        file = FileInfo(**token)
        device = self._devices[session["device"]]

        await self._callbacks["upload_start"](device, file)

        recv_path = self._download_directory / session["id"] / file.file_name
        recv_path.parent.mkdir(parents=True, exist_ok=True)
        with open(recv_path, "wb") as f:
            async for chunk in stream:
                f.write(chunk)

        await self._callbacks["upload_complete"](device, file)

    def callback(
            self, callback_type: Literal["discover", "prepare_upload", "upload_start", "upload_complete"],
            func: Callable = None
    ):
        if func is not None:
            self._callbacks[callback_type] = func
            return

        def decorator(func_: Callable) -> Callable:
            self._callbacks[callback_type] = func_
            return func_

        return decorator

    async def _discover_stub(self, device: Device) -> None:
        ...

    async def _prepare_upload_stub(self, device: Device, files: dict[str, FileInfo], pin: str | None) -> None:
        ...

    async def _upload_start_stub(self, device: Device, file: FileInfo) -> None:
        ...

    async def _upload_complete_stub(self, device: Device, file: FileInfo) -> None:
        ...
