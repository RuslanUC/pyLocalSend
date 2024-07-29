from asyncio import get_event_loop

from localsend import Device, FileInfo
from localsend.localsend import LocalSend


async def _discover_cb(device: Device) -> None:
    print(f"New device: {device.alias}")


async def _prepare_upload_cb(device: Device, files: dict[str, FileInfo]) -> None:
    print(f"Requested upload of {len(files)} files from {device.alias}")


async def _upload_start_cb(device: Device, file: FileInfo) -> None:
    print(f"Upload of {file.file_name} from {device.alias} has started")


async def _upload_complete_cb(device: Device, file: FileInfo) -> None:
    print(f"Upload of {file.file_name} from {device.alias} completed")


async def main() -> None:
    ls = LocalSend("idk")
    ls.callback("discover", _discover_cb)
    ls.callback("prepare_upload", _prepare_upload_cb)
    ls.callback("upload_start", _upload_start_cb)
    ls.callback("upload_complete", _upload_complete_cb)

    await ls.run()


if __name__ == '__main__':
    get_event_loop().run_until_complete(main())
