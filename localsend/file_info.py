from __future__ import annotations


class FileInfoMetadata:
    __slots__ = ("modified", "accessed")

    def __init__(self, modified: str | None, accessed: str | None):
        self.modified = modified
        self.accessed = accessed

    def to_dict(self) -> dict:
        return {field: getattr(self, field) for field in self.__slots__}


class FileInfo:
    __slots__ = (
        "id", "file_name", "size", "file_type", "sha256", "preview", "metadata"
    )

    def __init__(
            self, id_: str, fileName: str, size: int, fileType: str, sha256: str | None = None,
            preview: str | None = None, metadata: FileInfoMetadata | None = None, **kwargs
    ):
        self.id = id_
        self.file_name = fileName
        self.size = size
        self.file_type = fileType
        self.sha256 = sha256
        self.preview = preview
        self.metadata = metadata

    def to_dict(self) -> dict:
        result = {field: getattr(self, field) for field in self.__slots__}
        if self.metadata is not None:
            result["metadata"] = self.metadata.to_dict()
        result["fileName"] = self.file_name
        result["fileType"] = self.file_type
        return result
