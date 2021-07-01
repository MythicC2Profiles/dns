from MythicBaseRPCAux import *
import base64


class MythicRPCResponseAux(RPCResponseAux):
    def __init__(self, resp: RPCResponseAux):
        super().__init__(resp._raw_resp)
        if resp.status == MythicStatusAux.Success:
            self.data = resp.response
        else:
            self.data = None

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        self._data = data


class MythicCallbackRPCAux(MythicBaseRPCAux):
    # returns dictionary of `{"raw": raw_tasking, "encrypted": base64(uuid+encrypted_tasking)}`
    async def get_tasking(
        self, uuid: str, tasking_size: int = 1
    ) -> MythicRPCResponseAux:
        resp = await self.call(
            {
                "action": "get_tasking",
                "uuid": uuid,
                "tasking_size": tasking_size,
            }
        )
        return MythicRPCResponseAux(resp)

    async def add_route(
        self,
        source_uuid: str,
        destination_uuid: str,
        direction: int = 1,
        metadata: str = None,
    ) -> MythicRPCResponseAux:
        resp = await self.call(
            {
                "action": "add_route",
                "source": source_uuid,
                "destination": destination_uuid,
                "direction": direction,
                "metadata": metadata,
            }
        )
        return MythicRPCResponseAux(resp)

    async def remove_route(
        self,
        source_uuid: str,
        destination_uuid: str,
        direction: int = 1,
        metadata: str = None,
    ) -> MythicRPCResponseAux:
        resp = await self.call(
            {
                "action": "remove_route",
                "source": source_uuid,
                "destination": destination_uuid,
                "direction": direction,
                "metadata": metadata,
            }
        )
        return MythicRPCResponseAux(resp)

    async def get_callback_info(self, uuid: str) -> MythicRPCResponseAux:
        resp = await self.call({"action": "get_callback_info", "uuid": uuid})
        return MythicRPCResponseAux(resp)

    async def get_encryption_data(self, uuid: str, profile: str) -> MythicRPCResponseAux:
        resp = await self.call(
            {
                "action": "get_encryption_data",
                "uuid": uuid,
                "c2_profile": profile,
            }
        )
        return MythicRPCResponseAux(resp)

    async def update_callback_info(self, uuid: str, info: dict) -> MythicRPCResponseAux:
        resp = await self.call(
            {"action": "update_callback_info", "uuid": uuid, "data": info}
        )
        return MythicRPCResponseAux(resp)

    async def add_event_message(
        self, message: str, level: str = "info"
    ) -> MythicRPCResponseAux:
        resp = await self.call(
            {"action": "add_event_message", "level": level, "message": message}
        )
        return MythicRPCResponseAux(resp)

    async def encrypt_bytes(
        self, data: bytes, uuid: str, with_uuid: bool = False,
    ) -> MythicRPCResponseAux:
        resp = await self.call(
            {
                "action": "encrypt_bytes",
                "data": base64.b64encode(data).decode(),
                "uuid": uuid,
                "with_uuid": with_uuid,
            }
        )
        return MythicRPCResponseAux(resp)

    async def decrypt_bytes(
        self, data: str, uuid: str, with_uuid: bool = False,
    ) -> MythicRPCResponseAux:
        resp = await self.call(
            {
                "action": "decrypt_bytes",
                "uuid": uuid,
                "data": data,
                "with_uuid": with_uuid,
            }
        )
        return MythicRPCResponseAux(resp)
