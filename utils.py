# some basic utility functions that multiple classes use
import zlib
from DataModels import WebsocketPacket
import ast


def datamodel_to_bytes(datamodel, compress=False):
    byte_obj = str(datamodel.dict()).encode("utf-8")
    if compress:
        byte_obj = zlib.compress(byte_obj, level=-1)
    return byte_obj


def bytes_to_datamodel(datamodel, is_compressed=False):
    if is_compressed:
        datamodel = zlib.decompress(datamodel)
    datamodel = datamodel.decode('utf-8')
    data_dict = ast.literal_eval(datamodel)
    datamodel = WebsocketPacket.parse_obj(data_dict)
    return datamodel
