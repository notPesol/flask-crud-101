from .enum import Message

class ResponseDTO:
    message = None
    data = None
    status = 200
    count = None
    
    def __init__(self, data = None, message: str = Message.SUCCESS.value) -> None:
        self.message = message
        self.data = data
        
    def to_dict(self) -> dict:
        return { "message": self.message, "data": self.data, "count": self.count }