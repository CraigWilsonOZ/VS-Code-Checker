from abc import ABC, abstractmethod


class BaseCheck(ABC):

    @property
    @abstractmethod
    def check_id(self) -> str:
        ...

    @abstractmethod
    def run(self, target) -> list:
        ...
