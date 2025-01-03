from typing import Iterator, Optional

import lief.objc # type: ignore

class Class:
    def __init__(self, *args, **kwargs) -> None: ...
    def to_decl(self, opt: lief.objc.DeclOpt = ...) -> str: ...
    @property
    def demangled_name(self) -> str: ...
    @property
    def is_meta(self) -> bool: ...
    @property
    def ivars(self) -> Iterator[Optional[lief.objc.IVar]]: ...
    @property
    def methods(self) -> Iterator[Optional[lief.objc.Method]]: ...
    @property
    def name(self) -> str: ...
    @property
    def properties(self) -> Iterator[Optional[lief.objc.Property]]: ...
    @property
    def protocols(self) -> Iterator[Optional[lief.objc.Protocol]]: ...
    @property
    def super_class(self) -> Optional[lief.objc.Class]: ...

class DeclOpt:
    show_annotations: bool
    def __init__(self) -> None: ...

class IVar:
    def __init__(self, *args, **kwargs) -> None: ...
    @property
    def mangled_type(self) -> str: ...
    @property
    def name(self) -> str: ...

class Metadata:
    def __init__(self, *args, **kwargs) -> None: ...
    def get_class(self, name: str) -> Optional[lief.objc.Class]: ...
    def get_protocol(self, name: str) -> Optional[lief.objc.Protocol]: ...
    def to_decl(self, opt: lief.objc.DeclOpt = ...) -> str: ...
    @property
    def classes(self) -> Iterator[Optional[lief.objc.Class]]: ...
    @property
    def protocols(self) -> Iterator[Optional[lief.objc.Protocol]]: ...

class Method:
    def __init__(self, *args, **kwargs) -> None: ...
    @property
    def address(self) -> int: ...
    @property
    def is_instance(self) -> bool: ...
    @property
    def mangled_type(self) -> str: ...
    @property
    def name(self) -> str: ...

class Property:
    def __init__(self, *args, **kwargs) -> None: ...
    @property
    def attribute(self) -> str: ...
    @property
    def name(self) -> str: ...

class Protocol:
    def __init__(self, *args, **kwargs) -> None: ...
    def to_decl(self, opt: lief.objc.DeclOpt = ...) -> str: ...
    @property
    def mangled_name(self) -> str: ...
    @property
    def optional_methods(self) -> Iterator[Optional[lief.objc.Method]]: ...
    @property
    def properties(self) -> Iterator[Optional[lief.objc.Property]]: ...
    @property
    def required_methods(self) -> Iterator[Optional[lief.objc.Method]]: ...
