from collections import UserDict
from collections.abc import Mapping
from copy import deepcopy
from typing import Self

__all__ = ["ExtendedDict"]


class ExtendedDict(UserDict):
    """一种支持嵌套，且定义了如何递归合并与按key删减的dict类型。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 如果参数是一个容器，检查其中元素，如果是dict，则该元素也被替换为ExtendedDict
        for key, value in list(self.items()):
            if isinstance(value, Mapping) and not isinstance(value, ExtendedDict):
                self[key] = ExtendedDict(value)

    def __add__(self, dest: dict | Self, rewrite=True):
        """使用迭代方式合并字典，避免递归深度限制。

        Args:
            dest (dict | Self): 目标dict
            rewrite (bool, optional): 是否允许覆盖目标dict中的同名键。 Defaults to True.

        Returns:
            ExtendedDict: 合并后的dict
        """
        if dest is None:
            dest = {}

        # 先深拷贝 dest 再合并，避免原地修改调用方传入的对象（`+` 不应有副作用）。
        # 同时把 dest 统一成 ExtendedDict：若只做 ExtendedDict(dest) 这种浅拷贝，
        # 嵌套节点仍与 dest 共享，合并时会连带改到 dest。
        # 注意：循环里的 target_dict 会被重绑定为嵌套节点，所以根节点要单独用 root 持有。
        root = deepcopy(dest)
        if not isinstance(root, ExtendedDict):
            root = ExtendedDict(root)

        stack = [(root, self)]
        while stack:
            target_dict, source_dict = stack.pop()
            for key, value in source_dict.items():
                # Ensure both sides are ExtendedDict for further merging
                if key in target_dict:
                    if isinstance(value, Mapping) and isinstance(
                        target_dict[key], Mapping
                    ):
                        # Convert to ExtendedDict if not already
                        if not isinstance(target_dict[key], ExtendedDict):
                            target_dict[key] = ExtendedDict(target_dict[key])
                        if not isinstance(value, ExtendedDict):
                            value = ExtendedDict(value)
                        stack.append((
                            target_dict[key],
                            value,  # pyright: ignore[reportArgumentType]
                        ))
                    elif rewrite:
                        target_dict[key] = value
                else:
                    target_dict[key] = value
        return root

    def __sub__(self, deleted_keys: list[str]) -> Self:
        """按key删除dict中元素，返回**新对象**，不修改原对象（与 `+` 的无副作用语义一致）。

        Args:
            deleted_keys (list[str]): dict中待删除的key列表
        Returns:
            Self: 返回删除后的dict。
        """
        pruned = deepcopy(self)
        stack = [pruned]
        while stack:
            node = stack.pop()
            for key in list(node.keys()):
                if key in deleted_keys:
                    del node[key]
                elif isinstance(node[key], ExtendedDict):
                    stack.append(node[key])
        return pruned
