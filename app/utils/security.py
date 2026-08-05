#!/usr/bin/env python3
"""
安全工具模块 - 密码哈希与验证
"""

import hashlib

import bcrypt


def get_password_hash(password: str) -> str:
    """
    使用 bcrypt 对密码进行哈希（rounds=12）
    
    Args:
        password: 明文密码
    
    Returns:
        bcrypt 哈希字符串
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    验证密码，兼容 bcrypt 和旧版 SHA-256
    
    Args:
        plain_password: 明文密码
        hashed_password: 哈希后的密码
    
    Returns:
        是否匹配
    """
    if not plain_password or not hashed_password:
        return False
    
    # bcrypt 哈希以 $2b$ 或 $2a$ 开头
    if hashed_password.startswith("$2b$") or hashed_password.startswith("$2a$"):
        try:
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                hashed_password.encode("utf-8")
            )
        except Exception:
            return False
    
    # 兼容旧版 SHA-256（登录后会自动升级为 bcrypt）
    return hashlib.sha256(plain_password.encode("utf-8")).hexdigest() == hashed_password
