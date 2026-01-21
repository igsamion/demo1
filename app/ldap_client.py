from dataclasses import dataclass
from typing import Any

from ldap3 import Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars


@dataclass
class LdapUser:
    dn: str
    attributes: dict[str, Any]


def _server(url: str, ca_cert: str | None, timeout: int) -> Server:
    tls = None
    if url.startswith("ldaps://"):
        tls = Tls(ca_certs_file=ca_cert, validate=2)
    return Server(url, use_ssl=url.startswith("ldaps://"), tls=tls, connect_timeout=timeout)


def fetch_user(
    *,
    url: str,
    base_dn: str,
    bind_dn: str,
    bind_password: str,
    user_filter: str,
    username: str,
    attrs: list[str],
    timeout: int,
    ca_cert: str | None,
) -> LdapUser | None:
    server = _server(url, ca_cert, timeout)
    try:
        with Connection(
            server,
            user=bind_dn,
            password=bind_password,
            auto_bind=True,
            receive_timeout=timeout,
        ) as conn:
            escaped_username = escape_filter_chars(username)
            search_filter = user_filter.format(username=escaped_username)
            conn.search(base_dn, search_filter, attributes=attrs)
            if not conn.entries:
                return None
            entry = conn.entries[0]
            return LdapUser(dn=entry.entry_dn, attributes=entry.entry_attributes_as_dict)
    except LDAPException:
        return None


def verify_password(
    *,
    url: str,
    user_dn_or_upn: str,
    password: str,
    timeout: int,
    ca_cert: str | None,
) -> bool:
    server = _server(url, ca_cert, timeout)
    try:
        with Connection(
            server,
            user=user_dn_or_upn,
            password=password,
            auto_bind=True,
            receive_timeout=timeout,
        ):
            return True
    except LDAPException:
        return False
