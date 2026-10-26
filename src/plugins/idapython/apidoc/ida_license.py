def get_license_id() -> Optional[str]:
    """
    Get the ID of the active license, in the "XX-XXXX-XXXX-XX" form.

    :returns: the license ID, or None if there is no license
    """
    pass


def get_license_ids() -> List[str]:
    """
    Get the IDs of all licenses provided by the active license source.

    A license file may contain several licenses; for a license server,
    the licenses listed when the seat was acquired are reported.
    The list is not filtered by validity.

    :returns: the list of license IDs; empty if there is no license source
    """
    pass


def get_license_product() -> Optional[str]:
    """
    Get the product of the active license, e.g. "IDAPRO", "IDAHOME".

    :returns: the product code, or None if there is no license
    """
    pass


def get_license_edition() -> Optional[str]:
    """
    Get the edition of the active license, e.g. "ida-pro", "ida-home-arm".

    The value is informational, for display purposes; use has_valid_add_on()
    and has_valid_feature() to check what the license covers.

    :returns: the edition, or None if there is no license
    """
    pass


def is_floating_license() -> bool:
    """
    Check if the active license is a floating license, served by a license
    server, rather than a named license.

    :returns: False if there is no license
    """
    pass


def get_license_product_version() -> int:
    """
    Get the product version the active license is bound to,
    as major*100+minor (e.g. 904 for 9.4).

    :returns: the product version; 0 if there is no license
              or the license is not bound to a version
    """
    pass


def get_license_description() -> Optional[str]:
    """
    Get the description of the active license.

    :returns: the description, empty if the license has none;
              None if there is no license
    """
    pass


def get_license_issued_on() -> int:
    """
    Get the time the active license was issued.

    :returns: seconds since the Epoch (UTC); 0 if there is no license
    """
    pass


def get_license_start() -> int:
    """
    Get the start of the activation period of the active license.

    :returns: seconds since the Epoch (UTC); 0 if there is no license
    """
    pass


def get_license_end() -> int:
    """
    Get the end of the activation period of the active license.

    The license remains usable during a grace period after this time.
    A borrowed floating license may stop being usable earlier,
    at the end of the borrow period.

    :returns: seconds since the Epoch (UTC);
              0 if there is no license or the license never expires
    """
    pass


def get_add_on_end(name: str) -> int:
    """
    Get the end of the activation period of an add-on of the active license.

    The add-on remains usable during a grace period after this time.

    :param name: add-on product code, e.g. "HEXX64", "LUMINA" (case sensitive)
    :returns: seconds since the Epoch (UTC); 0 if there is no license,
              the add-on is not part of it, or the add-on never expires
    """
    pass


def get_valid_add_ons() -> List[str]:
    """
    Get the product codes of all currently usable add-ons of the active license.

    A floating license is usable only while this IDA instance holds it
    (a checked out seat or an unexpired borrow).

    :returns: the list of product codes, e.g. ["HEXX64", "LUMINA"];
              empty if there is no usable license
    """
    pass


def get_valid_features() -> List[str]:
    """
    Get the features of the active license.

    A floating license is usable only while this IDA instance holds it
    (a checked out seat or an unexpired borrow).

    :returns: the list of features; empty if there is no usable license
    """
    pass


def borrow_license(until: int) -> bool:
    pass


class License(object):
    """
    A License object lets a plugin check what the active license covers
    and change which license IDA uses.

    The object holds no state of its own: each query reports the current
    state of the license.
    An empty ``id`` means there is no active license.
    ``valid`` tells whether the license is usable.

    set_file(), set_server(), checkout(), checkin(), borrow() and
    return_borrowed() act on the license of the whole IDA instance, not on
    the object they are called on: they replace the license source or the
    active license for the entire application, including the kernel and all
    other plugins.
    """

    def add_ons(self) -> List[str]:
        pass

    def features(self) -> List[str]:
        pass

    def source_ids(self) -> List[str]:
        pass

    def start(self) -> int:
        pass

    def end(self) -> int:
        pass

    def issued_on(self) -> int:
        pass

    def add_on_end(self, name: str) -> int:
        pass

    def borrow(self, until: int) -> bool:
        pass
