
def split_metadata(metadata: bytes) -> dict:
    """
    Split the metadata blob into a set of KVP's

    :param metadata: a metadata blob
    :returns: a set of KVP's
    """
    pass


class lumina_client_t:
    """
    Lumina server connection client.

    Use `get_server_connection()` to obtain an instance.
    """

    def pull_md(self, *args) -> "pkt_pull_md_result_t":
        """
        Pull metadata from the Lumina server.
        See lumina.hpp's lumina_client_t::pull_md() for authoritative documentation.

        This method has the following signatures:

            1. pull_md(funcs: ida_pro.eavec_t, pull_md_flags: int = 0) -> pkt_pull_md_result_t
            2. pull_md(pattern_ids: pattern_ids_t, pull_md_flags: int = 0) -> pkt_pull_md_result_t

        Note: The C++ `errbuf` parameter is not exposed in Python.

        :param funcs: vector of function addresses (if empty, will be filled with "interesting" functions)
        :param pattern_ids: vector of pattern IDs (will be consumed/destroyed)
        :param pull_md_flags: combination of PULL_MD_* flags:
            - PULL_MD_AUTO_APPLY (0x01): automatically apply metadata
            - PULL_MD_SEEN_FILE (0x02): do not increase frequency count
        :returns: pkt_pull_md_result_t with `results` (func_info_and_frequency_vec_t)
                  and `codes` (lumina_op_res_vec_t) for per-input status
        """
        pass
