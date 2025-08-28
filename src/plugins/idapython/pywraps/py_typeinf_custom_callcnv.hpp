#pragma once

//-------------------------------------------------------------------------
//<inline(py_typeinf_custom_callcnv)>
callcnv_t py_register_custom_callcnv(custom_callcnv_t *cnv_incref)
{
  return register_custom_callcnv(*cnv_incref);
}

bool py_unregister_custom_callcnv(custom_callcnv_t *cnv_decref)
{
  callcnv_t id = find_custom_callcnv(cnv_decref->name.c_str());
  if ( id == CM_CC_INVALID )
    return false;
  return unregister_custom_callcnv(id);
}
//</inline(py_typeinf_custom_callcnv)>

//<code(py_typeinf_custom_callcnv)>
typedef std::pair<custom_callcnv_t*,ref_t> custom_callcnv_tuple_t;
static qvector<custom_callcnv_tuple_t *> kernel_registered_py_custom_callcnvs;
static void clear_custom_callcnvs()
{
  PYW_GIL_GET;
  for ( ssize_t i=kernel_registered_py_custom_callcnvs.size()-1; i >= 0; --i )
  {
    auto *pair = kernel_registered_py_custom_callcnvs[i];
    callcnv_t id = find_custom_callcnv(pair->first->name.c_str());
    if ( id != CM_CC_INVALID )
    {
      if ( unregister_custom_callcnv(id) )
        pair->second = borref_t(nullptr);
    }
  }
  kernel_registered_py_custom_callcnvs.clear();
}

static custom_callcnv_tuple_t *find_kernel_registered_py_custom_callcnv(custom_callcnv_t *cc)
{
  for ( auto &p : kernel_registered_py_custom_callcnvs )
    if ( p->first == cc )
      return p;
  return nullptr;
}

//</code(py_typeinf_custom_callcnv)>
