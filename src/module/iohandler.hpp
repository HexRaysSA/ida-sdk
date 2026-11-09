/*

  This file contains functions common to many processor modules
  to manage configuration files. The following functions can be called:

  bool apply_config_file(int _respect_info);
        Read and parse the config file

  void set_device_name(const char *dname, int respect_info);
        Set a new device name and reread the config file

  bool display_infotype_dialog(int *respect_info, const char *cfgname);
        Display a form and allow the user to clear some IORESP_ bits

*/
#pragma once

#include <pro.h>
#include <ida.hpp>
#include <netnode.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <segment.hpp>
#include <entry.hpp>
#include <name.hpp>
#include <xref.hpp>
#include <offset.hpp>
#include <idp.hpp>

struct iohandler_t
{
  qstring device;
  ioports_t ports;
  qstring deviceparams;
#define IORESP_PORT     1       // rename port names in memory
#define IORESP_AREA     2       // respect "area" directives
#define IORESP_INT      4       // respect interrupt information

#define IORESP_ALL     (IORESP_PORT|IORESP_AREA|IORESP_INT)
#define IORESP_NONE     0
  int respect_info = IORESP_NONE;
  netnode &helper;

  iohandler_t(netnode &_helper) : helper(_helper) {}
  virtual ~iohandler_t() {}

#define NONEPROC        "NONE"

  // Option: additional segment class to appear in the device description
  // Default: EEPROM
  virtual const char *aux_segm() const { return "EEPROM"; }

  // Option: respect configuration information for different file types?
  // Default: only binary-like files use IORESP_PORT, AREA, INT
  virtual bool check_ioresp() const { return inf_like_binary(); }

  // Option: a callback function to parse additional configuration file lines
  // Default: "interrupt" and "entry" keywords are recognized
  virtual const char *iocallback(const ioports_t &iop, const char *line)
  {
    return standard_callback(iop, line);
  }

  // can be used as object handler for read_ioports()
  struct ioports_loader_t : public ioports_fallback_t
  {
    iohandler_t *_this;
    ioports_loader_t(iohandler_t *_t) : _this(_t) {}

    virtual bool handle(qstring *errbuf, const ioports_t &_ports, const char *line) override
    {
      const char *errmsg = _this->iocallback(_ports, line);
      if ( errmsg == nullptr )
        return true;
      if ( errmsg == IOPORT_SKIP_DEVICE )
        errmsg = "SKIP device (logic error):";
      *errbuf = errmsg;
      return false;
    }
  };

  // Option: the function that will actually apply the IO port info into the IDB.
  // Default: will simply set name & comment.
  virtual void apply_io_port(ea_t ea, const char *name, const char *cmt)
  {
    set_name(ea, name, SN_NODUMMY);
    set_cmt(ea, cmt, true);
  }

  // Option: the function that will be called for unknown directives
  // (e.g., "area", "mirror", ...)
  // Default: standard_handle_unknown_directive
  virtual const char *handle_unknown_directive(const char *line)
  {
    return parse_area_line(&deviceparams, line);
  }

  // Option: function to handle entry points
  // Default: create an entry point
  //-V:entry_processing:669
  virtual bool entry_processing(ea_t &, const char * /*word*/, const char * /*cmt*/) { return false; }

  // Option: function to handle areas
  // Default: create a segment
  virtual bool area_processing(ea_t /*start*/, ea_t /*end*/, const char * /*name*/, const char * /*aclass*/) { return false; }

  virtual bool segment_created(ea_t /*start*/, ea_t /*end*/, const char * /*name*/, const char * /*aclass*/) { return false; }

  // Option: define function get_cfg_path()
  // Default: yes, it returns a file name using the current processor name
  virtual void get_cfg_filename(char *buf, size_t bufsize)
  {
    inf_get_procname(buf, bufsize);
    qstrlwr(buf);
    qstrncat(buf, ".cfg", bufsize);
  }

  GCC_DIAG_OFF(format-nonliteral);
  //------------------------------------------------------------------
  const char *parse_area_line(qstring *buf, const char *line)
  {
    if ( line[0] != ';' )
    {
      char word[MAXSTR];
      char aclass[MAXSTR];
      word[MAXSTR-1] = '\0';
      aclass[MAXSTR-1] = '\0';
      ea_t ea1, ea2;
      CASSERT(MAXSTR == 1024);
      if ( qsscanf(line, "area %1023s %1023s %a:%a", aclass, word, &ea1, &ea2) == 4 )
      {
        size_t _ram = 0;
        size_t _rom = 0;
        size_t _eprom = 0;
        size_t _eeprom = 0;
        qstring format("RAM=%" FMT_Z " ROM=%" FMT_Z " EPROM=%" FMT_Z " ");
        format.append(aux_segm());
        format.append("=%" FMT_Z);
        qsscanf(buf->c_str(), format.c_str(), &_ram, &_rom, &_eprom, &_eeprom);
        size_t size = size_t(ea2 - ea1);
        if ( stristr(word, "RAM") != nullptr )
          _ram += size;
        else if ( stristr(word, aux_segm()) != nullptr )
          _eeprom += size;
        else if ( stristr(word, "EPROM") != nullptr )
          _eprom  += size;
        else if ( stristr(word, "ROM") != nullptr )
          _rom    += size;
        if ( _ram || _rom || _eprom || _eeprom )
          buf->sprnt(format.c_str(), _ram, _rom, _eprom, _eeprom);
        else
          buf->qclear();
        if ( (respect_info & IORESP_AREA) != 0 && get_first_seg() != nullptr )
        {
          if ( !area_processing(ea1, ea2, word, aclass) )
          {
            if ( !segment_created(ea1, ea2, word, aclass) )
            {
              segment_t s;
              s.sel     = setup_selector(0);
              s.start_ea = ea1;
              s.end_ea   = ea2;
              s.align   = saRelByte;
              s.comb    = streq(aclass, "STACK") ? scStack : scPub;
              s.bitness = PH.get_default_segm_bitness(inf_is_64bit());
              if ( s.bitness == 0 && s.size() > 0xFFFF )
                s.bitness = 1;
              int sfl = ADDSEG_NOSREG;
              if ( !is_loaded(s.start_ea) )
                sfl |= ADDSEG_SPARSE;
              add_segm_ex(&s, word, aclass, sfl);
            }
          }
        }
        return nullptr;
      }
    }
    return "syntax error";
  }
  GCC_DIAG_ON(format-nonliteral);

  //------------------------------------------------------------------
  struct parse_area_line0_t : public choose_ioport_parser_t
  {
    iohandler_t &_this;
    parse_area_line0_t(iohandler_t &_t) : _this(_t) {}

    virtual bool parse(qstring *param, const char *line) override
    {
      _this.respect_info = 0;
      _this.parse_area_line(param, line);
      return true;
    }
  };

  //------------------------------------------------------------------
  const char *idaapi standard_callback(const ioports_t &, const char *line)
  {
    int len;
    ea_t ea1;
    char word[MAXSTR];
    word[MAXSTR-1] = '\0';
    CASSERT(MAXSTR == 1024);
    if ( qsscanf(line, "interrupt %1023s %" FMT_EA "i%n", word, &ea1, &len) == 2 )
    {
      if ( (respect_info & IORESP_INT) != 0 )
      {
        ea_t proc, wrong;
        segment_t *s = getseg(ea1);
        if ( s == nullptr || s->is_16bit() )
        {
          create_word(ea1, 2);
          proc = get_word(ea1);
          wrong = 0xFFFF;
        }
        else
        {
          create_dword(ea1, 4);
          proc = get_dword(ea1);
          wrong = 0xFFFFFFFF;
        }
        if ( proc != wrong && is_mapped(proc) )
        {
          op_plain_offset(ea1, 0, 0);
          add_entry(proc, proc, word, true);
        }
        else
        {
          set_name(ea1, word, SN_NODUMMY);
        }
        const char *ptr = &line[len];
        ptr = skip_spaces(ptr);
        if ( ptr[0] != '\0' )
          set_cmt(ea1, ptr, true);
      }
      return nullptr;
    }
    if ( qsscanf(line, "entry %1023s %" FMT_EA "i%n", word, &ea1, &len) == 2 )
    {
      if ( (respect_info & IORESP_INT) != 0 )
      {
        if ( is_mapped(ea1) )
        {
          const char *ptr = &line[len];
          ptr = skip_spaces(ptr);
          if ( !entry_processing(ea1, word, ptr) )
          {
            add_entry(ea1, ea1, word, true);
            if ( ptr[0] != '\0' )
              set_cmt(ea1, ptr, true);
          }
        }
      }
      return nullptr;
    }
    return handle_unknown_directive(line);
  }

  //------------------------------------------------------------------
  bool apply_config_file(int _respect_info)
  {
    if ( device == NONEPROC ) // processor not selected
      return true;

    char cfgfile[QMAXFILE];
    get_cfg_filename(cfgfile, sizeof(cfgfile));
    deviceparams.qclear();
    if ( !check_ioresp() )
      _respect_info = 0;
    respect_info = _respect_info;
    ports.clear();
    ioports_loader_t ldr(this);
    read_ioports(&ports, &device, cfgfile, &ldr);
    if ( respect_info & IORESP_PORT )
    {
      for ( size_t i=0; i < ports.size(); i++ )
      {
        const ioport_t &p = ports[i];
        ea_t ea = p.address;
        apply_io_port(ea, p.name.c_str(), p.cmt.c_str());
      }
    }
    return true;
  }

  //------------------------------------------------------------------
  void set_device_name(const char *dname, int respinfo)
  {
    if ( dname != nullptr )
    {
      device = dname;
      helper.supset(-1, device.c_str());
      apply_config_file(respinfo);
    }
  }

  //------------------------------------------------------------------
  void restore_device(int respinfo = IORESP_NONE)
  {
    if ( helper.supstr(&device, -1) > 0 )
      apply_config_file(respinfo);
  }

  //------------------------------------------------------------------
  // Some processor modules wrongly store device with index 0 (some store
  // duplicate value with both indices 0 and -1). Upgrade IDB to use -1
  void upgrade_device_index()
  {
    qstring old_device;
    if ( helper.supstr(&old_device, 0) >= 0 )
    {
      helper.supset(-1, old_device.c_str());
      helper.supdel(0);
    }
  }

  //------------------------------------------------------------------
  // Display a dialog form with the information types
  // Let the user to clear some checkboxes if he wants so
  // Returns: true - the user clicked OK
  bool display_infotype_dialog(
        int display_info,
        int *p_resp_info,
        const char *cfg_filename)
  {
    if ( display_info == 0 )
      return false;
    static const char *const form =
      "Loaded information type\n"
      "\n"
      "Please specify what information should be loaded from\n"
      "the configuration file %s to the database.\n"
      "\n"
      "If the input file does not contain parts corresponding to\n"
      "the segmentation defined in the config file, you might want\n"
      "to clear the 'memory layout' checkbox or even cancel this\n"
      "dialog box.\n";
    char buf[MAXSTR];
    char *ptr = buf + qsnprintf(buf, sizeof(buf), form, cfg_filename);
    char *const end = buf + sizeof(buf);
    int B = 1;
    ushort b = 0;
    ushort r = (ushort)*p_resp_info;
  #define ADD_FIELD(bit, desc) \
    if ( display_info & bit )  \
    {                          \
      if ( r & bit )           \
        b |= B;                \
      B <<= 1;                 \
      APPEND(ptr, end, desc);  \
    }
    ADD_FIELD(IORESP_PORT, "\n<#Rename port and I/O registers#I/O ports:C>")
    ADD_FIELD(IORESP_AREA, "\n<#Adjust the segments#Memory layout:C>")
    ADD_FIELD(IORESP_INT,  "\n<#Create interrupt vectors and/or entry points#Interrupts:C>")
  #undef ADD_FIELD
    qnotused(B);
    APPEND(ptr, end, ">\n\n");
    if ( !ask_form(buf, &b) )
      return false;
    B = 1;
    if ( display_info & IORESP_PORT )
    {
      setflag(r, IORESP_PORT, (B & b) != 0);
      B <<= 1;
    }
    if ( display_info & IORESP_AREA )
    {
      setflag(r, IORESP_AREA, (B & b) != 0);
      B <<= 1;
    }
    if ( display_info & IORESP_INT )
      setflag(r, IORESP_INT, (B & b) != 0);
    *p_resp_info = r;
    return true;
  }
};
