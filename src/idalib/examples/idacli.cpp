#include <memory>
#include <set>
#include <iostream>

#include <pro.h>
#include <prodir.h>
#include <ida.hpp>
#include <auto.hpp>
#include <expr.hpp>
#include <name.hpp>
#include <undo.hpp>
#include <name.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <dirtree.hpp>
#include <kernwin.hpp>
#include <segment.hpp>
#include <parsejson.hpp>
#include <idalib.hpp>

//-------------------------------------------------------------------------
/// \brief Print application usage
/// \param exec_filename The application name (argv[0])
static void display_usage(const char *exec_filename)
{
  // Bad usage, need the input file
  std::cout << "Usage: " << std::endl << " " << exec_filename
            << " -f <binary-file-name>"
            << " [-s <script-file-name> [-a <script-arguments>]]"
            << " [-p 0/1]"
            << " [-g <signature-path> [-o signature-results]]"
            << " [-l 0/1]"
            << " [-v 0/1]"
            << " -h"
            << std::endl << std::endl
            << " -f <binary-file-name> specifies the file to be analyzed" << std::endl
            << " -s <script-file-name> provide an idc or python script file to be run" << std::endl
            << " -p <integer 0/1/2> produce signatures, generate .sig and .pat for current database, 1 only .pat, 2 both .sig and .pat" << std::endl
            << " -a <script-arguments> string used for passing arguments to Python script, the string will be passed in sys.argv" << std::endl
            << " -g <signature-path> provide a signature file or folder to be checked, if the path is a folder all existing sig files will be checked sequentially" << std::endl
            << " -o <signature-results> json output file where the signature applying results to be stored" << std::endl
            << " -l <boolean 0/1> list the segments" << std::endl
            << " -v <level 0/1> verbosity level 0 quiet, 1 show messages" << std::endl
            << " -h display help" << std::endl;
}

//-------------------------------------------------------------------------
/// \brief Function used to dump a memory address
/// \param addr the memory address
/// \return Textual represention of the address
static std::string dump_address(ea_t addr)
{
  // IDA style. call ea2str which decorates the address with segment
  qstring astext;
  ea2str(&astext, addr);
  return astext.c_str();
}

//-------------------------------------------------------------------------
/// @brief Structure containing all command line parameters
struct command_line_arguments
{
  qstring binary_file_name;
  qstring script_file_name;
  qstring script_file_args;
  qstring signature_path;
  qstring signature_res_file;
  bool list_segments = false;
  char produce_sig = 0;
  char verbosity = 1;
};

//-------------------------------------------------------------------------
/// \brief Parse application command line
/// \param argc main() argc argument
/// \param argv main() argv argument
/// \param arguments structure used for reading and passing app arguments
/// \return true on success
static bool parse_arguments(int argc, char *argv[], command_line_arguments &arguments)
{
  int opt = 0;
  char *opt_data = nullptr;
  char *optargument = nullptr;

  for ( int arg = 0; arg < argc; )
  {
    if ( ++arg >= argc )
      break;

    opt_data = argv[arg];
    optargument = nullptr;
    opt = 0;

    if ( (strlen(opt_data)) > 1 && opt_data[0] == '-' )
      opt = opt_data[1];
    else
      return false;

    if ( ++arg >= argc )
      break;

    opt_data = argv[arg];
    optargument = opt_data;

    switch ( opt )
    {
      case 'f':
        if ( !optargument )
          return false;
        arguments.binary_file_name = optargument;
        break;

      case 's':
        if ( !optargument )
          return false;
        arguments.script_file_name = optargument;
        break;

      case 'a':
        if ( !optargument )
          return false;
        arguments.script_file_args = optargument;
        break;

      case 'g':
        if ( !optargument )
          return false;
        arguments.signature_path = optargument;
        break;

      case 'o':
        if ( !optargument )
          return false;
        arguments.signature_res_file = optargument;
        break;

      case 'l':
        if ( !optargument )
          return false;
        arguments.list_segments = strcmp(optargument, "0") != 0 && strcmp(optargument, " 0") != 0;
        break;

      case 'p':
        if ( !optargument )
          return false;
        arguments.produce_sig = (char)atoi(optargument);
        break;

      case 'v':
        if ( !optargument )
          return false;
        arguments.verbosity = (char)atoi(optargument);
        break;

      case 'h':
        return false;

      default:
        return false;
    }
  }

  return !arguments.binary_file_name.empty();
}

//-------------------------------------------------------------------------
/// \brief Launch a script provided by the user, IDC or Python
/// \param fname script file name
/// \param args script file arguments
/// \return true on success
static bool execute_script(const char *fname, const char *args)
{
  std::cout << "Running script " << fname << "..." << std::endl;

  qstring errbuf;
  if ( !qfileexist(fname) )
  {
    std::cout << "Script file " << fname << " does not exists" << std::endl;
    return false;
  }

  // Parse extension
  const char *ext = get_file_ext(fname);
  const extlang_object_t el = find_extlang_by_ext(ext);
  if ( el == nullptr // execute as IDC
    || el->compile_file == nullptr
    || el->is_idc() )
  {
    // is idc file
    if ( !compile_idc_file(fname, &errbuf) )
    {
      std::cout << "Failed to compile IDC script file " << fname << ", error: " << errbuf.c_str() << std::endl;
      return false;
    }

    if ( !call_idc_func(nullptr, "main", nullptr, 0, &errbuf) )
    {
      std::cout << "Failed to call IDC script main function for file " << fname << ", error: " << errbuf.c_str() << std::endl;
      return false;
    }
    std::cout << "Script " << fname << " successfully run" << std::endl;
    return true;
  }

  // Run python script

  // If we have parameters, prepend the script with code that sets the sys.argv
  // (we cannot use compile_file which overrides the sys.argv with the script file name)
  if ( args && qstrlen(args) )
  {
    qstrvec_t script_args;
    if ( args && qstrlen(args) && !parse_command_line(&script_args, nullptr, args, 0) )
    {
      std::cout << "Script arguments could not be parsed" << args << std::endl;
      return false;
    }

    qstring script_code = "import sys\n";
    script_code += qstring("sys.argv = ['") + fname + qstring("']\n");
    for ( const auto &arg : script_args )
      script_code += qstring("sys.argv.append('") + arg + qstring("')\n");

    FILE *py_script_file = qfopen(fname, "r");
    if ( !py_script_file )
    {
      std::cout << "Script " << fname << " could not be read" << std::endl;
      return false;
    }

    char buf[4096];
    while ( true )
    {
      char *rv = qfgets(buf, sizeof(buf), py_script_file);
      if ( rv == nullptr )
        break;

      size_t line_len = strlen(buf);
      if ( line_len > 0 )
      {
        if ( buf[line_len-1] == '\n' )
          buf[line_len-1] = 0;
      }

      script_code += qstring(buf) + "\n";
    }

    qfclose(py_script_file);

    if ( !el->eval_snippet(script_code.c_str(), &errbuf) )
    {
      std::cout << "Failed to run script file " << fname << " with arguments, error: " << errbuf.c_str() << std::endl;
      return false;
    }

    return true;
  }

  // Run python without paremeters
  if ( !el->compile_file(fname, nullptr, &errbuf) )
  {
    std::cout << "Failed to run script file " << fname << ", error: " << errbuf.c_str() << std::endl;
    return false;
  }

  return true;
}

//-------------------------------------------------------------------------
/// \brief List the segments for the loaded binary
static void produce_signatures(int arg)
{
  std::cout << std::endl << "Making signatures..." << std::endl;
  if ( make_signatures(arg == 1) )
  {
    std::cout << std::endl << "Signatures generation completed successfully." << std::endl;
  }
  else
  {
    std::cout << std::endl << "Signatures generation failed." << std::endl;
  }
}

//-------------------------------------------------------------------------
/// \brief List the segments for the loaded binary
static void list_binary_segments()
{
  int nb_items = get_segm_qty();
  std::cout << std::endl << "Listing segments, there are " << nb_items << " segments:" << std::endl<< std::endl;
  for ( int seg_no = 0; seg_no < nb_items; ++seg_no )
  {
    segment_t *segment = getnseg(seg_no);
    if ( segment != nullptr )
    {
      qstring name;
      get_visible_segm_name(&name, segment);
      qstring sclass;
      get_segm_class(&sclass, segment);

      std::cout << seg_no + 1 << "." << "\tname: " << name.c_str() << std::endl;
      std::cout << "\tstart: " << dump_address(segment->start_ea) << std::endl;
      std::cout << "\talign: " << (int)segment->align << std::endl;
      std::cout << "\ttype: " <<  get_segment_combination(segment->comb) << std::endl;
      std::cout << "\tclass: " << (qstrlen(sclass.c_str()) > 0 ? sclass.c_str() : "unknown") << std::endl;
      std::cout << "\taddress bits: " << segment->abits() << std::endl;
      std::cout << std::endl;
    }
  }
}

//-------------------------------------------------------------------------
/// \brief Applies signatures from sig file provided by the user
/// \param fname sigantures file name
/// \param matches reference to variable that will be filled with number of matches
/// \return true on success and fill the matches
static bool apply_signatures(const char *fname, int &matches, qstring &title)
{
  title.clear();
  // add the signature file in the signatures queue
  int index = plan_to_apply_idasgn(fname);
  if ( index <= 0 )
    return false;

  // wait for the signatures to be applied, call auto_wait() to trigger the process
  auto_wait();

  // search our file in the list of signatures
  bool ok = false;
  for ( index = 0; index < get_idasgn_qty(); index++ )
  {
    qstring signame;
    qstring optlibs;
    matches = get_idasgn_desc(&signame, &optlibs, index);
    if ( signame.ends_with(fname) )
    {
      // just set the flag, let all sigs to be applied anyway
      ok = get_idasgn_title(&title, fname) > 0;
    }
  }

  return ok;
}

//-------------------------------------------------------------------------
/// \brief Local structure used to pass user data to IDB hook
struct idb_callback_user_data
{
  std::set<ea_t> functions;
  std::set<ea_t> names;
};

//-------------------------------------------------------------------------
/// \brief Callback function used to collect siganture information
/// \param user_data user data passed by the caller when callback was registered
/// \param notification_code internal notification code describing the database event
/// \param va the variable arguments list specific to each notification code
/// \param 0, just passivelly listen for notifications, let the kernel flow continue
static ssize_t idaapi idb_signatures_callback(
        void *user_data,
        int notification_code,
        va_list va)
{
  switch ( notification_code )
  {
    case idb_event::thunk_func_created:
    case idb_event::func_updated:
    case idb_event::func_added:
      {
        // Get function pointer passed by caller, if is lib function then retain it
        func_t *pfn = va_arg(va, func_t *);
        if ( pfn->flags & FUNC_LIB )
        {
          idb_callback_user_data *found_items = reinterpret_cast<idb_callback_user_data*>(user_data);
          found_items->functions.insert(pfn->start_ea);
        }
      }
      break;
    case idb_event::renamed:
      {
        ea_t ea = va_arg(va, ea_t);
        idb_callback_user_data *found_items = reinterpret_cast<idb_callback_user_data*>(user_data);
        found_items->names.insert(ea);
      }
      break;

    default:
      break;
    }

  return 0;
};

//-------------------------------------------------------------------------
/// \brief Search all FLIRT files in the specified path and sequentially applies all
/// \param signature_path the path where to search for sig files, file or a folder
static void apply_signatures_from_path(
        const qstring &binary_file_name,
        const qstring &signature_path,
        const qstring &signature_res_file)
{
  qvector<qstring> signature_files_list;
  const char *ext = get_file_ext(signature_path.c_str());
  if ( ext != nullptr && strieq(ext, "sig") )
  {
    // This is a file, just take it as it is
    signature_files_list.push_back(signature_path);
  }
  else
  {
    // This is a folder, collect all sig files from it
    char matcher[QMAXPATH];
    qmakepath(matcher, sizeof(matcher), signature_path.c_str(), "*.sig", nullptr);

    qffblk64_t ff;
    for ( int code = qfindfirst(matcher, &ff, 0); code == 0; code = qfindnext(&ff) )
    {
      char found_sig[QMAXPATH];
      qmakepath(found_sig, sizeof(found_sig), signature_path.c_str(), ff.ff_name, nullptr);

      signature_files_list.push_back(found_sig);
    }
  }

  // Prepare json report
  jvalue_t jsonReport;
  jsonReport.set_obj(new jobj_t());
  auto &jsonObj = jsonReport.obj();

  jsonObj.put("binary_file", binary_file_name);
  jsonObj.put("min_ea", dump_address(inf_get_min_ea()).c_str());
  jsonObj.put("max_ea", dump_address(inf_get_max_ea()).c_str());

  jsonObj.put("segments", new jarr_t());
  jvalue_t *segments = jsonObj.get_value("segments");

  // Fill the report with segments
  int nb_items = get_segm_qty();
  for ( int seg_no = 0; seg_no < nb_items; ++seg_no )
  {
    segment_t *segment = getnseg(seg_no);
    if ( segment != nullptr )
    {
      qstring s_name;
      get_visible_segm_name(&s_name, segment);

      qstring s_class;
      get_segm_class(&s_class, segment);

      qstring s_perm;
      if ( segment->perm != 0 )
      {
        s_perm.append((segment->perm & SEGPERM_READ)  != 0 ? 'r' : '-');
        s_perm.append((segment->perm & SEGPERM_WRITE) != 0 ? 'w' : '-');
        s_perm.append((segment->perm & SEGPERM_EXEC)  != 0 ? 'x' : '-');
      }
      else
        s_perm = "n/a";

      // Fill the segment json structure
      jvalue_t seg_value;
      seg_value.set_obj(new jobj_t());
      seg_value.obj().put("name", s_name);
      seg_value.obj().put("start_ea", dump_address(segment->start_ea).c_str());
      seg_value.obj().put("end_ea", dump_address(segment->end_ea).c_str());
      seg_value.obj().put("align", (int)segment->align);
      seg_value.obj().put("type", get_segment_combination(segment->comb));
      seg_value.obj().put("class", s_class.size() ? s_class : "unknown");
      seg_value.obj().put("address_bits", (int)segment->abits());
      seg_value.obj().put("perm", s_perm);
      segments->arr().values.push_back(seg_value);
    }
  }

  // Collect the newlly added/edited function start addresses using IDB hook
  idb_callback_user_data found_items;
  hook_to_notification_point(HT_IDB, idb_signatures_callback, &found_items);

  jsonObj.put("analyzed_sig_files", new jarr_t());
  jvalue_t *files = jsonObj.get_value("analyzed_sig_files");

  // Apply all signatures, one by one and store found functions list in the json report
  for ( const qstring &signature_file_name : signature_files_list )
  {
    // Create an undo point just before applying the signatures
    bytevec_t rec;
    rec.pack_ds("LoadSigFile");
    rec.pack_ds("FLIRT signature file...");
    rec.pack_str(signature_file_name);
    if ( !create_undo_point(rec.begin(), rec.size()) )
      std::cout << "Failed to create undo point before applying sig file " << signature_file_name.c_str() << "..." << std::endl;

    // Clear functions collection after each file, we want them by file
    found_items.functions.clear();
    found_items.names.clear();

    int matches = 0;
    qstring sig_title;
    if ( apply_signatures(signature_file_name.c_str(), matches, sig_title) )
    {
      std::cout << "Signature file " << signature_file_name.c_str() << " was successfully applied, number of matches " << matches << std::endl;
    }
    else
    {
      std::cout << "Failed to apply signature file " << signature_file_name.c_str() << std::endl;
    }

    jvalue_t jsonFileInfo;
    jsonFileInfo.set_obj(new jobj_t());
    auto &jsonFileObj = jsonFileInfo.obj();
    jsonFileObj.put("file", signature_file_name);
    jsonFileObj.put("library_name", sig_title);
    jsonFileObj.put("matches", matches);

    // Dump all collected functions in the json report
    jsonFileObj.put("functions", new jarr_t());
    jvalue_t *functions = jsonFileObj.get_value("functions");

    for ( ea_t fiea : found_items.functions )
    {
      func_t *pfn = get_func(fiea);
      if ( pfn )
      {
        // Obtain function name
        qstring fn;
        get_func_name(&fn, pfn->start_ea);

        // Fill the function json structure
        jvalue_t function_value;
        function_value.set_obj(new jobj_t());
        function_value.obj().put("name", fn);
        function_value.obj().put("start_ea", dump_address(pfn->start_ea).c_str());
        function_value.obj().put("end_ea", dump_address(pfn->end_ea).c_str());
        functions->arr().values.push_back(function_value);
      }
    }

    // Dump all collected names in the json report
    jsonFileObj.put("names", new jarr_t());
    jvalue_t *names = jsonFileObj.get_value("names");

    for ( ea_t nea : found_items.names )
    {
      qstring name;
      if ( get_visible_name(&name, nea) )
      {
        // Fill the function json structure
        jvalue_t name_value;
        name_value.set_obj(new jobj_t());
        name_value.obj().put("name", name);
        name_value.obj().put("start_ea", dump_address(nea).c_str());
        names->arr().values.push_back(name_value);
      }
    }

    // list the total number of functions in the program after the sig was applied and compute few stats
    int nb_funcs = get_func_qty(); // total number of functions found in program
    int total_funcs_sizes = 0;     // cumulated size of all functions found in program
    int lib_funcs_no = 0;          // number of lib functions found in program
    int lib_funcs_sizes = 0;       // cumulated size of lib functions found in program
    for ( int func_no = 0; func_no < nb_funcs; ++func_no )
    {
      func_t *pfn = getn_func(func_no);
      if ( !pfn )
        continue;

      total_funcs_sizes += (pfn->end_ea - pfn->start_ea);
      if ( pfn->flags & FUNC_LIB )
      {
        ++lib_funcs_no;
        lib_funcs_sizes += (pfn->end_ea - pfn->start_ea);
      }
    }

    jsonFileObj.put("total_funcs_no_with_sig", nb_funcs);
    jsonFileObj.put("total_funcs_sizes_with_sig", total_funcs_sizes);
    jsonFileObj.put("lib_funcs_no_with_sig", lib_funcs_no);
    jsonFileObj.put("lib_funcs_sizes_with_sig", lib_funcs_sizes);

    // Store the file information in parent json container
    files->arr().values.push_back(jsonFileInfo);

    // Perform undo, go back to the state before applying signatures
    perform_undo();
  }

  // Stop IDB hook
  unhook_from_notification_point(HT_IDB, idb_signatures_callback, &found_items);

  // Dump json to results file
  qstring buf_json_dump;
  serialize_json(&buf_json_dump, jsonReport, SJF_PRETTY);

  // Generate the result file name based on the input if not specified by the user
  qstring out_file_name = signature_res_file.empty() ? binary_file_name + ".json" : signature_res_file;

  FILE *fp = qfopen(out_file_name.c_str(), "w");
  if ( fp != nullptr )
  {
    qfwrite(fp, buf_json_dump.begin(), buf_json_dump.length());
    qfclose(fp);
  }

  std::cout << "Signature applying report written to " << out_file_name.c_str() << std::endl;
}

//-------------------------------------------------------------------------
/// \brief Application main
/// \param argc number of arguments
/// \param argv the list of arguments
/// \return exit code, 0 on success
int main(int argc, char *argv[])
{
  command_line_arguments arguments;
  if ( !parse_arguments(argc, argv, arguments) )
  {
    display_usage(argv[0]);
    return -1;
  }

  //////////////////////////////////////////
  // Initialize library with the sample file, if verbose display to console library provided logs

  int res = init_library();
  if ( res != 0 )
  {
    std::cout << "Library initialization failed with result: " << res <<std::endl;
    return -1;
  }

  ///////////////////////////////////////////
  // Enable console messages if required
  enable_console_messages(arguments.verbosity > 0);

  res = open_database(arguments.binary_file_name.c_str(), true);
  if ( res != 0 )
  {
    std::cout << "Open file failed with result: " << res <<std::endl;
    return -1;
  }

  ///////////////////////////////////////////
  // Run provided script if any
  if ( !arguments.script_file_name.empty() )
  {
    execute_script(arguments.script_file_name.c_str(), arguments.script_file_args.c_str());
  }

  ////////////////////////////////////////////
  // List segments if requested
  if ( arguments.list_segments )
  {
    list_binary_segments();
  }

  ////////////////////////////////////////////
  // Invoke makesig if requested
  if ( arguments.produce_sig > 0 )
  {
    produce_signatures(arguments.produce_sig);
  }

  ////////////////////////////////////////////
  // Apply signatures file
  if ( !arguments.signature_path.empty() )
  {
    apply_signatures_from_path(arguments.binary_file_name, arguments.signature_path, arguments.signature_res_file);
  }

  ////////////////////////////////////////////
  // Close the database without saving, let it in a consistent state
  set_database_flag(DBFL_KILL);
  term_database();

  return 0;
}
