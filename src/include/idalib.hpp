/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __IDALIB_HPP
#define __IDALIB_HPP

#include <pro.h>

/*! \file idalib.hpp

  \brief Contains the IDA as library functions.
*/

/// \brief Initialize ida as library
/// \param argc Optional parameters count for advanced usage
/// \param argv Optional parameters list for advanced usage
/// \return 0 if successfully initialized, non zero in case of errors
idaman int ida_export init_library(int argc = 0, char *argv[] = nullptr);


/// \brief Open the database specified in file_path argument
/// If the database did not exist, a new database will be created and
/// the input file will be loaded
/// Note: All library functions must be called from the same thread that initialized the library
/// The library is single-threaded, and performing database operations from a different thread
/// than the initialization thread may lead to undefined behavior
/// \param file_path the file name to be loaded
/// \param run_auto if set to true, library will run also auto analysis
/// \return 0 if successfully opened, otherwise error code
idaman int ida_export open_database(const char *file_path, bool run_auto);


/// \brief Close the current database
/// \param save boolean value, save or discard changes
idaman void ida_export close_database(bool save);

/// \brief Generate .sig and .pat files for the current database
/// \param only_pat Generate .pat file only
/// \return true in case of success
idaman bool ida_export make_signatures(bool only_pat);

/// \brief Enable console messages
/// \param enable  flag to activate or deactivate console messages
/// by default, console messages are disabled
idaman void ida_export enable_console_messages(bool enable);

/// \brief Set screen ea, let the user specify the current screen ea
/// subsequent calls to get_screen_ea will return this value
/// Please note that with idalib there is no screen, this is provided
/// just for being able to use the get_screen_ea
/// \param ea screen ea
idaman void ida_export set_screen_ea(ea_t ea);

/// \brief Get ida library version
/// \param major major version
/// \param minor minor version
/// \param build build number
/// \return true in case of success
idaman bool ida_export get_library_version(int &major, int &minor, int &build);

#endif // __IDALIB_HPP
