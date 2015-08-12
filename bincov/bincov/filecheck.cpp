/// @file: filecheck.cpp
/// @brief: file attribute check
/// @author: Sang Kil Cha <sangkilc@gmail.com>

/*
Copyright (c) 2013, Sang Kil Cha

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#include "dr_api.h"
#include "dr_config.h"
#include "drmgr.h"
#include <string>
#include <cstring>
#include <climits>
#include <cstdlib>
#include <tr1/unordered_map>
#include <map>
#include <set>
#include "common.hpp"
#ifdef UNIX
#include <unistd.h>
#include <sys/file.h>
#include <fcntl.h>
#include <syscall.h>
#endif

#ifdef WINDOWS
# define SYS_MAX_ARGS 9
#else
# define SYS_MAX_ARGS 3
#endif

#ifndef MAXSIZE
#define MAXSIZE  16384
#endif

typedef struct {
    reg_t param[SYS_MAX_ARGS];
} per_thread_t;

typedef enum {
    console_mode,
    pipe_mode
} run_mode_t;

typedef enum {
    normal_term = 0,
    timeout_term,
    abort_term,
    crash_term
} term_mode_t;

typedef std::tr1::unordered_map< std::string, std::set< int > >
    fname_fd_set;

//

static int g_pipe = 0;
static run_mode_t g_mode = console_mode;
static int g_timeout = 0;
static int tcls_idx;
static bool stdin_is_duped_by_file = false;
// file name to argument index
static std::multimap< std::string, int > file_arg_tbl;
// file desc to input file name
static std::tr1::unordered_map< int, std::string > fd_file_tbl;
// stdin desc set
static std::set< int > stdin_set;
// read set (filename to argument index)
static fname_fd_set read_tbl;
// write set (filename to argument index)
static fname_fd_set write_tbl;
// stdin is used or not
static bool stdin_is_used = false;

bool is_valid_descriptor( int fd )
{
    return fcntl( fd, F_GETFD ) != -1;
}

void emit_result( term_mode_t term, bool to_console )
{
    int pipe = g_pipe;
    char buf[MAXSIZE];
    bool file_is_used;
    unsigned int pos = 0;
    unsigned int cnt = 0;

    if ( to_console ) {
        pipe = fileno( stdout );
    } else {
        DR_ASSERT( is_valid_descriptor( pipe ) && "pipe not opened" );
    }

    flock( pipe, LOCK_SH );

    file_is_used = read_tbl.size() > 0 || write_tbl.size() > 0;

    // output in the following format:
    // @START@;
    // term mode;
    // file_is_used; stdin_is_used;
    // list of read args;
    // list of write args;
    // list of not-opened files
    // @END@;
    // each list is tokenized by @ sign, and begines with a size constant

    snprintf( buf, MAXSIZE - 1, "@START@\n%d\n%d\n%d\n",
              (int) term, (int) file_is_used, (int) stdin_is_used & !stdin_is_duped_by_file );
    write( pipe, buf, strlen(buf) );

    cnt = 0;
    for ( fname_fd_set::const_iterator it = read_tbl.begin();
          it != read_tbl.end(); ++it )
    {
        for ( std::set<int>::const_iterator it2 = it->second.begin();
              it2 != it->second.end();
              ++it2 )
        {
            cnt += 1;
        }
    }
    snprintf( buf, MAXSIZE - 1, "%d", cnt );
    write( pipe, buf, strlen(buf) );

    // user input files that are used to read
    for ( fname_fd_set::const_iterator it = read_tbl.begin();
          it != read_tbl.end(); ++it )
    {
        for ( std::set<int>::const_iterator it2 = it->second.begin();
              it2 != it->second.end();
              ++it2 )
        {
            pos += snprintf( buf + pos, MAXSIZE - 1 - pos,
                             SEP_CHAR"%s"SEP_CHAR"%d", it->first.c_str(), *it2 );
        }

        DR_ASSERT( pos < MAXSIZE - 2 );
    }

    cnt = 0;
    for ( fname_fd_set::const_iterator it = write_tbl.begin();
          it != write_tbl.end(); ++it )
    {
        for ( std::set<int>::const_iterator it2 = it->second.begin();
              it2 != it->second.end();
              ++it2 )
        {
            cnt += 1;
        }
    }
    snprintf( buf + pos, MAXSIZE - 1 - pos, "\n%d", cnt );
    write( pipe, buf, strlen(buf) );

    // user input files that are used to write
    pos = 0;
    for ( fname_fd_set::const_iterator it = write_tbl.begin();
          it != write_tbl.end(); ++it )
    {
        for ( std::set<int>::const_iterator it2 = it->second.begin();
              it2 != it->second.end();
              ++it2 )
        {
            pos += snprintf( buf + pos, MAXSIZE - 1 - pos,
                             SEP_CHAR"%s"SEP_CHAR"%d", it->first.c_str(), *it2 );
        }

        DR_ASSERT( pos < MAXSIZE - 2 );
    }

    snprintf( buf + pos, MAXSIZE - 1 - pos, "\n%d", fd_file_tbl.size() );
    write( pipe, buf, strlen(buf) );

    // pattern-matched files that are not opened
    pos = 0;
    for ( std::tr1::unordered_map< int, std::string >::const_iterator it =
            fd_file_tbl.begin();
          it != fd_file_tbl.end();
          ++it )
    {
        pos += snprintf( buf + pos, MAXSIZE - 1 - pos,
                         SEP_CHAR"%s", it->second.c_str() );
    }

    snprintf( buf + pos, MAXSIZE - 1 - pos, "\n@END@\n" );
    write( pipe, buf, strlen(buf) );

    flock( pipe, LOCK_UN );
    close( pipe );
}

static void
event_thread_context_init( void *drcontext, bool new_depth )
{
    per_thread_t *data;

    if ( new_depth ) {
        data =
            (per_thread_t *) dr_thread_alloc( drcontext, sizeof(per_thread_t) );
        drmgr_set_cls_field( drcontext, tcls_idx, data );
    } else
        data = (per_thread_t *) drmgr_get_cls_field( drcontext, tcls_idx );

    memset( data, 0, sizeof(*data) );
}

static void
event_thread_context_exit( void *drcontext, bool thread_exit )
{
    if ( thread_exit ) {
        per_thread_t *data =
            (per_thread_t *) drmgr_get_cls_field( drcontext, tcls_idx );
        dr_thread_free( drcontext, data, sizeof(per_thread_t) );
    }
}

void at_term( term_mode_t term )
{
#ifdef COUNT_INSTRUMENTATION
    fprintf( stderr, "instrumented: %ld\n", instrument_count );
#endif

    emit_result( term, g_mode == console_mode );

    drmgr_unregister_cls_field( event_thread_context_init,
                                event_thread_context_exit,
                                tcls_idx );
}

void dr_exit( void )
{
    at_term( normal_term );
}

#ifdef UNIX
static bool
event_filter_syscall( void *drcontext, int sysnum )
{
    if ( sysnum == SYS_open
      || sysnum == SYS_close
      || sysnum == SYS_read
      || sysnum == SYS_write
      || sysnum == SYS_dup2 )
    {
        return true;
    } else {
        return false;
    }
}

static void
delete_fd_tbl( int fd )
{
    std::tr1::unordered_map< int, std::string >::const_iterator it;

    it = fd_file_tbl.find( fd );
    if ( it != fd_file_tbl.end() ) {
        fd_file_tbl.erase( it );
    }
}

// if file open is failed, then we still insert path using a wrong fd (< 0)
// Since, we are using multimap, we can store all the failed open attempts that
// match patterns
static void
insert_fd_tbl( int fd, const char* path )
{
    delete_fd_tbl( fd );
    fd_file_tbl.insert( std::make_pair( fd, path ) );
}

static void
delete_stdin_fd( int fd )
{
    std::set< int >::iterator it;

    it = stdin_set.find( fd );
    if ( it != stdin_set.end() )
        stdin_set.erase( it );
}

static void
input_file_check( int fd,
                  std::tr1::unordered_map< std::string, std::set< int > >& filetbl )
{
    std::tr1::unordered_map< int, std::string >::const_iterator it;

    it = fd_file_tbl.find( fd );
    if ( it != fd_file_tbl.end() ) {
        std::pair< std::multimap< std::string, int >::const_iterator,
                   std::multimap< std::string, int >::const_iterator > ret;
        ret = file_arg_tbl.equal_range( it->second );
        for ( std::multimap< std::string, int >::const_iterator it2 = ret.first;
              it2 != ret.second; ++it2 )
        {
            std::tr1::unordered_map< std::string, std::set< int > >::iterator it3 =
                filetbl.find( it->second );
            if ( it3 != filetbl.end() ) {
                it3->second.insert( it2->second );
            } else {
                std::set<int> tmpset;
                tmpset.insert( it2->second );
                filetbl.insert( std::make_pair( it->second, tmpset ) );
            }
        }
    }
}

static void
input_read_check( int fd )
{
    input_file_check( fd, read_tbl );
}

static void
input_write_check( int fd )
{
    input_file_check( fd, write_tbl );
}

static void
duplicate_fd( int from, int to )
{
    std::tr1::unordered_map< int, std::string >::iterator it = fd_file_tbl.find( from );
    std::set< int >::const_iterator stdin_it;
    if ( it != fd_file_tbl.end() ) {
        stdin_it = stdin_set.find( to );
        if ( stdin_it != stdin_set.end() || to == (int) STDIN ) {
            input_read_check( from );
            fd_file_tbl.erase( it );
            stdin_is_duped_by_file = true;
        } else {
            insert_fd_tbl( to, it->second.c_str() );
        }
        // fd_file_tbl.erase( it );
    }
}

static void
stdin_check( int fd, const char* path )
{
    if ( strcmp( path, "/dev/stdin" ) == 0
      || strcmp( path, "/dev/tty" ) == 0 )
    {
        stdin_set.insert( fd );
    }
}

static void
stdin_open_check( int fd )
{
    std::set< int >::const_iterator it = stdin_set.find( fd );
    if ( it != stdin_set.end() || fd == (int) STDIN ) {
        stdin_is_used = true;
    }
}

static bool
event_pre_syscall( void *drcontext, int sysnum )
{
    int i;
    per_thread_t *data =
        (per_thread_t *) drmgr_get_cls_field( drcontext, tcls_idx );

    switch ( sysnum ) {
    case SYS_open:
        for (i = 0; i < SYS_MAX_ARGS; i++)
            data->param[i] = dr_syscall_get_param( drcontext, i );
        break;
    case SYS_close:
        data->param[0] = dr_syscall_get_param( drcontext, 0 );
        delete_fd_tbl( (int) data->param[0] );
        delete_stdin_fd( (int) data->param[0] );
        break;
    case SYS_read:
        data->param[0] = dr_syscall_get_param( drcontext, 0 );
        input_read_check( (int) data->param[0] );
        stdin_open_check( (int) data->param[0] );
        break;
    case SYS_write:
        data->param[0] = dr_syscall_get_param( drcontext, 0 );
        input_write_check( (int) data->param[0] );
        break;
    case SYS_dup2:
        data->param[0] = dr_syscall_get_param( drcontext, 0 );
        data->param[1] = dr_syscall_get_param( drcontext, 1 );
        break;
    default:
        break;
    }

    return true;
}

static
std::string get_basename( const char *path )
{
    char* buf = strdup( path );
    DR_ASSERT( buf );

    char *base = strrchr( buf, '/' );
    char *ret = NULL;

    if ( base )
        if ( *(base+1) ) ret = base+1;
        else {
            buf[ (base-buf) ] = 0;
            base = strrchr( buf, '/' );
            if ( base ) ret = base+1;
            else ret = buf;
        }
    else
        ret = buf;

    std::string result(ret);
    free( buf );
    return result;
}

static bool
is_absolute( const char* path )
{
    return path[0] == '/';
}

static void
thorough_match( int fd, const char* path )
{
    std::string basepath = get_basename( path );
    if ( basepath.size() == 0 ) return;
    // fprintf(stderr, "thorough(%s;%s)\n", path, basepath.c_str() );

    for ( std::multimap< std::string, int >::const_iterator it =
            file_arg_tbl.begin();
          it != file_arg_tbl.end();
          ++it )
    {
        // fprintf( stderr,
        //          "%s not matched with %s\n", it->first.c_str(), basepath.c_str() );
        if ( it->first == basepath ) {
            insert_fd_tbl( fd, it->first.c_str() );
            break;
        }
        if ( strstr( basepath.c_str(), it->first.c_str() ) ) {
            // we will insert negative fd (failure case) to the table, and this
            // will help us to figure out whether there was a file open failure
            // also, dynamorio will not try to hook open system call for library
            // loading, which will give us more precision
            insert_fd_tbl( fd, basepath.c_str() );
        }
    }
}

static void
event_post_syscall( void *drcontext, int sysnum )
{
    per_thread_t *data =
        (per_thread_t *) drmgr_get_cls_field( drcontext, tcls_idx );

    reg_t result;
    std::multimap< std::string, int >::const_iterator it;

    switch ( sysnum ) {
    case SYS_open:
        result = dr_syscall_get_result( drcontext ); // fd
        it = file_arg_tbl.find( (const char*) data->param[0] );
        // fprintf( stderr, "check(%s)\n", (const char*) data->param[0] );
        if ( it != file_arg_tbl.end() ) {
            // fprintf( stderr, "open(%s)\n", (const void*) data->param[0] );
            insert_fd_tbl( (int) result, (const char*) data->param[0] );
        } else {
            // if not found, we have to iterate through all the candidates and
            // perform pattern matching (in case file name is modified)
            thorough_match( (int) result, (const char*) data->param[0] );
        }
        stdin_check( result, (const char*) data->param[0] );
        break;
    case SYS_dup2:
        result = dr_syscall_get_result( drcontext ); // fd
        if ( (int)result != -1 ) {
            // only when the syscall succeeded
            duplicate_fd( (int) data->param[0], (int) data->param[1] );
        }
        break;
    default:
        return;
    }
}

#include <signal.h>
#include <sys/time.h>

static
dr_signal_action_t event_signal( void *drcontext, dr_siginfo_t *info )
{
    // fprintf( stderr, "SIGNAL: %d\n", info->sig ); fflush( stderr );
    if ( info->sig == SIGTERM ) {
        at_term( timeout_term );
        return DR_SIGNAL_DELIVER;
    } else if ( info->sig == SIGSEGV
             || info->sig == SIGFPE
             || info->sig == SIGILL ) {
        at_term( crash_term );
        exit( 1 );
    } else if ( info->sig == SIGABRT ) {
        at_term( abort_term );
        exit( 1 );
    }

    return DR_SIGNAL_DELIVER;
}

static void
timeout( void *drcontext, dr_mcontext_t *mcontext )
{
    at_term( timeout_term );
    exit( 1 );
}
#endif

bool
is_main( const char* appname, const char* client_opt )
{
    if ( !client_opt ) return true;
    return (strcmp( client_opt, appname ) == 0);
}

void
error_exit( const char* msg )
{
    fprintf( stderr, msg );
    exit( 1 );
}

char*
parse_client_opt( char* client_opt )
{
    // programname@file_descriptor
    char* mode_token;
    char* prog_token;
    char* fd_token = NULL;
    char* timeout_token;
    char* file_token;
    char* idx_token;
    char buf[PATH_MAX];
    std::string str;
    int idx = 0;

    mode_token = strtok( client_opt, SEP_CHAR );
    prog_token = strtok( NULL, SEP_CHAR );
    if ( !prog_token ) {
        error_exit( "invalid client option\n" );
    }

    if ( strcmp( mode_token, "console" ) == 0 ) {
        g_mode = console_mode;
    } else {
        g_mode = pipe_mode;
        fd_token = strtok( NULL, SEP_CHAR );
        g_pipe = (int) strtoul( fd_token, NULL, 10 );
    }

    timeout_token = strtok( NULL, SEP_CHAR );
    if ( !timeout_token ) {
        error_exit( "invalid client option\n" );
    }
    // milli seconds
    g_timeout = ((int) strtoul( timeout_token, NULL, 10 )) * 1000;

    do {
        file_token = strtok( NULL, SEP_CHAR );
        if ( !file_token ) {
            return prog_token;
        }
        idx_token = strtok( NULL, SEP_CHAR );
        idx = (int) strtoul( idx_token, NULL, 10 );
        // fprintf(stderr, "insert(%s)\n", file_token);
        if ( is_absolute( file_token ) )
            file_arg_tbl.insert( std::make_pair( file_token, idx ) );
        else {
            str = get_basename( file_token );
            if ( str.size() > 0 )
                file_arg_tbl.insert(
                        std::make_pair( str, idx ) );
        }
    } while( true );

    return prog_token;
}

DR_EXPORT
void dr_init( client_id_t id )
{
    const char* client_opt = dr_get_options( id );
    char* client_opt_copy = strdup( client_opt );
    char* progname = parse_client_opt( client_opt_copy );

    DR_ASSERT( client_opt_copy && "strdup failed" );

    if ( !is_main( dr_get_application_name(), progname ) ) {
        free( client_opt_copy );
        return;
    }

#ifdef UNIX
    if ( g_timeout )
        dr_set_itimer( ITIMER_REAL, g_timeout, timeout );
#endif

    drmgr_init();
    dr_register_filter_syscall_event( event_filter_syscall );
    drmgr_register_pre_syscall_event( event_pre_syscall );
    drmgr_register_post_syscall_event( event_post_syscall );
    dr_register_exit_event( dr_exit );
    tcls_idx = drmgr_register_cls_field( event_thread_context_init,
                                         event_thread_context_exit );
    DR_ASSERT(tcls_idx != -1);
#ifdef UNIX
    drmgr_register_signal_event( event_signal );
#endif

    free( client_opt_copy );
}

