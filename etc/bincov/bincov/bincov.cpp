/// @file: bincov.cpp
/// @brief: binary coverage tool
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
#include "dr_tools.h"
#include <sparsehash/dense_hash_map>
#include <string>
#include <list>
#include <map>
#include <cstring>
#include "common.hpp"

using google::dense_hash_map;

#define CBR_NEITHER      0x00
#define CBR_TRUE_BRANCH  0x01
#define CBR_FALSE_BRANCH 0x10

void *map_lock, *set_lock;

typedef uint64 addr_t;
typedef dense_hash_map< addr_t, int, std::tr1::hash< addr_t > > addr_map_t;
typedef std::map< std::string, addr_map_t* > module_addr_map_t;

static addr_map_t br_tbl;
static module_addr_map_t visited_tbl;
static std::list< int > pid_list;
static int path_hash = 0;

typedef enum {
    node_coverage,
    path_coverage
} cov_mode_t;

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

static int g_pipe = 0;
static cov_mode_t g_cov = node_coverage;
static run_mode_t g_mode = console_mode;
static int g_timeout = 0;
static unsigned int g_path_hash = 0;

//
// several knobs for experiments
//

// #define DEDUP_INSTRUMENTATION
// #define COUNT_INSTRUMENTATION

#ifdef COUNT_INSTRUMENTATION
static unsigned long instrument_count = 0;
#endif

#ifndef MAXSIZE
#define MAXSIZE  16384
#endif

static void at_branch_for_nodecoverage( app_pc src, app_pc next, int branch_kind )
{
    dr_mcontext_t mcontext = { sizeof(mcontext), DR_MC_ALL, };
    void *drcontext = dr_get_current_drcontext();
    module_data_t *mod = dr_lookup_module( src );
    addr_t relative_targ = (addr_t) next - (addr_t) (mod->start);
    addr_map_t::iterator it;
    addr_map_t* addr_map;

    dr_mutex_lock( map_lock );
    br_tbl[(addr_t)src] |= branch_kind;
    dr_mutex_unlock( map_lock );

    addr_map = visited_tbl[mod->full_path];
    dr_mutex_lock( set_lock );
    it = addr_map->find( relative_targ );
    if ( it != addr_map->end() ) {
        it->second += 1;
    } else {
        addr_map->insert( std::make_pair( relative_targ, 1 ) );
    }
    dr_mutex_unlock( set_lock );

#ifdef COUNT_INSTRUMENTATION
    instrument_count += 1;
#endif

#ifdef DEDUP_INSTRUMENTATION
    dr_flush_region( src, 1 );
#endif
    dr_get_mcontext( drcontext, &mcontext );
    mcontext.pc = next;
    dr_redirect_execution( &mcontext );
}

static void at_true_nodecoverage( app_pc src, app_pc targ )
{
    at_branch_for_nodecoverage( src, targ, CBR_TRUE_BRANCH );
}

static void at_false_nodecoverage( app_pc src, app_pc fall )
{
    at_branch_for_nodecoverage( src, fall, CBR_FALSE_BRANCH );
}

// MurmurHash2, by Austin Appleby
// removed seed param
unsigned int
strhash( const void * key, int len )
{
    // 'm' and 'r' are mixing constants generated offline.
    // They're not really 'magic', they just happen to work well.

    const unsigned int m = 0x5bd1e995;
    const int r = 24;

    // Initialize the hash to a 'random' value

    unsigned int h = len;

    // Mix 4 bytes at a time into the hash

    const unsigned char * data = (const unsigned char *) key;

    while( len >= 4 )
    {
        unsigned int k = *(unsigned int *)data;

        k *= m;
        k ^= k >> r;
        k *= m;

        h *= m;
        h ^= k;

        data += 4;
        len -= 4;
    }

    // Handle the last few bytes of the input array

    switch( len )
    {
    case 3: h ^= data[2] << 16;
    case 2: h ^= data[1] << 8;
    case 1: h ^= data[0];
            h *= m;
    };

    // Do a few final mixes of the hash to ensure the last few
    // bytes are well-incorporated.

    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return h;
}

static void at_branch_for_pathcov( app_pc src, app_pc next, int branch_kind )
{
    dr_mcontext_t mcontext = { sizeof(mcontext), DR_MC_ALL, };
    void *drcontext = dr_get_current_drcontext();
    module_data_t *mod = dr_lookup_module( src );
    addr_t relative_targ = (addr_t) next - (addr_t) (mod->start);
    unsigned int *data = (unsigned int *) dr_get_tls_field( drcontext );
    char buf[MAXSIZE];
    char* ptr = buf;

    dr_mutex_lock( map_lock );
    br_tbl[(addr_t)src] |= branch_kind;
    dr_mutex_unlock( map_lock );

    memcpy( ptr, data, sizeof(int) );
    ptr += sizeof(int);
    strcpy( ptr, mod->full_path );
    ptr += strlen( mod->full_path );
    memcpy( ptr, (void*) &relative_targ, sizeof(app_pc) );

    *data += strhash( buf, (unsigned)(ptr-buf)+sizeof(app_pc) );

#ifdef COUNT_INSTRUMENTATION
    instrument_count += 1;
#endif

#ifdef DEDUP_INSTRUMENTATION
    dr_flush_region( src, 1 );
#endif
    dr_get_mcontext( drcontext, &mcontext );
    mcontext.pc = next;
    dr_redirect_execution( &mcontext );
}

static void at_true_pathcoverage( app_pc src, app_pc targ )
{
    at_branch_for_pathcov( src, targ, CBR_TRUE_BRANCH );
}

static void at_false_pathcoverage( app_pc src, app_pc fall )
{
    at_branch_for_pathcov( src, fall, CBR_FALSE_BRANCH );
}

static void (*g_true_br)( app_pc src, app_pc targ ) = at_true_nodecoverage;
static void (*g_false_br)( app_pc src, app_pc targ ) = at_false_nodecoverage;

static dr_emit_flags_t
bb_event( void *drcontext,
          void *tag,
          instrlist_t *bb,
          bool for_trace,
          bool translating )
{
    instr_t *instr, *next_instr;
    addr_map_t::const_iterator it;

    for ( instr = instrlist_first(bb); instr != NULL; instr = next_instr ) {
        next_instr = instr_get_next( instr );

        if ( instr_is_cbr( instr ) ) {
            int state;
#ifdef DEDUP_INSTRUMENTATION
            bool insert_taken, insert_not_taken;
#endif
            addr_t src = (addr_t) instr_get_app_pc( instr );

            it = br_tbl.find( src );
            if ( it == br_tbl.end() ) {
                state = CBR_NEITHER;
                dr_mutex_lock( map_lock );
                br_tbl[src] = CBR_NEITHER;
                dr_mutex_unlock( map_lock );
            }
            else {
                state = it->second;
            }

#ifdef DEDUP_INSTRUMENTATION
            insert_taken = (state & CBR_TRUE_BRANCH) == 0;
            insert_not_taken = (state & CBR_FALSE_BRANCH) == 0;

            if ( insert_taken | insert_not_taken ) {
#endif
                app_pc fall = (app_pc) decode_next_pc( drcontext, (byte *)src );
                app_pc targ = instr_get_branch_target_pc( instr );

                instr_t *label = INSTR_CREATE_label( drcontext );
                instr_set_meta_no_translation( instr );
                if ( instr_is_cti_short( instr ) ) {
                    instr = instr_convert_short_meta_jmp_to_long( drcontext,
                                                                  bb,
                                                                  instr );
                }
                instr_set_target(instr, opnd_create_instr(label));

#ifdef DEDUP_INSTRUMENTATION
                if ( insert_not_taken ) {
#endif
                    dr_insert_clean_call( drcontext, bb, NULL,
                                          (void*) g_false_br,
                                          false /* don't save fp state */,
                                          2 /* 2 args */,
                                          OPND_CREATE_INTPTR(src),
                                          OPND_CREATE_INTPTR(fall) );
#ifdef DEDUP_INSTRUMENTATION
                }
#endif

                instrlist_preinsert( bb, NULL,
                                     INSTR_XL8(
                                         INSTR_CREATE_jmp
                                         (drcontext, opnd_create_pc(fall)),
                                         fall) );

                instrlist_meta_preinsert( bb, NULL, label );

#ifdef DEDUP_INSTRUMENTATION
                if ( insert_taken ) {
#endif
                    dr_insert_clean_call( drcontext, bb, NULL,
                                          (void*) g_true_br,
                                          false /* don't save fp state */,
                                          2 /* 2 args */,
                                          OPND_CREATE_INTPTR(src),
                                          OPND_CREATE_INTPTR(targ) );
#ifdef DEDUP_INSTRUMENTATION
                }
#endif

                instrlist_preinsert( bb, NULL,
                                     INSTR_XL8(
                                         INSTR_CREATE_jmp(
                                             drcontext,
                                             opnd_create_pc(targ)), targ )
                                   );
#ifdef DEDUP_INSTRUMENTATION
            }
#endif
        }
    }

    return DR_EMIT_STORE_TRANSLATIONS;
}

#include <unistd.h>
#include <sys/file.h>
#include <fcntl.h>
bool is_valid_descriptor( int fd )
{
    return fcntl( fd, F_GETFD ) != -1;
}

void emit_node_coverage_result( int pipe, term_mode_t term, bool to_console )
{
    char buf[MAXSIZE];
    unsigned int num = (unsigned int) visited_tbl.size();
    unsigned int pos = 0;
    module_addr_map_t::const_iterator it;

    // output in the following format:
    // @START@;
    // normal or crash;
    // num_modules;
    // module_path;
    // size_of_addrs;
    // addrs array (addr @ count);
    // ...
    // @END@

    snprintf( buf, MAXSIZE - 1, "@START@\n%d\n%u\n", (int) term, num );
    write( pipe, buf, strlen(buf) );

    for ( it = visited_tbl.begin(); it != visited_tbl.end(); ++it ) {
        const char* module_path = it->first.c_str();
        unsigned int size = it->second->size();

        snprintf( buf, MAXSIZE - 1, "%s\n%u\n", module_path, size );
        write( pipe, buf, strlen(buf) );

        pos = 0;
        for ( addr_map_t::const_iterator ci = it->second->begin();
              ci != it->second->end();
              ++ci )
        {
            pos += snprintf( buf + pos, MAXSIZE - 1 - pos, "0x%llx"SEP_CHAR"%d\n", ci->first, ci->second );

            if ( pos > MAXSIZE - 32 /* enough room */ ) {
                write( pipe, buf, strlen(buf) );
                pos = 0;
                continue;
            }
        }

        if ( pos > 0 ) {
            write( pipe, buf, strlen(buf) );
        }
    }

    snprintf( buf, MAXSIZE - 1, "@END@\n" );
    write( pipe, buf, strlen(buf) );
}

void emit_path_coverage_result( int pipe, term_mode_t term, bool to_console )
{
    char buf[MAXSIZE];

    // output in the following format:
    // @START@;
    // normal or crash;
    // path hash
    // @END@

    snprintf( buf, MAXSIZE - 1, "@START@\n%d\n0x%x\n", (int) term, g_path_hash );
    write( pipe, buf, strlen(buf) );

    snprintf( buf, MAXSIZE - 1, "@END@\n" );
    write( pipe, buf, strlen(buf) );
}

void emit_result( term_mode_t term, bool to_console )
{
    int pipe = g_pipe;

    if ( to_console ) {
        pipe = fileno( stdout );
    } else {
        DR_ASSERT( is_valid_descriptor( pipe ) && "pipe not opened" );
    }

    flock( pipe, LOCK_SH );

    if ( g_cov == node_coverage )
        emit_node_coverage_result( pipe, term, to_console );
    else
        emit_path_coverage_result( pipe, term, to_console );

    flock( pipe, LOCK_UN );
    close( pipe );
}

void at_term( term_mode_t term )
{
#ifdef COUNT_INSTRUMENTATION
    fprintf( stderr, "instrumented: %ld\n", instrument_count );
#endif

    emit_result( term, g_mode == console_mode );

    dr_mutex_destroy( map_lock );
    dr_mutex_destroy( set_lock );
}

void dr_exit( void )
{
    at_term( normal_term );
}

#ifdef UNIX
#include <signal.h>
#include <sys/time.h>

static
dr_signal_action_t event_signal( void *drcontext, dr_siginfo_t *info )
{
    if ( info->sig == SIGTERM ) {
        /* Ignore TERM */
        return DR_SIGNAL_BYPASS;
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
    dr_exit_process( 1 );
    at_term( timeout_term );
    exit( 1 );
}

#endif

void
error_exit( const char* msg )
{
    fprintf( stderr, msg );
    exit( 1 );
}

void module_load_event( void *drcontext,
                        const module_data_t *info,
                        bool loaded )
{
    visited_tbl[info->full_path] = new addr_map_t;
    if ( !visited_tbl[info->full_path] )
        error_exit( "load info alloc failed" );

    visited_tbl[info->full_path]->set_empty_key( 0 );
}

static void
event_thread_init( void *drcontext )
{
    unsigned int *data =
        (unsigned int *) dr_thread_alloc( drcontext, sizeof(unsigned int) );
    dr_set_tls_field( drcontext, data );
    *data = 0;
}

static void
event_thread_exit(void *drcontext)
{
    unsigned int *data = (unsigned int *) dr_get_tls_field( drcontext );

    g_path_hash += *data;

    dr_thread_free( drcontext, data, sizeof(unsigned int) );
}

bool
is_main( const char* appname, const char* client_opt )
{
    if ( !client_opt ) return true;
    return (strcmp( client_opt, appname ) == 0);
}

static
void parse_coverage_type( const char* token )
{
    if ( token[0] == 'p' ) {
        g_true_br = at_true_pathcoverage;
        g_false_br = at_false_pathcoverage;
        g_cov = path_coverage;
    }
    else {
        g_true_br = at_true_nodecoverage;
        g_false_br = at_false_nodecoverage;
        g_cov = node_coverage;
    }
}

char*
parse_client_opt( char* client_opt )
{
    // pipe mode: programname@covmode@timeout@file_descriptor
    // console mode: programname@covmode@timeout
    char* prog_token;
    char* cov_token;
    char* fd_token;
    char* timeout_token;

    prog_token = strtok( client_opt, SEP_CHAR );
    cov_token = strtok( NULL, SEP_CHAR );
    if ( !cov_token ) {
        error_exit( "invalid client option\n" );
    }
    parse_coverage_type( cov_token );

    timeout_token = strtok( NULL, SEP_CHAR );
    if ( !timeout_token ) {
        error_exit( "invalid client option\n" );
    }
    fd_token = strtok( NULL, SEP_CHAR );
    if ( !fd_token ) { // console mode
        g_timeout = ((int) strtoul( timeout_token, NULL, 10 )) * 1000;
        g_mode = console_mode;
    } else {
        g_timeout = ((int) strtoul( timeout_token, NULL, 10 )) * 1000;
        g_mode = pipe_mode;
        g_pipe = (int) strtoul( fd_token, NULL, 10 );
    }

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

    if ( g_cov == path_coverage ) {
        dr_register_thread_init_event( event_thread_init );
        dr_register_thread_exit_event( event_thread_exit );
    }

    map_lock = dr_mutex_create();
    set_lock = dr_mutex_create();

    br_tbl.set_empty_key( 0 );

    dr_register_module_load_event( module_load_event );
    dr_register_bb_event( bb_event );
    dr_register_exit_event( dr_exit );
#ifdef UNIX
    dr_register_signal_event( event_signal );
#endif

    free( client_opt_copy );
}

