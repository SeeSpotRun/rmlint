/**
* This file is part of rmlint.
*
*  rmlint is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  rmlint is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with rmlint.  If not, see <http://www.gnu.org/licenses/>.
*
* Authors:
*
*  - Christopher <sahib> Pahl 2010-2015 (https://github.com/sahib)
*  - Daniel <SeeSpotRun> T.   2014-2015 (https://github.com/SeeSpotRun)
*
* Hosted on http://github.com/sahib/rmlint
**/

#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "cfg.h"

/* Options not specified by commandline get a default option -
 * this is usually called before rm_cmd_parse_args */
void rm_cfg_set_default(RmCfg *cfg) {
    /* Set everything to 0 at first,
     * only non-null options are listed below.
     */
    memset(cfg, 0, sizeof(RmCfg));

    /* Traversal options */
    cfg->depth = PATH_MAX / 2;
    cfg->minsize = 1;
    cfg->maxsize = (RmOff)-1;

    /* Lint Types */
    cfg->ignore_hidden = true;
    cfg->find_emptydirs = true;
    cfg->find_emptyfiles = true;
    cfg->find_duplicates = true;
    cfg->find_badids = true;
    cfg->find_badlinks = true;
    cfg->find_hardlinked_dupes = true;
    cfg->build_fiemap = true;
    cfg->crossdev = true;
    cfg->list_mounts = true;

    /* Misc options */
    cfg->sort_criteria = g_strdup("pm");

    cfg->checksum_type = RM_DEFAULT_DIGEST;
    cfg->with_color = true;
    cfg->with_stdout_color = true;
    cfg->with_stderr_color = true;
    cfg->read_threads = 12;
    cfg->hash_threads = 12;
    cfg->threads_per_hdd = 2;
    cfg->threads_per_ssd = 8;
    cfg->verbosity = G_LOG_LEVEL_INFO;
    cfg->follow_symlinks = false;

    cfg->total_mem = (RmOff)1024 * 1024 * 1024;
    /* empirical optimum for paranoid option based on limited testing */
    cfg->sweep_count = 4 * 1024;

    cfg->skip_start_factor = 0.0;
    cfg->skip_end_factor = 1.0;

    cfg->use_absolute_start_offset = false;
    cfg->use_absolute_end_offset = false;
    cfg->skip_start_offset = 0;
    cfg->skip_end_offset = 0;

    rm_trie_init(&cfg->file_trie);
    g_queue_init(&cfg->replay_files);

    cfg->pattern_cache = g_ptr_array_new_full(0, (GDestroyNotify)g_regex_unref);
}
