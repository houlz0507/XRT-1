/*
 * Copyright (C) 2018, Xilinx Inc - All rights reserved
 * Xilinx SDAccel Media Accelerator API
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * not use this file except in compliance with the License. A copy of the
 * License is located at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "lib/xmaapi.h"
//#include "lib/xmahw_hal.h"
//#include "lib/xmares.h"
#include "xmaplugin.h"

#define XMA_FILTER_MOD "xmafilter"

extern XmaSingleton *g_xma_singleton;

XmaFilterSession*
xma_filter_session_create(XmaFilterProperties *filter_props)
{
    xma_logmsg(XMA_DEBUG_LOG, XMA_FILTER_MOD, "%s()\n", __func__);
    if (!g_xma_singleton->xma_initialized) {
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
                   "XMA session creation must be after initialization\n");
        return NULL;
    }

    // Load the xmaplugin library as it is a dependency for all plugins
    void *xmahandle = dlopen("libxmaplugin.so",
                             RTLD_LAZY | RTLD_GLOBAL);
    if (!xmahandle)
    {
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
                   "Failed to open plugin xmaplugin.so. Error msg: %s\n",
                   dlerror());
        return NULL;
    }
    void *handle = dlopen(filter_props->plugin_lib, RTLD_NOW);
    if (!handle)
    {
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
            "Failed to open plugin %s\n Error msg: %s\n",
            filter_props->plugin_lib, dlerror());
        return NULL;
    }

    XmaFilterPlugin *plg =
        (XmaFilterPlugin*)dlsym(handle, "filter_plugin");
    char *error;
    if ((error = dlerror()) != NULL)
    {
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
            "Failed to get filterer_plugin from %s\n Error msg: %s\n",
            filter_props->plugin_lib, dlerror());
        return NULL;
    }

    XmaFilterSession *filter_session = (XmaFilterSession*) malloc(sizeof(XmaFilterSession));
    if (filter_session == NULL) {
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
            "Failed to allocate memory for filterSession\n");
        return NULL;
    }
    memset(filter_session, 0, sizeof(XmaFilterSession));
    // init session data
    filter_session->props = *filter_props;
    filter_session->base.channel_id = filter_props->channel_id;
    filter_session->base.session_type = XMA_FILTER;
    filter_session->base.stats = NULL;
    filter_session->filter_plugin = plg;

    bool expected = false;
    bool desired = true;
    while (!(g_xma_singleton->locked).compare_exchange_weak(expected, desired)) {
        expected = false;
    }
    //Singleton lock acquired

    int32_t rc, dev_index, cu_index;
    dev_index = filter_props->dev_index;
    cu_index = filter_props->cu_index;
    //filter_handle = filter_props->cu_index;

    XmaHwCfg *hwcfg = &g_xma_singleton->hwcfg;
    if (dev_index >= hwcfg->num_devices || dev_index < 0) {
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
                   "XMA session creation failed. dev_index not found\n");
        //Release singleton lock
        g_xma_singleton->locked = false;
        free(filter_session);
        return NULL;
    }

    uint32_t hwcfg_dev_index = 0;
    bool found = false;
    for (XmaHwDevice& hw_device: g_xma_singleton->hwcfg.devices) {
        if (hw_device.dev_index == (uint32_t)dev_index) {
            found = true;
            break;
        }
        hwcfg_dev_index++;
    }
    if (!found) {
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
                   "XMA session creation failed. dev_index not loaded with xclbin\n");
        //Release singleton lock
        g_xma_singleton->locked = false;
        free(filter_session);
        return NULL;
    }
    if ((uint32_t)cu_index >= hwcfg->devices[hwcfg_dev_index].number_of_cus || cu_index < 0) {
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
                   "XMA session creation failed. Invalid cu_index = %d\n", cu_index);
        //Release singleton lock
        g_xma_singleton->locked = false;
        free(filter_session);
        return NULL;
    }
    if (hwcfg->devices[hwcfg_dev_index].kernels[cu_index].in_use) {
        xma_logmsg(XMA_INFO_LOG, XMA_FILTER_MOD,
                   "XMA session sharing CU: %s\n", hwcfg->devices[hwcfg_dev_index].kernels[cu_index].name);
    } else {
        xma_logmsg(XMA_INFO_LOG, XMA_FILTER_MOD,
                   "XMA session with CU: %s\n", hwcfg->devices[hwcfg_dev_index].kernels[cu_index].name);
    }

    filter_session->base.hw_session.dev_handle = hwcfg->devices[hwcfg_dev_index].handle;

    //For execbo:
    filter_session->base.hw_session.kernel_info = &hwcfg->devices[hwcfg_dev_index].kernels[cu_index];

    filter_session->base.hw_session.dev_index = hwcfg->devices[hwcfg_dev_index].dev_index;
    xma_logmsg(XMA_INFO_LOG, XMA_FILTER_MOD,
                "XMA session ddr_bank: %d\n", filter_session->base.hw_session.kernel_info->ddr_bank);

    // Call the plugins initialization function with this session data
    //Sarab: Check plugin compatibility to XMA
    int32_t xma_main_ver = -1;
    int32_t xma_sub_ver = -1;
    rc = filter_session->filter_plugin->xma_version(&xma_main_ver, & xma_sub_ver);
    if ((xma_main_ver == 2019 && xma_sub_ver < 2) || xma_main_ver < 2019 || rc < 0) {
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
                   "Initalization of plugin failed. Plugin is incompatible with this XMA version\n");
        //Release singleton lock
        g_xma_singleton->locked = false;
        free(filter_session);
        return NULL;
    }

    // Allocate the private data
    filter_session->base.plugin_data =
        calloc(filter_session->filter_plugin->plugin_data_size, sizeof(uint8_t));

    filter_session->base.session_id = g_xma_singleton->num_filters + 1;
    filter_session->base.session_signature = (void*)(((uint64_t)filter_session->base.hw_session.kernel_info) | ((uint64_t)filter_session->base.hw_session.dev_handle));
    xma_logmsg(XMA_INFO_LOG, XMA_FILTER_MOD,
                "XMA session channel_id: %d; filter_id: %d\n", filter_session->base.channel_id, filter_session->base.session_id);

    rc = filter_session->filter_plugin->init(filter_session);
    if (rc) {
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
                   "Initalization of filter plugin failed. Return code %d\n",
                   rc);
        //Release singleton lock
        g_xma_singleton->locked = false;
        free(filter_session->base.plugin_data);
        free(filter_session);
        return NULL;
    }

    g_xma_singleton->num_filters = filter_session->base.session_id;
    filter_session->base.hw_session.kernel_info->in_use = true;

    //Release singleton lock
    g_xma_singleton->locked = false;

    return filter_session;
}

int32_t
xma_filter_session_destroy(XmaFilterSession *session)
{
    int32_t rc;

    xma_logmsg(XMA_DEBUG_LOG, XMA_FILTER_MOD, "%s()\n", __func__);
    rc  = session->filter_plugin->close(session);
    if (rc != 0)
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
                   "Error closing filter plugin\n");

    // Clean up the private data
    free(session->base.plugin_data);

    /*Sarab: Remove xma_connect stuff
    // Free each sender connection
    xma_connect_free(session->conn_send_handle, XMA_CONNECT_SENDER);

    // Free the receiver connection
    xma_connect_free(session->conn_recv_handle, XMA_CONNECT_RECEIVER);
    */

    /* Remove xma_res stuff free kernel/kernel-session *--/
    rc = xma_res_free_kernel(g_xma_singleton->shm_res_cfg,
                             session->base.kern_res);
    if (rc)
        xma_logmsg(XMA_ERROR_LOG, XMA_FILTER_MOD,
                   "Error freeing filter session. Return code %d\n", rc);
    */
    // Free the session
    // TODO: (should also free the Hw sessions)
    free(session);

    return XMA_SUCCESS;
}

int32_t
xma_filter_session_send_frame(XmaFilterSession  *session,
                              XmaFrame          *frame)
{
    xma_logmsg(XMA_DEBUG_LOG, XMA_FILTER_MOD, "%s()\n", __func__);
    /*Sarab: Remove zerocopy stuff
    if (session->conn_send_handle != -1)
    {
        // Get the connection entry to find the receiver
        int32_t c_handle = session->conn_send_handle;
        XmaConnect *conn = &g_xma_singleton->connections[c_handle];
        XmaEndpoint *recv = conn->receiver;
        if (recv)
        {
            if (is_xma_encoder(recv->session))
            {
                XmaEncoderSession *e_ses = to_xma_encoder(recv->session);
                if (!e_ses->encoder_plugin->get_dev_input_paddr) {
                    xma_logmsg(XMA_DEBUG_LOG, XMA_FILTER_MOD,
                        "encoder plugin does not support zero copy\n");
                    goto send;
		}
                session->out_dev_addr = e_ses->encoder_plugin->get_dev_input_paddr(e_ses);
                session->zerocopy_dest = true;
            }
        }
    }
send:
    */
    return session->filter_plugin->send_frame(session, frame);
}

int32_t
xma_filter_session_recv_frame(XmaFilterSession  *session,
                              XmaFrame          *frame)
{
    xma_logmsg(XMA_DEBUG_LOG, XMA_FILTER_MOD, "%s()\n", __func__);
    return session->filter_plugin->recv_frame(session, frame);
}
