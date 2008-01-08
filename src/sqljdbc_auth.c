/*
 * libsqljdbc_auth - Unix support for integrated authentication with
 *                   the Microsoft SQL Server 2005 JDBC Driver
 *
 * Copyright (c) 2008, Dino A. Dai Zovi <ddz@theta44.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.  Neither the name of Theta44 nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * TODO:
 * - Use libntlm for NTLM authentication using supplied username,
 *   password, and domain.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <sys/socket.h>

/*
 * Check our autoconf definitions and set flags for whether we support
 * KRB5, NTLM, or both.
 */
#if defined(HAVE_GSSAPI_H) && defined(HAVE_GSSAPI_GSSAPI_KRB5_H)
  #include <gssapi.h>
  #include <gssapi/gssapi_krb5.h>
  #define DO_KRB5
#elif defined(HAVE_NTLM_H)
  #include <ntlm.h>
  #define DO_NTLM
#else
  #error "No supported authentication methods (KRB5 or NTLM) found"
#endif

#include "com_microsoft_sqlserver_jdbc_AuthenticationJNI.h"

typedef struct {
    gss_ctx_id_t    handle;      /* GSS context handle          */
    gss_name_t      target;      /* Service Principal Name      */
    gss_cred_id_t   credentials; /* Kerberos credentials handle */
    gss_OID         mech_type;   /* Actual mechanism type used  */
    gss_buffer_desc token;       /* Last received auth token    */
} context_t;

static int
gss_status(const gss_OID mech_type, OM_uint32 major, OM_uint32 minor,
           const char* prefix, char* status, size_t size)
{
    OM_uint32 context = 0;
    OM_uint32 major_status, minor_status;
    gss_buffer_desc maj_status_str, min_status_str;
    
    major_status = gss_display_status(&minor_status, major,
                                      GSS_C_GSS_CODE, mech_type,
                                      &context, &maj_status_str);
    if (minor) {
        major_status = gss_display_status(&minor_status, minor,
                                          GSS_C_MECH_CODE, mech_type,
                                          &context, &min_status_str);

        return snprintf(status, size, "%s: %*s (%*s)",
                        prefix,
                        (int)maj_status_str.length,
                        (char*)maj_status_str.value,
                        (int)min_status_str.length,
                        (char*)min_status_str.value);
    }
    else {
        return snprintf(status, size, "%s: %*s",
                        prefix,
                        (int)maj_status_str.length,
                        (char*)maj_status_str.value);
    }
}

typedef enum {
    ENTERING, EXITING, FINEST, FINER, FINE, CONFIG, INFO, WARNING, SEVERE
} logging_level_t;

static void
logger_log(JNIEnv *env, jobject logger, logging_level_t level,
           const char* message)
{
    static int is_initialized = 0;
    static jclass logger_class;
    static jmethodID entering, exiting, finest, finer, fine, config,
        info, warning, severe;
    static jobject class_jstr;
    jobject message_jstr;

    if (!is_initialized) {
        /*
         * Cache lookups of method ids
         */
        logger_class = (*env)->GetObjectClass(env, logger);
        
        entering = (*env)->GetMethodID(
            env, logger_class,
            "entering", "(Ljava/lang/String;Ljava/lang/String;)V");
        
        exiting = (*env)->GetMethodID(
            env, logger_class,
            "exiting", "(Ljava/lang/String;Ljava/lang/String;)V");

        finest = (*env)->GetMethodID(
            env, logger_class,
            "finest", "(Ljava/lang/String;)V");
        
        finer = (*env)->GetMethodID(
            env, logger_class,
            "finer", "(Ljava/lang/String;)V");

        fine = (*env)->GetMethodID(
            env, logger_class,
            "fine", "(Ljava/lang/String;)V");

        config = (*env)->GetMethodID(
            env, logger_class,
            "config", "(Ljava/lang/String;)V");

        info = (*env)->GetMethodID(
            env, logger_class,
            "info", "(Ljava/lang/String;)V");

        warning = (*env)->GetMethodID(
            env, logger_class,
            "warning", "(Ljava/lang/String;)V");

        severe = (*env)->GetMethodID(
            env, logger_class,
            "severe", "(Ljava/lang/String;)V");
        
        is_initialized = 1;
    }

    class_jstr = (*env)->NewStringUTF(
        env, "com.microsoft.sqlserver.jdbc.AuthenticationJNI");
    
    message_jstr = (*env)->NewStringUTF(env, message);

    switch (level) {
    case ENTERING:
        (*env)->CallVoidMethod(env, logger, entering,
                               class_jstr, message_jstr);
        break;
    case EXITING:
        (*env)->CallVoidMethod(env, logger, exiting,
                               class_jstr, message_jstr);
        break;
    case FINEST:
        (*env)->CallVoidMethod(env, logger, finest, message_jstr);
        break;
    case FINER:
        (*env)->CallVoidMethod(env, logger, finer, message_jstr);
        break;
    case FINE:
        (*env)->CallVoidMethod(env, logger, fine, message_jstr);
        break;
    case CONFIG:
        (*env)->CallVoidMethod(env, logger, config, message_jstr);
        break;
    case INFO:
        (*env)->CallVoidMethod(env, logger, info, message_jstr);
        break;
    case WARNING:
        (*env)->CallVoidMethod(env, logger, warning, message_jstr);
        break;
    case SEVERE:
        (*env)->CallVoidMethod(env, logger, severe, message_jstr);
        break;
    }
}

/*********************************************************************
                   AuthenticationJNI Native Methods
 *********************************************************************/

JNIEXPORT jint JNICALL
Java_com_microsoft_sqlserver_jdbc_AuthenticationJNI_SNISecInitPackage(
    JNIEnv *env,
    jclass klass,
    jintArray tokenMaxSize,
    jobject logger)
{
    /*
     * Return maximum authentication token size
     */
    int val = 65535;

    logger_log(env, logger, ENTERING, "SNISecInitPackage");
    
    (*env)->SetIntArrayRegion(env, tokenMaxSize, 0, 1, (void*)&val);

    logger_log(env, logger, EXITING, "SNISecInitPackage");
    
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_microsoft_sqlserver_jdbc_AuthenticationJNI_SNISecTerminatePackage(
    JNIEnv *env,
    jclass klass,
    jobject logger)
{

    logger_log(env, logger, ENTERING, "SNISecTerminatePackage");

    /* Do nothing */
    
    logger_log(env, logger, EXITING, "SNISecTerminatePackage");
    
    return 0;
}

/*
 * This is where the magic happens
 */
JNIEXPORT jint JNICALL
Java_com_microsoft_sqlserver_jdbc_AuthenticationJNI_SNISecGenClientContext(
    JNIEnv *env,
    jclass klass,
    jbyteArray jniContext,
    jintArray jniContextSize,
    jbyteArray authTokenIn,
    jint authTokenInSize,
    jbyteArray authTokenOut,
    jintArray authTokenOutSize,    
    jbooleanArray isContextComplete,
    jstring DNSNameAndPort,
    jstring jstring0,                   /* Unknown; usually NULL */
    jstring jstring1,                   /* Unknown; usually NULL */
    jobject logger)
{
    OM_uint32 major_status, minor_status, ret_flags;
    gss_buffer_desc output_token;
    
    context_t* context;
    size_t context_len;
    char status[1024];
    jboolean is_context_complete;
    
    logger_log(env, logger, ENTERING, "SNISecGenClientContext");
    
    if (authTokenIn == NULL) {
        const char* fqdn_and_port;
        char spn_str[2048];
        gss_buffer_desc input_name;
        gss_OID_set actual_mechs;
        
        /*
         * Allocate and initialize our context structure
         */
        context_len = sizeof(context_t);
        context = malloc(context_len);
        context->handle = GSS_C_NO_CONTEXT;
        context->target = GSS_C_NO_NAME;
        context->token.length = 0;
        context->token.value = NULL;
        
        /*
         * DNSNameAndPort is "<server>:<port>"
         */
        fqdn_and_port =
            (*env)->GetStringUTFChars(env, DNSNameAndPort, NULL);
        snprintf(spn_str, sizeof(spn_str), "MSSQLSvc/%s", fqdn_and_port);
        (*env)->ReleaseStringUTFChars(env, DNSNameAndPort, fqdn_and_port);

        /* Create service name with gss_import_name() */
        input_name.value = spn_str;
        input_name.length = strlen(spn_str);
        major_status = gss_import_name(&minor_status, &input_name,
                                       GSS_KRB5_NT_PRINCIPAL_NAME,
                                       &(context->target));

        if (GSS_ERROR(major_status)) {
            gss_status(GSS_KRB5_NT_PRINCIPAL_NAME,
                       major_status, minor_status,
                       "gss_import_name",
                       status, sizeof(status));
            logger_log(env, logger, SEVERE, status);

            return -1;
        }

        /*
         * Try to acquire our credentials first, before calling
         * gss_init_sec_context.
         *
         * XXX: We should pull in username JDBC URL option if
         * specified, and try to acquire the credential for that user.
         */
        major_status = gss_acquire_cred(&minor_status,
                                        GSS_C_NO_NAME,
                                        GSS_C_INDEFINITE,
                                        GSS_C_NO_OID_SET,
                                        GSS_C_INITIATE,
                                        &(context->credentials),
                                        &actual_mechs, NULL);
        if (GSS_ERROR(major_status)) {
            gss_status(actual_mechs->elements,
                       major_status, minor_status,
                       "gss_acquire_cred", status, sizeof(status));
            logger_log(env, logger, SEVERE, status);
            return -1;
        }
    }
    else {
        /*
         * Retrieve our context structure
         */

        (*env)->GetIntArrayRegion(env, jniContextSize, 0, 1,
                                  (void*)&context_len);
        context = malloc(context_len);
        (*env)->GetByteArrayRegion(env, jniContext, 0, context_len,
                                   (void*)context);

        /*
         * Copy sspiBlob into a gss_token for use by gss_init_sec_context.
         */
        context->token.value = malloc(authTokenInSize);
        context->token.length = authTokenInSize;

        (*env)->GetByteArrayRegion(env, authTokenIn, 0, authTokenInSize,
                                   context->token.value);
    }

    major_status = gss_init_sec_context(&minor_status,
                                        context->credentials,
                                        &(context->handle),
                                        context->target,
                                        GSS_C_NO_OID,
                                        GSS_C_MUTUAL_FLAG,
                                        GSS_C_INDEFINITE,
                                        GSS_C_NO_CHANNEL_BINDINGS,
                                        &(context->token),
                                        &(context->mech_type),
                                        &output_token,
                                        &ret_flags, NULL);
    if (GSS_ERROR(major_status)) {
        gss_status(context->mech_type, major_status, minor_status,
                   "gss_init_sec_context", status, sizeof(status));
        logger_log(env, logger, SEVERE, status);
        return -1;
    }

    /* Indicate whether context establishment is complete */
    is_context_complete = (major_status == GSS_S_COMPLETE);
    (*env)->SetBooleanArrayRegion(env, isContextComplete, 0, 1,
                                  (void*)&is_context_complete);
    
    /*
     * Copy output token into Java byte array authTokenOut
     */
    (*env)->SetByteArrayRegion(env, authTokenOut, 0,
                               output_token.length, output_token.value);
    (*env)->SetIntArrayRegion(env, authTokenOutSize, 0,
                              1, (void*)&output_token.length);
    
    major_status = gss_release_buffer(&minor_status, &output_token);
    if (GSS_ERROR(major_status)) {
        gss_status(context->mech_type, major_status, minor_status,
                   "gss_release_buffer", status, sizeof(status));
        logger_log(env, logger, WARNING, status);
    }

    /*
     * Copy our context structure back into jniContext byte array
     */
    (*env)->SetByteArrayRegion(env, jniContext, 0, context_len,
                               (void*)context);
    (*env)->SetIntArrayRegion(env, jniContextSize, 0, 1, (void*)&context_len);

    free(context);

    logger_log(env, logger, EXITING, "SNISecGenClientContext");
    
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_microsoft_sqlserver_jdbc_AuthenticationJNI_SNISecReleaseClientContext(
    JNIEnv *env,
    jclass klass,
    jbyteArray sniSec,
    jint sniSecSize,
    jobject logger)
{

    OM_uint32 major_status, minor_status;
    char status[1024];
    context_t* context;
    size_t context_len;

    logger_log(env, logger, EXITING, "SNISecReleaseClientContext");
    
    /*
     * Retrieve our context structure
     */
    context_len = sniSecSize;
    context = malloc(context_len);
    (*env)->GetByteArrayRegion(env, sniSec, 0, context_len,
                               (void*)context);
    
    major_status = gss_delete_sec_context(&minor_status,
                                          &(context->handle),
                                          GSS_C_NO_BUFFER);
    if (GSS_ERROR(major_status)) {
        gss_status(context->mech_type, major_status, minor_status,
                   "gss_delete_sec_context", status, sizeof(status));
        logger_log(env, logger, WARNING, status);
    }

    major_status = gss_release_name(&minor_status, &(context->target));
    if (GSS_ERROR(major_status)) {
        gss_status(context->mech_type, major_status, minor_status,
                   "gss_release_name", status, sizeof(status));
        logger_log(env, logger, WARNING, status);
    }

    major_status = gss_release_buffer(&minor_status, &(context->token));
    if (GSS_ERROR(major_status)) {
        gss_status(context->mech_type, major_status, minor_status,
                   "gss_release_buffer", status, sizeof(status));
        logger_log(env, logger, WARNING, status);
    }

    free(context);

    logger_log(env, logger, EXITING, "SNISecReleaseClientContext");
    
    return 0;
}


/*
 * Lookup the canonical fully qualified domain name for the server
 * name given in the JDBC URL.
 */
JNIEXPORT jint JNICALL
Java_com_microsoft_sqlserver_jdbc_AuthenticationJNI_GetDNSName(
    JNIEnv *env,
    jclass klass,
    jstring serverName,
    jobjectArray DNSName,
    jobject logger)
{
    const char* node;
    struct addrinfo hints, *ai;
    int gai_errno;
    jstring dns_name;
    char message[1024];

    logger_log(env, logger, ENTERING, "GetDNSName");

    node = (*env)->GetStringUTFChars(env, serverName, NULL);
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;
    
    hints.ai_flags = AI_CANONNAME;    /* We want canonical FQDN */
           
    if ((gai_errno = getaddrinfo(node, NULL, &hints, &ai)) < 0) {
        snprintf(message, sizeof(message),
                 "getaddrinfo(%s, ...): %s\n", node, gai_strerror(gai_errno));
        logger_log(env, logger, SEVERE, message);
        return -1;
    }
    
    snprintf(message, sizeof(message),
             "Found canonical name: %s -> %s\n", node, ai->ai_canonname);
    logger_log(env, logger, FINE, message);

    dns_name = (*env)->NewStringUTF(env, ai->ai_canonname);    
    (*env)->SetObjectArrayElement(env, DNSName, 0, dns_name);
    
    freeaddrinfo(ai);

    (*env)->ReleaseStringUTFChars(env, serverName, node);

    logger_log(env, logger, EXITING, "GetDNSName");
    
    return 0;
}

/* Never called */
JNIEXPORT jint JNICALL
Java_com_microsoft_sqlserver_jdbc_AuthenticationJNI_SNIGetSID(
    JNIEnv *env,
    jclass klass,
    jbyteArray SID,
    jobject logger)
{
    logger_log(env, logger, ENTERING, "SNIGetSID");
    
    /* Do nothing */

    logger_log(env, logger, EXITING, "SNIGetSID");
    
    return 0;
}

/* Never called */
JNIEXPORT jboolean JNICALL
Java_com_microsoft_sqlserver_jdbc_AuthenticationJNI_SNIIsEqualToCurrentSID(
    JNIEnv *env,
    jclass klass,
    jbyteArray SID,
    jobject logger)
{
    logger_log(env, logger, EXITING, "SNIIsEqualToCurrentSID");

    /* Do nothing */
    
    logger_log(env, logger, EXITING, "SNIIsEqualToCurrentSID");
    
    return 1;
}

