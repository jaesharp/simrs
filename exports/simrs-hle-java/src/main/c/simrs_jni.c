/*
 * JNI shim bridging com.simrs.Sim native methods to the SimRS C API.
 * Compiled into libsimrs_jni.so which links against libsimrs_hle_capi.so.
 */

#include <jni.h>
#include <string.h>
#include "simrs.h"

/* --- Initialization --- */

JNIEXPORT void JNICALL
Java_com_simrs_Sim_nativeInit(JNIEnv *env, jclass cls,
                              jbyteArray jki, jbyteArray jk, jbyteArray jopc)
{
    jbyte *ki  = (*env)->GetByteArrayElements(env, jki, NULL);
    jbyte *k   = (*env)->GetByteArrayElements(env, jk, NULL);
    jbyte *opc = (*env)->GetByteArrayElements(env, jopc, NULL);

    simrs_init((const uint8_t *)ki, (const uint8_t *)k, (const uint8_t *)opc);

    (*env)->ReleaseByteArrayElements(env, jki, ki, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jk, k, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jopc, opc, JNI_ABORT);
}

JNIEXPORT jboolean JNICALL
Java_com_simrs_Sim_nativeInitProfile(JNIEnv *env, jclass cls, jbyteArray jder)
{
    jsize len = (*env)->GetArrayLength(env, jder);
    jbyte *der = (*env)->GetByteArrayElements(env, jder, NULL);

    uint32_t ok = simrs_init_profile((const uint8_t *)der, (uint32_t)len);

    (*env)->ReleaseByteArrayElements(env, jder, der, JNI_ABORT);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_simrs_Sim_nativeInitFromSnapshot(JNIEnv *env, jclass cls, jbyteArray jsnap)
{
    jsize len = (*env)->GetArrayLength(env, jsnap);
    jbyte *snap = (*env)->GetByteArrayElements(env, jsnap, NULL);

    uint32_t ok = simrs_init_from_snapshot((const uint8_t *)snap, (uint32_t)len);

    (*env)->ReleaseByteArrayElements(env, jsnap, snap, JNI_ABORT);
    return ok ? JNI_TRUE : JNI_FALSE;
}

/* --- Reset --- */

JNIEXPORT jbyteArray JNICALL
Java_com_simrs_Sim_nativeReset(JNIEnv *env, jclass cls)
{
    uint8_t atr_buf[64];
    uint32_t atr_len = simrs_reset(atr_buf, sizeof(atr_buf));
    if (atr_len == 0) return NULL;

    jbyteArray result = (*env)->NewByteArray(env, (jsize)atr_len);
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)atr_len, (const jbyte *)atr_buf);
    return result;
}

/* --- APDU --- */

JNIEXPORT jbyteArray JNICALL
Java_com_simrs_Sim_nativeApdu(JNIEnv *env, jclass cls, jbyteArray jcmd)
{
    jsize cmd_len = (*env)->GetArrayLength(env, jcmd);
    jbyte *cmd = (*env)->GetByteArrayElements(env, jcmd, NULL);

    uint8_t rsp_buf[258];
    uint32_t rsp_len = simrs_apdu((const uint8_t *)cmd, (uint32_t)cmd_len,
                                  rsp_buf, sizeof(rsp_buf));

    (*env)->ReleaseByteArrayElements(env, jcmd, cmd, JNI_ABORT);

    if (rsp_len == 0) return NULL;

    jbyteArray result = (*env)->NewByteArray(env, (jsize)rsp_len);
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)rsp_len, (const jbyte *)rsp_buf);
    return result;
}

/* --- Snapshot --- */

JNIEXPORT jbyteArray JNICALL
Java_com_simrs_Sim_nativeSnapshotSave(JNIEnv *env, jclass cls)
{
    uint32_t size = simrs_snapshot_size();
    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return NULL;

    uint32_t written = simrs_snapshot_save(buf, size);
    if (written == 0) {
        free(buf);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)written);
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)written, (const jbyte *)buf);
    free(buf);
    return result;
}

JNIEXPORT jint JNICALL
Java_com_simrs_Sim_nativeSnapshotSize(JNIEnv *env, jclass cls)
{
    return (jint)simrs_snapshot_size();
}

/* --- State hash --- */

JNIEXPORT jlong JNICALL
Java_com_simrs_Sim_nativeStateHash(JNIEnv *env, jclass cls)
{
    return (jlong)simrs_state_hash();
}
