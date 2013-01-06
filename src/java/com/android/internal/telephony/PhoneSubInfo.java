/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.internal.telephony;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.telephony.PhoneNumberUtils;
import android.telephony.Rlog;

import com.android.internal.telephony.uicc.IsimRecords;

public class PhoneSubInfo extends IPhoneSubInfo.Stub {
    static final String LOG_TAG = "PhoneSubInfo";
    private static final boolean DBG = true;
    private static final boolean VDBG = false; // STOPSHIP if true
    private static final boolean PFF_DBG = true;

    private Phone mPhone;
    private Context mContext;
    private static final String READ_PHONE_STATE =
        android.Manifest.permission.READ_PHONE_STATE;
    // TODO: change getCompleteVoiceMailNumber() to require READ_PRIVILEGED_PHONE_STATE
    private static final String CALL_PRIVILEGED =
        android.Manifest.permission.CALL_PRIVILEGED;
    private static final String READ_PRIVILEGED_PHONE_STATE =
        android.Manifest.permission.READ_PRIVILEGED_PHONE_STATE;

    public PhoneSubInfo(Phone phone) {
        mPhone = phone;
        mContext = phone.getContext();
    }

    public void dispose() {
    }

    @Override
    protected void finalize() {
        try {
            super.finalize();
        } catch (Throwable throwable) {
            loge("Error while finalizing:", throwable);
        }
        if (DBG) log("PhoneSubInfo finalized");
    }

    /**
     * Retrieves the unique device ID, e.g., IMEI for GSM phones and MEID for CDMA phones.
     */
    @Override
    public String getDeviceId() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            return mPhone.getDeviceId();
        case PackageManager.PERMISSION_SPOOFED:
            if (PFF_DBG) log("VM: PhoneSubInfo.getDeviceId: spoofed");
            return createNumericSpoof(mPhone.getDeviceId().length(), 6, 3, null);
        default:
            return "";
        }
    }

    /**
     * Retrieves the software version number for the device, e.g., IMEI/SV
     * for GSM phones.
     */
    @Override
    public String getDeviceSvn() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            return mPhone.getDeviceSvn();
        case PackageManager.PERMISSION_SPOOFED:
            if (PFF_DBG) log("VM: PhoneSubInfo.getDeviceSvn: spoofed");
            return createNumericSpoof(mPhone.getDeviceSvn().length(), 5, 2, null);
        default:
            return "";
        }
    }

    /**
     * Retrieves the unique subscriber ID, e.g., IMSI for GSM phones.
     */
    @Override
    public String getSubscriberId() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            return mPhone.getSubscriberId();
        case PackageManager.PERMISSION_SPOOFED:
            if (PFF_DBG) log("VM: PhoneSubInfo.getSubscriberId: spoofed");
            return createNumericSpoof(mPhone.getSubscriberId().length(), 0, 3, null);
        default:
            return "";
        }
    }

    /**
     * Retrieves the Group Identifier Level1 for GSM phones.
     */
    public String getGroupIdLevel1() {
        mContext.enforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        return mPhone.getGroupIdLevel1();
    }

    /**
     * Retrieves the serial number of the ICC, if applicable.
     */
    @Override
    public String getIccSerialNumber() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            return mPhone.getIccSerialNumber();
        case PackageManager.PERMISSION_SPOOFED:
            String real = mPhone.getIccSerialNumber();
            if (PFF_DBG) log("VM: PhoneSubInfo.getIccSerialNumber: spoofed");
            return createNumericSpoof(real.length(), 2, 5, null);
        default:
            return "";
        }
    }

    /**
     * Retrieves the phone number string for line 1.
     */
    @Override
    public String getLine1Number() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            return mPhone.getLine1Number();
        case PackageManager.PERMISSION_SPOOFED:
            byte[] data = getMD5Sum();
            StringBuilder spoof = new StringBuilder("+11");
            for(int i = 0; i < 4; i++) {
                spoof.append(0x0f & data[i+4]);
                spoof.append(data[i] >> 8);
            }
        	if (PFF_DBG) log("VM: PhoneSubInfo.getLine1Number: spoofed");
            return spoof.toString();
         default:
            return "";
        }
    }

    /**
     * Retrieves the alpha identifier for line 1.
     */
    @Override
    public String getLine1AlphaTag() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            return (String) mPhone.getLine1AlphaTag();
        case PackageManager.PERMISSION_SPOOFED:
            if (PFF_DBG) log("VM: PhoneSubInfo.getLine1AlphaTag: spoofed");
            return "Line1";
        default:
            return "";
        }
    }

    /**
     * Retrieves the MSISDN string.
     */
    @Override
    public String getMsisdn() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            mContext.enforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
            return mPhone.getMsisdn();
        case PackageManager.PERMISSION_SPOOFED:
            byte[] data = getMD5Sum();
            StringBuilder spoof = new StringBuilder("+11");
            for(int i = 0; i < 4; i++) {
                spoof.append(0x0f & data[i+4]);
                spoof.append(data[i] >> 8);
            }
            if (PFF_DBG) log("VM: PhoneSubInfo.getMsisdn: spoofed");
            return spoof.toString();
        default:
            return "";
        }
    }

    /**
     * Retrieves the voice mail number.
     */
    @Override
    public String getVoiceMailNumber() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            mContext.enforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
            String number = PhoneNumberUtils.extractNetworkPortion(mPhone.getVoiceMailNumber());
	    if (VDBG) log("VM: PhoneSubInfo.getVoiceMailNUmber: " + number);
            return number;
        case PackageManager.PERMISSION_SPOOFED:
            byte[] data = getMD5Sum();
            StringBuilder spoof = new StringBuilder("+11");
            for(int i = 0; i < 4; i++) {
                spoof.append(0x0f & data[i]);
                spoof.append(data[i] >> 8);
            }
            if (PFF_DBG) log("VM: PhoneSubInfo.getVoiceMailNumber: spoofed");
            return spoof.toString();
        default:
            return "";
        }        
    }

    /**
     * Retrieves the complete voice mail number.
     *
     * @hide
     */
    @Override
    public String getCompleteVoiceMailNumber() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            mContext.enforceCallingOrSelfPermission(CALL_PRIVILEGED, "Requires CALL_PRIVILEGED");
            String number = mPhone.getVoiceMailNumber();
            if (VDBG) log("VM: PhoneSubInfo.getCompleteVoiceMailNUmber: " + number);
            return number;
        case PackageManager.PERMISSION_SPOOFED:
            byte[] data = getMD5Sum();
            StringBuilder spoof = new StringBuilder("+11");
            for(int i = 0; i < 4; i++) {
                spoof.append(0x0f & data[i]);
                spoof.append(data[i] >> 8);
            }
            if (PFF_DBG) log("VM: PhoneSubInfo.getCompleteVoiceMailNumber: spoofed");
            return spoof.toString();
        default:
            return "";
        }        
    }

    /**
     * Retrieves the alpha identifier associated with the voice mail number.
     */
    @Override
    public String getVoiceMailAlphaTag() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
	    mContext.enforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
	    return mPhone.getVoiceMailAlphaTag();
        case PackageManager.PERMISSION_SPOOFED:
            if (PFF_DBG) log("VM: PhoneSubInfo.getVoiceMailAlphaTag: spoofed");
            return "Voicemail";
        default:
            return "";
        }
    }

    /**
     * Returns the IMS private user identity (IMPI) that was loaded from the ISIM.
     * @return the IMPI, or null if not present or not loaded
     */
    @Override
    public String getIsimImpi() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            mContext.enforceCallingOrSelfPermission(READ_PRIVILEGED_PHONE_STATE,
                    "Requires READ_PRIVILEGED_PHONE_STATE");
            IsimRecords isim = mPhone.getIsimRecords();
            if (isim != null) {
                return isim.getIsimImpi();
            } else {
                return null;
            }
        case PackageManager.PERMISSION_SPOOFED:
            if (PFF_DBG) log("VM: PhoneSubInfo.getIsimImpi: spoofed");
            // Guhl: TBD change this to spoofing!
            return null; 
        default:
            return null;
        }
    }

    /**
     * Returns the IMS home network domain name that was loaded from the ISIM.
     * @return the IMS domain name, or null if not present or not loaded
     */
    @Override
    public String getIsimDomain() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            mContext.enforceCallingOrSelfPermission(READ_PRIVILEGED_PHONE_STATE,
                    "Requires READ_PRIVILEGED_PHONE_STATE");
            IsimRecords isim = mPhone.getIsimRecords();
            if (isim != null) {
                return isim.getIsimDomain();
            } else {
                return null;
            }
        case PackageManager.PERMISSION_SPOOFED:
            if (PFF_DBG) log("VM: PhoneSubInfo.getIsimDomain: spoofed");
            // Guhl: TBD change this to spoofing!
            return null; 
        default:
            return null;
        }
    }

    /**
     * Returns the IMS public user identities (IMPU) that were loaded from the ISIM.
     * @return an array of IMPU strings, with one IMPU per string, or null if
     *      not present or not loaded
     */
    @Override
    public String[] getIsimImpu() {
        int res = mContext.pffEnforceCallingOrSelfPermission(READ_PHONE_STATE, "Requires READ_PHONE_STATE");
        switch (res) {
        case PackageManager.PERMISSION_GRANTED:
            mContext.enforceCallingOrSelfPermission(READ_PRIVILEGED_PHONE_STATE,
                    "Requires READ_PRIVILEGED_PHONE_STATE");
            IsimRecords isim = mPhone.getIsimRecords();
            if (isim != null) {
                return isim.getIsimImpu();
            } else {
                return null;
            }
        case PackageManager.PERMISSION_SPOOFED:
            if (PFF_DBG) log("VM: PhoneSubInfo.getIsimImpu: spoofed");
            // Guhl: TBD change this to spoofing!
            return null; 
        default:
            return null;
        }
    }

    private void log(String s) {
        Rlog.d(LOG_TAG, s);
    }

    private void loge(String s, Throwable e) {
        Rlog.e(LOG_TAG, s, e);
    }

    @Override
    protected void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
        if (mContext.checkCallingOrSelfPermission(android.Manifest.permission.DUMP)
                != PackageManager.PERMISSION_GRANTED) {
            pw.println("Permission Denial: can't dump PhoneSubInfo from from pid="
                    + Binder.getCallingPid()
                    + ", uid=" + Binder.getCallingUid());
            return;
        }

        pw.println("Phone Subscriber Info:");
        pw.println("  Phone Type = " + mPhone.getPhoneName());
        pw.println("  Device ID = " + mPhone.getDeviceId());
    }

    private String createNumericSpoof(final int len, int begin, int step, String prefix) {
        byte[] data = getMD5Sum();
        StringBuilder spoof = new StringBuilder();
        if (prefix != null) {
            spoof.append(prefix);
        }
        int j = begin;
        while (spoof.length() < len) {
            spoof.append(0xff & data[j]);
            j += step;
            if (j >= data.length) {
                j -= data.length;
            }
        }
        spoof.setLength(len);
        return spoof.toString();
    }

    private byte[] getMD5Sum() {
        byte[] data = null;
        try {
            int uid = Binder.getCallingUid();
            String name = mContext.getPackageManager().getNameForUid(uid);
            MessageDigest md = MessageDigest.getInstance("MD5");
            data = md.digest(name.getBytes());
        } catch (NoSuchAlgorithmException e) {
        }
        return data;
    }
    
}
