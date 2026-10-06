package com.vulnweave;

import com.intellij.credentialStore.CredentialAttributes;
import com.intellij.credentialStore.CredentialAttributesKt;
import com.intellij.ide.passwordSafe.PasswordSafe;
import com.intellij.openapi.project.Project;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

final class SettingsStore {
    private final Project project; private final Path file; private final Map<String,Object> data=new LinkedHashMap<>();
    SettingsStore(Project p){project=p;file=Paths.get(Objects.requireNonNull(p.getBasePath()),".vulnweave","ide-settings.json");load();}
    private void load(){try{if(Files.exists(file))data.putAll(MiniJson.map(MiniJson.parse(Files.readString(file))));}catch(Exception ignored){}}
    synchronized String get(String k){Object v=data.get(k);return v==null?"":String.valueOf(v);} synchronized void put(String k,String v){data.put(k,v);save();}
    private void save(){try{Files.createDirectories(file.getParent());Files.writeString(file,MiniJson.stringify(data),StandardCharsets.UTF_8);}catch(Exception e){throw new RuntimeException(e);}}
    private CredentialAttributes attrs(String key){String service=CredentialAttributesKt.generateServiceName("VulnWeave",key);return new CredentialAttributes(service);}
    void setSecret(String key,String value){PasswordSafe.getInstance().setPassword(attrs(key),value);} String getSecret(String key){return PasswordSafe.getInstance().getPassword(attrs(key));}
}
