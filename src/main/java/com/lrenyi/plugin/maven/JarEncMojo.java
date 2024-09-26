package com.lrenyi.plugin.maven;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipOutputStream;
import lombok.Setter;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.archivers.jar.JarArchiveEntry;
import org.apache.commons.compress.archivers.jar.JarArchiveInputStream;
import org.apache.commons.compress.archivers.jar.JarArchiveOutputStream;
import org.apache.commons.lang3.StringUtils;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

@Setter
@Mojo(name = "encrypt", defaultPhase = LifecyclePhase.PACKAGE)
public class JarEncMojo extends AbstractMojo {
    private static final byte[] ENCRYPT_FLAG = new byte[]{-66, -70, -2, -54};
    private final List<String> encryptFiles = new ArrayList<>();
    private final AESUtil aesUtil = new AESUtil();
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;
    @Parameter(property = "encrypt.sourceDir", required = true, defaultValue = "${project.build.directory}")
    private File sourceDir;
    @Parameter(property = "encrypt.targetDir", required = true, defaultValue = "${project.build.directory}")
    private File targetDir;
    @Parameter(property = "encrypt.sourceJar")
    private String sourceJar;
    @Parameter(property = "encrypt.targetJar")
    private String targetJar;
    @Parameter(property = "encrypt.includes")
    private String[] includes;
    @Parameter(property = "encrypt.excludes")
    private String[] excludes;
    @Parameter(property = "encrypt.deletes")
    private String[] deletes;
    @Parameter(property = "encrypt.aesKey")
    private String aesKey;
    @Parameter(property = "encrypt.aesIv")
    private String aesIv;
    
    @Override
    public void execute() {
        Log log = this.getLog();
        String packaging = this.project.getPackaging();
        if (!"jar".equalsIgnoreCase(packaging)) {
            log.info("skip for jar encrypt, because project packaging not jar. ");
            return;
        }
        if (StringUtils.isEmpty(aesKey) || StringUtils.isEmpty(aesIv)) {
            log.info("skip for jar encrypt, because aesKey is empty or aesIv is empty");
            return;
        }
        log.info("jar encrypt sourceDir: " + sourceDir);
        log.info("jar encrypt targetDir: " + targetDir);
        log.info("jar encrypt sourceJar: " + sourceJar);
        log.info("jar encrypt targetJar: " + targetJar);
        log.info("jar encrypt includes: " + String.join(",", includes));
        log.info("jar encrypt excludes: " + String.join(",", excludes));
        log.info("jar encrypt deletes: " + String.join(",", deletes));
        if (!sourceDir.getAbsolutePath().equalsIgnoreCase(targetDir.getAbsolutePath())) {
            cycleDealFile(targetDir);
        }
        if (!StringUtils.isEmpty(sourceJar) && !StringUtils.isEmpty(targetJar)) {
            File src = new File(this.sourceDir, this.sourceJar);
            File dest = new File(this.targetDir, this.targetJar);
            encSigneJarFile(dest, src);
        } else {
            dealSingDir(sourceDir, targetDir);
        }
        log.info("加密class文件数量：" + encryptFiles.size());
        if (log.isDebugEnabled()) {
            for (String encryptFile : encryptFiles) {
                log.debug("class文件已被加密：" + encryptFile);
            }
        }
    }
    
    private void cycleDealFile(File targetDir) {
        if (!targetDir.exists()) {
            return;
        }
        if (targetDir.isDirectory()) {
            File[] files = targetDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    cycleDealFile(file);
                }
            }
        }
        try {
            Files.delete(targetDir.toPath());
        } catch (IOException e) {
            getLog().error(e);
        }
    }
    
    private void dealSingDir(File sourceDir, File targetDir) {
        if (!targetDir.exists() && !targetDir.mkdirs()) {
            getLog().error("创建目录失败，跳过加密，目标目录为：" + targetDir.getAbsolutePath());
            return;
        }
        File[] files = sourceDir.listFiles();
        if (files == null) {
            getLog().warn("加密目录下没有需要加密的文件，跳过加密编译。");
            return;
        }
        List<File> fileList = Arrays.asList(files);
        fileList.parallelStream().forEach(file -> {
            String name = file.getName();
            File destDir = new File(targetDir, name);
            if (file.isDirectory()) {
                dealSingDir(new File(sourceDir, name), new File(targetDir, name));
                return;
            }
            if (name.endsWith(".jar")) {
                File src = new File(sourceDir, name);
                File dest = new File(targetDir, name);
                encSigneJarFile(dest, src);
            } else if (name.endsWith(".class")) {
                byte[] classBytes;
                try {
                    classBytes = Files.readAllBytes(file.toPath());
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    encryption(classBytes, outputStream);
                } catch (Exception e) {
                    getLog().error("读取或者加密class文件内容异常：" + file.getAbsolutePath());
                }
            } else {
                try {
                    Files.copy(file.toPath(), destDir.toPath());
                } catch (IOException e) {
                    getLog().error("复制文件异常：" + file.getAbsolutePath());
                }
            }
        });
    }
    
    private void encSigneJarFile(File dest, File src) {
        getLog().debug("encryption jar: " + dest + " for jar: " + src);
        // @formatter:off
        try (FileInputStream fis = new FileInputStream(src);
                FileOutputStream fos = new FileOutputStream(dest);
                JarArchiveInputStream zis = new JarArchiveInputStream(
                fis); JarArchiveOutputStream zos = new JarArchiveOutputStream(fos)) {
            JarArchiveEntry entry;
            JarArchiveEntry jarArchiveEntry;
            while ((entry = zis.getNextJarEntry()) != null) {
                String entryName = entry.getName();
                if (deletesDeal(entryName, deletes)) {
                    continue;
                }
                if (entry.isDirectory()) {
                    jarArchiveEntry = new JarArchiveEntry(entryName);
                    jarArchiveEntry.setTime(entry.getTime());
                    zos.putArchiveEntry(jarArchiveEntry);
                } else if (entryName.toLowerCase().endsWith(".class")) {
                    jarArchiveEntry = new JarArchiveEntry(entryName);
                    jarArchiveEntry.setTime(entry.getTime());
                    zos.putArchiveEntry(jarArchiveEntry);
                    ByteArrayOutputStream classBytes = new ByteArrayOutputStream();
                    fetchByteData(zis, classBytes);
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    if (includes != null) {
                        boolean match = matchRule(includes, entryName);
                        if (match) {
                            encryptFiles.add(entryName);
                            encryption(classBytes.toByteArray(), outputStream);
                        } else {
                            outputStream.write(classBytes.toByteArray());
                        }
                    } else if (excludes != null) {
                        boolean match = matchRule(excludes, entryName);
                        if (!match) {
                            encryptFiles.add(entryName);
                            encryption(classBytes.toByteArray(), outputStream);
                        } else {
                            outputStream.write(classBytes.toByteArray());
                        }
                    } else {
                        encryptFiles.add(entryName);
                        encryption(classBytes.toByteArray(), outputStream);
                    }
                    zos.write(outputStream.toByteArray());
                    zos.flush();
                } else {
                    jarArchiveEntry = new JarArchiveEntry(entryName);
                    jarArchiveEntry.setTime(entry.getTime());
                    jarArchiveEntry.setMethod(ZipOutputStream.STORED); // 设置为 STORED 方式
                    
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    fetchByteData(zis, outputStream);
                    byte[] data = outputStream.toByteArray();
                    jarArchiveEntry.setSize(data.length); // 使用实际数据大小
                    jarArchiveEntry.setCrc(CRC32Util.calculateCRC32(data)); // 计算 CRC 值
                    zos.putArchiveEntry(jarArchiveEntry); // 在写入之前设置大小和 CRC
                    zos.write(data);
                    zos.flush();
                }
                zos.closeArchiveEntry();
            }
        } catch (Throwable cause) {
            getLog().error(cause);
        }
    }

    public static class CRC32Util {
        public static long calculateCRC32(byte[] bytes) {
            CRC32 crc = new CRC32();
            crc.update(bytes, 0, bytes.length); // 更新 CRC32 的值
            return crc.getValue();
        }
    }
    
    private boolean matchRule(String[] rules, String entryName) {
        boolean match = false;
        for (String rule : rules) {
            String lowerCase = rule.toLowerCase();
            String once = lowerCase.replace(".", "/");
            String two = once.replace(".", "\\");
            if (entryName.toLowerCase().contains(once) || entryName.toLowerCase().contains(two)) {
                match = true;
                break;
            }
        }
        return match;
    }
    
    private void encryption(byte[] classBytes, ByteArrayOutputStream outputStream) throws Exception {
        byte[] key = Hex.decodeHex(aesKey);
        byte[] iv = Hex.decodeHex(aesIv);
        byte[] encryption = aesUtil.encryption(key, iv, classBytes);
        outputStream.write(ENCRYPT_FLAG);
        outputStream.write(encryption);
    }
    
    private void fetchByteData(JarArchiveInputStream zis, ByteArrayOutputStream outputStream) throws IOException {
        int length;
        for (byte[] buffer = new byte[4096]; (length = zis.read(buffer)) != -1; ) {
            outputStream.write(buffer, 0, length);
        }
    }
    
    private boolean deletesDeal(String entryName, String[] deletes) {
        if (deletes == null) {
            return false;
        }
        for (String delete : deletes) {
            boolean match = entryName.startsWith(delete);
            if (match) {
                return true;
            }
        }
        return false;
    }
}
