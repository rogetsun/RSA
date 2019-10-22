package com.uv.rsa;

import picocli.CommandLine;

import java.io.File;
import java.util.Arrays;

/**
 * @author uvsun 2019-06-15 13:46
 * 区别于CmdArgs的参数格式
 */
@CommandLine.Command(name = "java -jar rsa.jar", footer = "\n山西盛华电子系统工程有限公司 Copyright(c) 2019 ",
        description = "encrypt or decrypt FILE")
public class CmdParam {

    @CommandLine.Option(names = {"-e", "--encrypt"}, description = "加密模式")
    private boolean encrypt;

    @CommandLine.Option(names = {"-d", "--decrypt"}, description = "解密模式, 不指定加密或解密时,默认解密模式!")
    private boolean decrypt;

    @CommandLine.Option(names = {"--help"}, description = "帮助")
    private boolean help;

    @CommandLine.Parameters(description = {"需要加密或解密的源文件[SourceFile]", "加密或解密后的结果文件[DistFile]"}, paramLabel = "SourceFile [DistFile]")
    private String[] files;

    @CommandLine.Option(names = {"-c", "--create"},
            description = "创建新的密钥对,必须指定密钥对名字,比如test,则生成的密钥对为:test-public.key,test-private.key", paramLabel = "KeyPairName")
    private String keyName;

    @CommandLine.Option(names = {"-k", "--key"}, description = "使用指定密钥加密或解密,如果不指定,则使用默认内置密钥!", paramLabel = "KeyFile")
    private File keyFile;

    @Override
    public String toString() {
        return "CmdParam{" +
                "encrypt=" + encrypt +
                ", decrypt=" + decrypt +
                ", help=" + help +
                ", files=" + Arrays.toString(files) +
                ", keyName='" + keyName + '\'' +
                ", keyFile=" + keyFile +
                '}';
    }

    public String getKeyName() {
        return keyName;
    }

    public void setKeyName(String keyName) {
        this.keyName = keyName;
    }

    public File getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(File keyFile) {
        this.keyFile = keyFile;
    }

    public boolean isEncrypt() {
        return encrypt;
    }

    public void setEncrypt(boolean encrypt) {
        this.encrypt = encrypt;
    }

    public boolean isDecrypt() {
        return !encrypt;
    }

    public void setDecrypt(boolean decrypt) {
        this.decrypt = decrypt;
    }

    public boolean isHelp() {
        return help;
    }

    public void setHelp(boolean help) {
        this.help = help;
    }

    public String[] getFiles() {
        return files;
    }

    public void setFiles(String[] files) {
        this.files = files;
    }
}
