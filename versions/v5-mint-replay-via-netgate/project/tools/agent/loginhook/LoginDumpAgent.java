package loginhook;

import java.io.ByteArrayInputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarFile;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.LoaderClassPath;
import javassist.Modifier;

// Hooks the obfuscated packet buffer (rev 238: xi.cc/db/ds; rev 239+: xm.co/dd/dn).
public final class LoginDumpAgent {

    private static final Set<String> TRANSFORMED = ConcurrentHashMap.newKeySet();

    private LoginDumpAgent() {
    }

    public static void premain(String options, Instrumentation inst) {
        log("[LOGIN-DUMP] premain start");
        arm(options, inst);
    }

    public static void agentmain(String options, Instrumentation inst) {
        arm(options, inst);
    }

    private static void log(String msg) {
        try {
            System.out.println(msg);
            java.nio.file.Files.write(
                    java.nio.file.Paths.get(System.getProperty("user.home"), "login_dump_agent.log"),
                    (msg + System.lineSeparator()).getBytes(),
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
        }
    }

    private static void arm(String options, Instrumentation inst) {
        try {
            inst.addTransformer(new BufferTransformer(), true);
            inst.addTransformer(new SocketTransformer(), true);
            if (options != null && !options.isEmpty()) {
                inst.appendToBootstrapClassLoaderSearch(new JarFile(options));
            }
            log("[LOGIN-DUMP] agent armed; hooks xi/xm buffers + SocketOutputStream login block.");
        } catch (Throwable t) {
            log("[LOGIN-DUMP] agentmain error: " + t);
            t.printStackTrace();
        }
    }

    private static boolean isLegacyBuffer(CtClass cc) {
        try {
            CtClass strType = cc.getClassPool().get("java.lang.String");
            CtClass bigInteger = cc.getClassPool().get("java.math.BigInteger");
            cc.getDeclaredMethod("cc", new CtClass[]{strType, CtClass.intType});
            cc.getDeclaredMethod("db", new CtClass[]{bigInteger, bigInteger, CtClass.byteType});
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean isModernBuffer(CtClass cc) {
        if (!"xm".equals(cc.getName())) {
            return false;
        }
        try {
            CtClass strType = cc.getClassPool().get("java.lang.String");
            CtClass intArray = cc.getClassPool().get("[I");
            cc.getDeclaredMethod("co", new CtClass[]{strType, CtClass.intType});
            cc.getDeclaredMethod("dn", new CtClass[]{intArray, CtClass.intType, CtClass.intType, CtClass.byteType});
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static void hookStringWrite(CtClass cc, String method, String logLabel) throws Exception {
        CtClass strType = cc.getClassPool().get("java.lang.String");
        CtMethod m = cc.getDeclaredMethod(method, new CtClass[]{strType, CtClass.intType});
        m.insertBefore("{ loginhook.LoginDumpHook.dumpStr($1); }");
        log("[LOGIN-DUMP] instrumented " + cc.getName() + "." + method + " (" + logLabel + ")");
    }

    // Live rev 239+ uses xm.cc(CharSequence, int) for login strings (pk, gf, username).
    private static void hookCharSequenceWrite(CtClass cc, String method, String logLabel) throws Exception {
        CtClass csType = cc.getClassPool().get("java.lang.CharSequence");
        CtMethod m = cc.getDeclaredMethod(method, new CtClass[]{csType, CtClass.intType});
        m.insertBefore("{ loginhook.LoginDumpHook.dumpStr($1 == null ? null : $1.toString()); }");
        log("[LOGIN-DUMP] instrumented " + cc.getName() + "." + method + " (CharSequence, " + logLabel + ")");
    }

    private static void hookLegacy(CtClass cc) throws Exception {
        hookStringWrite(cc, "cc", "string writes");

        CtClass bigInteger = cc.getClassPool().get("java.math.BigInteger");
        CtMethod db = cc.getDeclaredMethod("db",
                new CtClass[]{bigInteger, bigInteger, CtClass.byteType});
        if (!Modifier.isStatic(db.getModifiers())) {
            db.insertBefore("{ loginhook.LoginDumpHook.dumpRsa($0); }");
            log("[LOGIN-DUMP] instrumented " + cc.getName() + ".db (RSA plaintext)");
        }

        CtClass intArray = cc.getClassPool().get("[I");
        CtMethod ds = cc.getDeclaredMethod("ds",
                new CtClass[]{intArray, CtClass.intType, CtClass.intType, CtClass.intType});
        ds.insertBefore("loginhook.LoginDumpHook.dump($0, $3);");
        log("[LOGIN-DUMP] instrumented " + cc.getName() + ".ds (login frame)");
    }

    private static void hookModern(CtClass cc) throws Exception {
        hookStringWrite(cc, "co", "string writes");
        try {
            hookStringWrite(cc, "ce", "string writes");
        } catch (Throwable ignored) {
        }
        try {
            hookCharSequenceWrite(cc, "cc", "login string writes");
        } catch (Throwable ignored) {
        }

        CtClass bigInteger = cc.getClassPool().get("java.math.BigInteger");
        for (String rsaMethod : new String[]{"dd", "jo"}) {
            try {
                CtMethod rsa;
                if ("dd".equals(rsaMethod)) {
                    rsa = cc.getDeclaredMethod("dd",
                            new CtClass[]{bigInteger, bigInteger, CtClass.intType});
                } else {
                    rsa = cc.getDeclaredMethod("jo",
                            new CtClass[]{bigInteger, bigInteger});
                }
                if (!Modifier.isStatic(rsa.getModifiers())) {
                    rsa.insertBefore("{ loginhook.LoginDumpHook.dumpRsa($0); }");
                    log("[LOGIN-DUMP] instrumented " + cc.getName() + "." + rsaMethod + " (RSA plaintext)");
                }
            } catch (Throwable ignored) {
            }
        }

        CtClass intArray = cc.getClassPool().get("[I");
        for (String xteaMethod : new String[]{"dn", "dj"}) {
            try {
                CtMethod xtea = cc.getDeclaredMethod(xteaMethod,
                        new CtClass[]{intArray, CtClass.intType, CtClass.intType, CtClass.byteType});
                xtea.insertBefore("loginhook.LoginDumpHook.dump($0, $3);");
                log("[LOGIN-DUMP] instrumented " + cc.getName() + "." + xteaMethod + " (login frame)");
            } catch (Throwable ignored) {
            }
        }
    }

    private static final class BufferTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer) {
            if (className == null || className.indexOf('/') >= 0 || TRANSFORMED.contains(className)) {
                return null;
            }
            try {
                ClassPool cp = new ClassPool(true);
                if (loader != null) {
                    cp.appendClassPath(new LoaderClassPath(loader));
                }
                CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));

                boolean legacy = isLegacyBuffer(cc);
                boolean modern = isModernBuffer(cc);
                if (!legacy && !modern) {
                    cc.detach();
                    return null;
                }

                log("[LOGIN-DUMP] matched buffer class: " + className
                        + (legacy ? " (legacy)" : "") + (modern ? " (modern)" : ""));
                if (legacy) {
                    hookLegacy(cc);
                }
                if (modern) {
                    hookModern(cc);
                }

                byte[] out = cc.toBytecode();
                cc.detach();
                TRANSFORMED.add(className);
                return out;
            } catch (Throwable t) {
                log("[LOGIN-DUMP] transform error in " + className + ": " + t);
                return null;
            }
        }
    }

    private static final Set<String> SOCKET_TRANSFORMED = ConcurrentHashMap.newKeySet();

    private static void hookSocketOutputStream(CtClass cc) throws Exception {
        CtClass byteArray = cc.getClassPool().get("byte[]");
        try {
            CtMethod write3 = cc.getDeclaredMethod("write",
                    new CtClass[]{byteArray, CtClass.intType, CtClass.intType});
            write3.insertBefore(
                    "if (loginhook.LoginDumpHook.shouldBlockLoginWrite($1, $2, $3)) { return; }");
            log("[LOGIN-DUMP] instrumented java.net.SocketOutputStream.write(byte[],int,int)");
        } catch (Throwable t) {
            log("[LOGIN-DUMP] SocketOutputStream.write(b,off,len) hook failed: " + t);
        }
        try {
            CtMethod write1 = cc.getDeclaredMethod("write", new CtClass[]{byteArray});
            write1.insertBefore(
                    "if ($1 != null && loginhook.LoginDumpHook.shouldBlockLoginWrite($1, 0, $1.length)) { return; }");
            log("[LOGIN-DUMP] instrumented java.net.SocketOutputStream.write(byte[])");
        } catch (Throwable ignored) {
        }
    }

    private static final class SocketTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer) {
            if (!"java/net/SocketOutputStream".equals(className) || SOCKET_TRANSFORMED.contains(className)) {
                return null;
            }
            try {
                ClassPool cp = new ClassPool(true);
                CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));
                hookSocketOutputStream(cc);
                byte[] out = cc.toBytecode();
                cc.detach();
                SOCKET_TRANSFORMED.add(className);
                return out;
            } catch (Throwable t) {
                log("[LOGIN-DUMP] SocketOutputStream transform error: " + t);
                return null;
            }
        }
    }
}
