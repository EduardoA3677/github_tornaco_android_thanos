.class public abstract Llyiahf/vczjk/zw6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/wd;

.field public static final OooO0O0:Llyiahf/vczjk/rp3;

.field public static final OooO0OO:Llyiahf/vczjk/wp3;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    const/4 v0, 0x0

    const/16 v1, 0xc

    const-string v2, "java.vm.name"

    invoke-static {v2}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v3, 0x0

    const-string v4, "RoboVM"

    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_1

    const-string v4, "Dalvik"

    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_0

    sput-object v3, Llyiahf/vczjk/zw6;->OooO00o:Llyiahf/vczjk/wd;

    new-instance v0, Llyiahf/vczjk/xm7;

    const/4 v2, 0x1

    invoke-direct {v0, v2}, Llyiahf/vczjk/xm7;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/zw6;->OooO0O0:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/zj0;

    invoke-direct {v0, v1}, Llyiahf/vczjk/wp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/zw6;->OooO0OO:Llyiahf/vczjk/wp3;

    return-void

    :cond_0
    new-instance v2, Llyiahf/vczjk/wd;

    invoke-direct {v2, v0}, Llyiahf/vczjk/wd;-><init>(I)V

    sput-object v2, Llyiahf/vczjk/zw6;->OooO00o:Llyiahf/vczjk/wd;

    new-instance v2, Llyiahf/vczjk/xm7;

    invoke-direct {v2, v0}, Llyiahf/vczjk/xm7;-><init>(I)V

    sput-object v2, Llyiahf/vczjk/zw6;->OooO0O0:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/zj0;

    invoke-direct {v0, v1}, Llyiahf/vczjk/wp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/zw6;->OooO0OO:Llyiahf/vczjk/wp3;

    return-void

    :cond_1
    sput-object v3, Llyiahf/vczjk/zw6;->OooO00o:Llyiahf/vczjk/wd;

    new-instance v0, Llyiahf/vczjk/rp3;

    const/16 v2, 0x16

    invoke-direct {v0, v2}, Llyiahf/vczjk/rp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/zw6;->OooO0O0:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/wp3;

    invoke-direct {v0, v1}, Llyiahf/vczjk/wp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/zw6;->OooO0OO:Llyiahf/vczjk/wp3;

    return-void
.end method
