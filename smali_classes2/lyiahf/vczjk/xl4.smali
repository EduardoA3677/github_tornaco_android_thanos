.class public abstract Llyiahf/vczjk/xl4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static OooO00o:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v1, "ThanoxApp"

    invoke-direct {v0, v1}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    return-void
.end method

.method public static final OooO00o(Ljava/lang/String;)V
    .locals 3

    new-instance v0, Ljava/lang/Throwable;

    invoke-direct {v0}, Ljava/lang/Throwable;-><init>()V

    invoke-static {v0}, Llyiahf/vczjk/cp7;->Oooo0o(Ljava/lang/Throwable;)Ljava/lang/String;

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v0

    const-string v1, "39M5DC32-B17D-4370-AB98-A9L809256685"

    invoke-virtual {v0, v1}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-static {v0}, Lcom/tencent/mmkv/MMKV;->OooO(Ljava/lang/String;)Lcom/tencent/mmkv/MMKV;

    move-result-object v0

    invoke-static {}, Llyiahf/vczjk/m6a;->o0000oO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p0}, Lcom/tencent/mmkv/MMKV;->OooO0o(Ljava/lang/String;Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/m6a;->o0000oo()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p0}, Lcom/tencent/mmkv/MMKV;->OooO0o(Ljava/lang/String;Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/m6a;->o0000oO()Ljava/lang/String;

    invoke-static {}, Llyiahf/vczjk/m6a;->o0000oo()Ljava/lang/String;

    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    const/4 v1, 0x0

    if-eqz p0, :cond_0

    new-instance v2, Llyiahf/vczjk/vl4;

    invoke-direct {v2, p0, v1}, Llyiahf/vczjk/vl4;-><init>(Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v2}, Llyiahf/vczjk/os9;->Oooo(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/v74;

    return-void

    :cond_0
    new-instance p0, Llyiahf/vczjk/wl4;

    const/4 v2, 0x2

    invoke-direct {p0, v2, v1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-static {v0, p0}, Llyiahf/vczjk/os9;->Oooo(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/v74;

    return-void

    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string v0, "Required value was null."

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method
