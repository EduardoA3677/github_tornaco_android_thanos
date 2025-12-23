.class public abstract Llyiahf/vczjk/ru2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    const-class v1, Llyiahf/vczjk/ru2;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/gf4;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ru2;->OooO00o:Ljava/lang/String;

    return-void
.end method

.method public static OooO00o()I
    .locals 3

    sget-object v0, Llyiahf/vczjk/ru2;->OooO00o:Ljava/lang/String;

    :try_start_0
    invoke-static {}, Landroidx/window/extensions/WindowExtensionsProvider;->getWindowExtensions()Landroidx/window/extensions/WindowExtensions;

    move-result-object v1

    invoke-interface {v1}, Landroidx/window/extensions/WindowExtensions;->getVendorApiLevel()I

    move-result v0
    :try_end_0
    .catch Ljava/lang/NoClassDefFoundError; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_0 .. :try_end_0} :catch_0

    return v0

    :catch_0
    sget-object v1, Llyiahf/vczjk/pj0;->OooO00o:Llyiahf/vczjk/lea;

    sget-object v2, Llyiahf/vczjk/lea;->OooOOO0:Llyiahf/vczjk/lea;

    if-ne v1, v2, :cond_0

    const-string v1, "Stub Extension"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_0

    :catch_1
    sget-object v1, Llyiahf/vczjk/pj0;->OooO00o:Llyiahf/vczjk/lea;

    sget-object v2, Llyiahf/vczjk/lea;->OooOOO0:Llyiahf/vczjk/lea;

    if-ne v1, v2, :cond_0

    const-string v1, "Embedding extension version not found"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    :cond_0
    :goto_0
    const/4 v0, 0x0

    return v0
.end method
