.class public final Llyiahf/vczjk/eha;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/pp3;

.field public final OooO0O0:Ljava/util/LinkedHashMap;

.field public final OooO0OO:Ljava/util/LinkedHashSet;

.field public volatile OooO0Oo:Z


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/pp3;

    const/16 v1, 0x19

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/eha;->OooO00o:Llyiahf/vczjk/pp3;

    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/eha;->OooO0O0:Ljava/util/LinkedHashMap;

    new-instance v0, Ljava/util/LinkedHashSet;

    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/eha;->OooO0OO:Ljava/util/LinkedHashSet;

    return-void
.end method

.method public static OooO00o(Ljava/lang/AutoCloseable;)V
    .locals 1

    if-eqz p0, :cond_0

    :try_start_0
    invoke-static {p0}, Llyiahf/vczjk/u81;->OooOOoo(Ljava/lang/AutoCloseable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    new-instance v0, Ljava/lang/RuntimeException;

    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v0

    :cond_0
    return-void
.end method
