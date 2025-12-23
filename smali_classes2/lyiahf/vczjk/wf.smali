.class public abstract Llyiahf/vczjk/wf;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/i88;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/uf;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/uf;-><init>(I)V

    invoke-static {v0}, Llyiahf/vczjk/fu6;->OooOOo(Ljava/util/concurrent/Callable;)Llyiahf/vczjk/i88;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/wf;->OooO00o:Llyiahf/vczjk/i88;

    return-void
.end method

.method public static OooO00o()Llyiahf/vczjk/i88;
    .locals 2

    sget-object v0, Llyiahf/vczjk/wf;->OooO00o:Llyiahf/vczjk/i88;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/NullPointerException;

    const-string v1, "scheduler == null"

    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
