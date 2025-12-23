.class public final Llyiahf/vczjk/dj8;
.super Llyiahf/vczjk/vo1;
.source "SourceFile"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "StaticFieldLeak"
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Llyiahf/vczjk/vo1;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0007\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Llyiahf/vczjk/dj8;",
        "Llyiahf/vczjk/vo1;",
        "Llyiahf/vczjk/mi8;",
        "app_prcRelease"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final OooO:Llyiahf/vczjk/eh7;

.field public final OooO0oo:Llyiahf/vczjk/jl8;

.field public final OooOO0:Llyiahf/vczjk/jl8;

.field public final OooOO0O:Llyiahf/vczjk/eh7;

.field public final OooOO0o:Llyiahf/vczjk/jl8;

.field public final OooOOO:Llyiahf/vczjk/sc9;

.field public final OooOOO0:Llyiahf/vczjk/eh7;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 4

    new-instance v0, Llyiahf/vczjk/p35;

    const/16 v1, 0x18

    invoke-direct {v0, v1}, Llyiahf/vczjk/p35;-><init>(I)V

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/vo1;-><init>(Landroid/content/Context;Llyiahf/vczjk/le3;)V

    const/4 v0, 0x0

    const/4 v1, 0x7

    invoke-static {v1, v0}, Llyiahf/vczjk/zsa;->OooOO0o(ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/dj8;->OooO0oo:Llyiahf/vczjk/jl8;

    new-instance v3, Llyiahf/vczjk/eh7;

    invoke-direct {v3, v2}, Llyiahf/vczjk/eh7;-><init>(Llyiahf/vczjk/os5;)V

    iput-object v3, p0, Llyiahf/vczjk/dj8;->OooO:Llyiahf/vczjk/eh7;

    invoke-static {v1, v0}, Llyiahf/vczjk/zsa;->OooOO0o(ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/dj8;->OooOO0:Llyiahf/vczjk/jl8;

    new-instance v3, Llyiahf/vczjk/eh7;

    invoke-direct {v3, v2}, Llyiahf/vczjk/eh7;-><init>(Llyiahf/vczjk/os5;)V

    iput-object v3, p0, Llyiahf/vczjk/dj8;->OooOO0O:Llyiahf/vczjk/eh7;

    invoke-static {v1, v0}, Llyiahf/vczjk/zsa;->OooOO0o(ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/dj8;->OooOO0o:Llyiahf/vczjk/jl8;

    new-instance v1, Llyiahf/vczjk/eh7;

    invoke-direct {v1, v0}, Llyiahf/vczjk/eh7;-><init>(Llyiahf/vczjk/os5;)V

    iput-object v1, p0, Llyiahf/vczjk/dj8;->OooOOO0:Llyiahf/vczjk/eh7;

    new-instance v0, Llyiahf/vczjk/kt;

    const/16 v1, 0x15

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/dj8;->OooOOO:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OooO()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/di8;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/di8;-><init>(Llyiahf/vczjk/dj8;I)V

    iget-object v1, p0, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/xo8;->OooOOOO(Llyiahf/vczjk/oe3;)V

    return-void
.end method

.method public final OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/dj8;->OooOOO:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    return-object v0
.end method
