.class public final Llyiahf/vczjk/cj8;
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
        "Llyiahf/vczjk/cj8;",
        "Llyiahf/vczjk/vo1;",
        "Llyiahf/vczjk/ni8;",
        "ui_prcRelease"
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


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    new-instance v0, Llyiahf/vczjk/p35;

    const/16 v1, 0x17

    invoke-direct {v0, v1}, Llyiahf/vczjk/p35;-><init>(I)V

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/vo1;-><init>(Landroid/content/Context;Llyiahf/vczjk/le3;)V

    const/4 p1, 0x7

    const/4 v0, 0x0

    invoke-static {p1, v0}, Llyiahf/vczjk/zsa;->OooOO0o(ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/cj8;->OooO0oo:Llyiahf/vczjk/jl8;

    new-instance v0, Llyiahf/vczjk/eh7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/eh7;-><init>(Llyiahf/vczjk/os5;)V

    iput-object v0, p0, Llyiahf/vczjk/cj8;->OooO:Llyiahf/vczjk/eh7;

    return-void
.end method
