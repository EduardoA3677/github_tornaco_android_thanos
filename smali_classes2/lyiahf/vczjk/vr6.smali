.class public final Llyiahf/vczjk/vr6;
.super Llyiahf/vczjk/fy4;
.source "SourceFile"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "StaticFieldLeak"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\n\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0007\u0018\u00002\u00020\u0001\u00a8\u0006\u0002"
    }
    d2 = {
        "Llyiahf/vczjk/vr6;",
        "Llyiahf/vczjk/fy4;",
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
.field public final OooO:Llyiahf/vczjk/sc9;

.field public final OooO0o:Llyiahf/vczjk/s29;

.field public final OooO0o0:Landroid/content/Context;

.field public final OooO0oO:Llyiahf/vczjk/gh7;

.field public final OooO0oo:Llyiahf/vczjk/jl8;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    invoke-direct {p0}, Llyiahf/vczjk/fy4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vr6;->OooO0o0:Landroid/content/Context;

    new-instance p1, Llyiahf/vczjk/yr6;

    sget-object v0, Llyiahf/vczjk/i59;->OooO00o:Llyiahf/vczjk/i59;

    const-string v1, ""

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/yr6;-><init>(Llyiahf/vczjk/k59;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vr6;->OooO0o:Llyiahf/vczjk/s29;

    new-instance v0, Llyiahf/vczjk/gh7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v0, p0, Llyiahf/vczjk/vr6;->OooO0oO:Llyiahf/vczjk/gh7;

    const/4 p1, 0x7

    const/4 v0, 0x0

    invoke-static {p1, v0}, Llyiahf/vczjk/zsa;->OooOO0o(ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vr6;->OooO0oo:Llyiahf/vczjk/jl8;

    new-instance p1, Llyiahf/vczjk/fz3;

    const/16 v0, 0x16

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/fz3;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vr6;->OooO:Llyiahf/vczjk/sc9;

    return-void
.end method
