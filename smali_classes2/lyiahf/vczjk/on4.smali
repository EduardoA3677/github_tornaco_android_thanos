.class public final Llyiahf/vczjk/on4;
.super Llyiahf/vczjk/dha;
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
        "Llyiahf/vczjk/on4;",
        "Llyiahf/vczjk/dha;",
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
.field public final OooO0O0:Landroid/content/Context;

.field public final OooO0OO:Llyiahf/vczjk/s29;

.field public final OooO0Oo:Llyiahf/vczjk/gh7;

.field public final OooO0o:Llyiahf/vczjk/sc9;

.field public final OooO0o0:Llyiahf/vczjk/sc9;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    invoke-direct {p0}, Llyiahf/vczjk/dha;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/on4;->OooO0O0:Landroid/content/Context;

    new-instance p1, Llyiahf/vczjk/xe6;

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const/4 v1, 0x1

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/xe6;-><init>(Ljava/util/List;Z)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/on4;->OooO0OO:Llyiahf/vczjk/s29;

    new-instance v0, Llyiahf/vczjk/gh7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v0, p0, Llyiahf/vczjk/on4;->OooO0Oo:Llyiahf/vczjk/gh7;

    new-instance p1, Llyiahf/vczjk/hn4;

    const/4 v0, 0x2

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/hn4;-><init>(Llyiahf/vczjk/on4;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/on4;->OooO0o0:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/hn4;

    const/4 v0, 0x3

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/hn4;-><init>(Llyiahf/vczjk/on4;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/on4;->OooO0o:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OooO0o0()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/on4;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xe6;

    iget-object v1, v1, Llyiahf/vczjk/xe6;->OooO0O0:Ljava/util/List;

    const-string v2, "ruleItems"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/xe6;

    const/4 v3, 0x1

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/xe6;-><init>(Ljava/util/List;Z)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/nn4;

    invoke-direct {v2, p0, v1}, Llyiahf/vczjk/nn4;-><init>(Llyiahf/vczjk/on4;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v1, v1, v2, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method
