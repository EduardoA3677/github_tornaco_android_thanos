.class public final Llyiahf/vczjk/gw6;
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
        "Llyiahf/vczjk/gw6;",
        "Llyiahf/vczjk/fy4;",
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
.field public final OooO:Llyiahf/vczjk/gh7;

.field public final OooO0o:Lgithub/tornaco/android/thanos/core/Logger;

.field public final OooO0o0:Llyiahf/vczjk/x58;

.field public final OooO0oO:Llyiahf/vczjk/s29;

.field public final OooO0oo:Llyiahf/vczjk/gh7;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/x58;)V
    .locals 4

    const-string p1, "savedStateHandle"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Llyiahf/vczjk/fy4;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/gw6;->OooO0o0:Llyiahf/vczjk/x58;

    new-instance p1, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v0, "PkgPickerVM"

    invoke-direct {p1, v0}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/gw6;->OooO0o:Lgithub/tornaco/android/thanos/core/Logger;

    const-string p1, "query"

    const-string v0, ""

    invoke-virtual {p2, p1, v0}, Llyiahf/vczjk/x58;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/gh7;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/ot6;

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sget-object v1, Llyiahf/vczjk/pw;->OooO0O0:Llyiahf/vczjk/mw;

    sget-object v2, Llyiahf/vczjk/pw;->OooO00o:Llyiahf/vczjk/mw;

    filled-new-array {v1, v2}, [Llyiahf/vczjk/mw;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    const/4 v3, 0x0

    invoke-direct {p2, v3, v0, v1, v2}, Llyiahf/vczjk/ot6;-><init>(ZLjava/util/List;Llyiahf/vczjk/mw;Ljava/util/List;)V

    invoke-static {p2}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/gw6;->OooO0oO:Llyiahf/vczjk/s29;

    new-instance v1, Llyiahf/vczjk/gh7;

    invoke-direct {v1, p2}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v1, p0, Llyiahf/vczjk/gw6;->OooO0oo:Llyiahf/vczjk/gh7;

    new-instance p2, Llyiahf/vczjk/b40;

    const/4 v2, 0x5

    invoke-direct {p2, v1, v2}, Llyiahf/vczjk/b40;-><init>(Llyiahf/vczjk/gh7;I)V

    new-instance v1, Llyiahf/vczjk/bw6;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/bw6;-><init>(Llyiahf/vczjk/gw6;Llyiahf/vczjk/yo1;)V

    new-instance v3, Llyiahf/vczjk/y63;

    invoke-direct {v3, p1, p2, v1}, Llyiahf/vczjk/y63;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;)V

    new-instance p1, Llyiahf/vczjk/cw6;

    invoke-direct {p1, p0, v2}, Llyiahf/vczjk/cw6;-><init>(Llyiahf/vczjk/gw6;Llyiahf/vczjk/yo1;)V

    new-instance p2, Llyiahf/vczjk/l53;

    invoke-direct {p2, v3, p1}, Llyiahf/vczjk/l53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;)V

    new-instance p1, Llyiahf/vczjk/dw6;

    invoke-direct {p1, p0, v2}, Llyiahf/vczjk/dw6;-><init>(Llyiahf/vczjk/gw6;Llyiahf/vczjk/yo1;)V

    new-instance v1, Llyiahf/vczjk/w53;

    const/4 v2, 0x1

    invoke-direct {v1, p2, p1, v2}, Llyiahf/vczjk/w53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;I)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/ql8;->OooO0O0:Llyiahf/vczjk/e86;

    invoke-static {v1, p1, p2, v0}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/gw6;->OooO:Llyiahf/vczjk/gh7;

    return-void
.end method
