.class public final Llyiahf/vczjk/i40;
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
        "Llyiahf/vczjk/i40;",
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

.field public final OooO0o:Llyiahf/vczjk/o30;

.field public final OooO0o0:Llyiahf/vczjk/x58;

.field public final OooO0oO:Llyiahf/vczjk/s29;

.field public final OooO0oo:Llyiahf/vczjk/gh7;

.field public final OooOO0:Llyiahf/vczjk/gh7;

.field public final OooOO0O:Llyiahf/vczjk/gh7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x58;Llyiahf/vczjk/o30;)V
    .locals 11

    const/4 v0, 0x2

    const/4 v1, 0x1

    const/4 v2, 0x0

    const-string v3, "savedStateHandle"

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "repo"

    invoke-static {p2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Llyiahf/vczjk/fy4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i40;->OooO0o0:Llyiahf/vczjk/x58;

    iput-object p2, p0, Llyiahf/vczjk/i40;->OooO0o:Llyiahf/vczjk/o30;

    new-instance v3, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v4, "BCVM"

    invoke-direct {v3, v4}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/q30;

    sget-object v6, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sget-object v7, Llyiahf/vczjk/pw;->OooO0O0:Llyiahf/vczjk/mw;

    sget-object v3, Llyiahf/vczjk/pw;->OooO00o:Llyiahf/vczjk/mw;

    filled-new-array {v7, v3}, [Llyiahf/vczjk/mw;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/j40;->OooO0OO:Llyiahf/vczjk/mw;

    sget-object v3, Llyiahf/vczjk/j40;->OooO00o:Llyiahf/vczjk/mw;

    sget-object v4, Llyiahf/vczjk/j40;->OooO0O0:Llyiahf/vczjk/mw;

    filled-new-array {v3, v4, v9}, [Llyiahf/vczjk/mw;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v10

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/q30;-><init>(Ljava/util/List;Llyiahf/vczjk/mw;Ljava/util/List;Llyiahf/vczjk/mw;Ljava/util/List;)V

    invoke-static {v5}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v3

    iput-object v3, p0, Llyiahf/vczjk/i40;->OooO0oO:Llyiahf/vczjk/s29;

    new-instance v4, Llyiahf/vczjk/gh7;

    invoke-direct {v4, v3}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v4, p0, Llyiahf/vczjk/i40;->OooO0oo:Llyiahf/vczjk/gh7;

    const-string v3, "query"

    const-string v5, ""

    invoke-virtual {p1, v3, v5}, Llyiahf/vczjk/x58;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/gh7;

    move-result-object p1

    invoke-virtual {p2}, Llyiahf/vczjk/o30;->OooO00o()Llyiahf/vczjk/y63;

    move-result-object v3

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v5

    sget-object v7, Llyiahf/vczjk/ql8;->OooO0O0:Llyiahf/vczjk/e86;

    invoke-static {v3, v5, v7, v6}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object v3

    new-instance v5, Llyiahf/vczjk/b40;

    invoke-direct {v5, v4, v2}, Llyiahf/vczjk/b40;-><init>(Llyiahf/vczjk/gh7;I)V

    new-instance v6, Llyiahf/vczjk/y30;

    invoke-direct {v6, v5, v2}, Llyiahf/vczjk/y30;-><init>(Ljava/lang/Object;I)V

    new-instance v5, Llyiahf/vczjk/b40;

    invoke-direct {v5, v4, v1}, Llyiahf/vczjk/b40;-><init>(Llyiahf/vczjk/gh7;I)V

    new-instance v8, Llyiahf/vczjk/b40;

    invoke-direct {v8, v4, v0}, Llyiahf/vczjk/b40;-><init>(Llyiahf/vczjk/gh7;I)V

    new-instance v4, Llyiahf/vczjk/r30;

    const/4 v9, 0x0

    invoke-direct {v4, v9}, Llyiahf/vczjk/r30;-><init>(Llyiahf/vczjk/yo1;)V

    const/4 v10, 0x5

    new-array v10, v10, [Llyiahf/vczjk/f43;

    aput-object v6, v10, v2

    aput-object v3, v10, v1

    aput-object p1, v10, v0

    const/4 p1, 0x3

    aput-object v5, v10, p1

    const/4 p1, 0x4

    aput-object v8, v10, p1

    new-instance p1, Llyiahf/vczjk/b73;

    invoke-direct {p1, v10, v9, v4}, Llyiahf/vczjk/b73;-><init>([Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;Llyiahf/vczjk/gf3;)V

    new-instance v2, Llyiahf/vczjk/s48;

    invoke-direct {v2, p1}, Llyiahf/vczjk/s48;-><init>(Llyiahf/vczjk/ze3;)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    sget-object v3, Llyiahf/vczjk/q7a;->OooO00o:Llyiahf/vczjk/q7a;

    invoke-static {v2, p1, v7, v3}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/i40;->OooO:Llyiahf/vczjk/gh7;

    iget-object p1, p2, Llyiahf/vczjk/o30;->OooO00o:Llyiahf/vczjk/l30;

    iget-object p2, p1, Llyiahf/vczjk/l30;->OooO00o:Landroid/content/Context;

    invoke-static {p2}, Llyiahf/vczjk/p30;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p2

    invoke-interface {p2}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object p2

    new-instance v2, Llyiahf/vczjk/wh;

    invoke-direct {v2, p2, v1}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p2

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v2, p2, v7, v1}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/i40;->OooOO0:Llyiahf/vczjk/gh7;

    iget-object p1, p1, Llyiahf/vczjk/l30;->OooO00o:Landroid/content/Context;

    invoke-static {p1}, Llyiahf/vczjk/p30;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/wh;

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    invoke-static {p2, p1, v7, v1}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/i40;->OooOO0O:Llyiahf/vczjk/gh7;

    return-void
.end method
