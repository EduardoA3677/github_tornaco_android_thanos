.class public final Llyiahf/vczjk/z66;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/x64;

.field public final OooO0O0:Llyiahf/vczjk/ng8;

.field public final OooO0OO:Llyiahf/vczjk/p66;

.field public final OooO0Oo:Llyiahf/vczjk/zb4;

.field public final OooO0o0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/ng8;Llyiahf/vczjk/p66;Llyiahf/vczjk/zb4;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/z66;->OooO00o:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/z66;->OooO0O0:Llyiahf/vczjk/ng8;

    iput-object p3, p0, Llyiahf/vczjk/z66;->OooO0OO:Llyiahf/vczjk/p66;

    iput-object p4, p0, Llyiahf/vczjk/z66;->OooO0Oo:Llyiahf/vczjk/zb4;

    iput-boolean p5, p0, Llyiahf/vczjk/z66;->OooO0o0:Z

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/p66;Z)Llyiahf/vczjk/z66;
    .locals 7

    const/4 v0, 0x0

    if-nez p1, :cond_0

    move-object p1, v0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object p1

    :goto_0
    if-nez p1, :cond_1

    :goto_1
    move-object v3, v0

    goto :goto_2

    :cond_1
    new-instance v0, Llyiahf/vczjk/ng8;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ng8;-><init>(Ljava/lang/String;)V

    goto :goto_1

    :goto_2
    new-instance v1, Llyiahf/vczjk/z66;

    const/4 v5, 0x0

    move-object v2, p0

    move-object v4, p2

    move v6, p3

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/z66;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/ng8;Llyiahf/vczjk/p66;Llyiahf/vczjk/zb4;Z)V

    return-object v1
.end method
