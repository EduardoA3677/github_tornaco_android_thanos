.class public final Llyiahf/vczjk/qsa;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/p66;

.field public OooO0O0:Ljava/lang/Object;

.field public OooO0OO:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/p66;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/qsa;->OooO0OO:Z

    iput-object p1, p0, Llyiahf/vczjk/qsa;->OooO00o:Llyiahf/vczjk/p66;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/z66;)V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/qsa;->OooO0OO:Z

    invoke-virtual {p1}, Llyiahf/vczjk/u94;->OooOOOO()Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/qsa;->OooO0O0:Ljava/lang/Object;

    if-nez p2, :cond_0

    const/4 p2, 0x0

    goto :goto_0

    :cond_0
    invoke-static {p2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    :goto_0
    invoke-virtual {p1, p2}, Llyiahf/vczjk/u94;->o0000OO0(Ljava/lang/String;)V

    return-void

    :cond_1
    iget-object v0, p3, Llyiahf/vczjk/z66;->OooO0O0:Llyiahf/vczjk/ng8;

    if-eqz v0, :cond_2

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u94;->o00000oO(Llyiahf/vczjk/fg8;)V

    iget-object p3, p3, Llyiahf/vczjk/z66;->OooO0Oo:Llyiahf/vczjk/zb4;

    iget-object v0, p0, Llyiahf/vczjk/qsa;->OooO0O0:Ljava/lang/Object;

    invoke-virtual {p3, v0, p1, p2}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    :cond_2
    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/z66;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/qsa;->OooO0O0:Ljava/lang/Object;

    if-eqz v0, :cond_2

    iget-boolean v0, p0, Llyiahf/vczjk/qsa;->OooO0OO:Z

    if-nez v0, :cond_0

    iget-boolean v0, p3, Llyiahf/vczjk/z66;->OooO0o0:Z

    if-eqz v0, :cond_2

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/u94;->OooOOOO()Z

    move-result v0

    if-nez v0, :cond_1

    iget-object p3, p3, Llyiahf/vczjk/z66;->OooO0Oo:Llyiahf/vczjk/zb4;

    iget-object v0, p0, Llyiahf/vczjk/qsa;->OooO0O0:Ljava/lang/Object;

    invoke-virtual {p3, v0, p1, p2}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    const/4 p1, 0x1

    return p1

    :cond_1
    iget-object p2, p0, Llyiahf/vczjk/qsa;->OooO0O0:Ljava/lang/Object;

    invoke-static {p2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p2, Llyiahf/vczjk/s94;

    const-string p3, "No native support for writing Object Ids"

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/s94;-><init>(Ljava/lang/String;Llyiahf/vczjk/u94;)V

    throw p2

    :cond_2
    const/4 p1, 0x0

    return p1
.end method
