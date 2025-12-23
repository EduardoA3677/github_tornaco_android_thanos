.class public final Llyiahf/vczjk/gs5;
.super Llyiahf/vczjk/hs5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/mg4;


# direct methods
.method public constructor <init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V
    .locals 6

    sget-object v1, Llyiahf/vczjk/fo0;->OooOOO0:Llyiahf/vczjk/fo0;

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ab7;-><init>(Ljava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final bridge synthetic OooO0O0()Llyiahf/vczjk/fh4;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/gs5;->OooO0O0()Llyiahf/vczjk/lh4;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/lh4;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ab7;->OooOOO()Llyiahf/vczjk/th4;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/mg4;

    invoke-interface {v0}, Llyiahf/vczjk/mh4;->OooO0O0()Llyiahf/vczjk/lh4;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic OooO0OO()Llyiahf/vczjk/gg4;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/gs5;->OooO0OO()Llyiahf/vczjk/lg4;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0OO()Llyiahf/vczjk/lg4;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ab7;->OooOOO()Llyiahf/vczjk/th4;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/mg4;

    invoke-interface {v0}, Llyiahf/vczjk/mg4;->OooO0OO()Llyiahf/vczjk/lg4;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/gs5;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0oO()Llyiahf/vczjk/bf4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/zm7;->OooO0o0(Llyiahf/vczjk/gs5;)Llyiahf/vczjk/mg4;

    move-result-object v0

    return-object v0
.end method

.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/gs5;->OooO0O0()Llyiahf/vczjk/lh4;

    move-result-object v0

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    check-cast v0, Llyiahf/vczjk/ff4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ff4;->OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
