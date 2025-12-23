.class public final Llyiahf/vczjk/jn0;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/h23;

.field public final OooO0O0:Llyiahf/vczjk/jl8;

.field public final OooO0OO:Llyiahf/vczjk/a99;

.field public final OooO0Oo:Llyiahf/vczjk/r09;

.field public final OooO0o0:Llyiahf/vczjk/s48;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;)V
    .locals 5

    const-string v0, "src"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "scope"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/h23;

    invoke-direct {v0}, Llyiahf/vczjk/h23;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/jn0;->OooO00o:Llyiahf/vczjk/h23;

    sget-object v0, Llyiahf/vczjk/aj0;->OooOOO0:Llyiahf/vczjk/aj0;

    const v1, 0x7fffffff

    const/4 v2, 0x1

    invoke-static {v2, v1, v0}, Llyiahf/vczjk/zsa;->OooOO0O(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/jn0;->OooO0O0:Llyiahf/vczjk/jl8;

    new-instance v1, Llyiahf/vczjk/in0;

    const/4 v3, 0x0

    invoke-direct {v1, p0, v3}, Llyiahf/vczjk/in0;-><init>(Llyiahf/vczjk/jn0;Llyiahf/vczjk/yo1;)V

    new-instance v4, Llyiahf/vczjk/a99;

    invoke-direct {v4, v0, v1}, Llyiahf/vczjk/a99;-><init>(Llyiahf/vczjk/jl8;Llyiahf/vczjk/in0;)V

    iput-object v4, p0, Llyiahf/vczjk/jn0;->OooO0OO:Llyiahf/vczjk/a99;

    sget-object v0, Llyiahf/vczjk/as1;->OooOOO:Llyiahf/vczjk/as1;

    new-instance v1, Llyiahf/vczjk/gn0;

    invoke-direct {v1, p1, p0, v3}, Llyiahf/vczjk/gn0;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/jn0;Llyiahf/vczjk/yo1;)V

    invoke-static {p2, v3, v0, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/hn0;

    invoke-direct {p2, p0}, Llyiahf/vczjk/hn0;-><init>(Llyiahf/vczjk/jn0;)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/k84;->OoooO00(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/sc2;

    iput-object p1, p0, Llyiahf/vczjk/jn0;->OooO0Oo:Llyiahf/vczjk/r09;

    new-instance p1, Llyiahf/vczjk/dn0;

    invoke-direct {p1, p0, v3}, Llyiahf/vczjk/dn0;-><init>(Llyiahf/vczjk/jn0;Llyiahf/vczjk/yo1;)V

    new-instance p2, Llyiahf/vczjk/s48;

    invoke-direct {p2, p1}, Llyiahf/vczjk/s48;-><init>(Llyiahf/vczjk/ze3;)V

    iput-object p2, p0, Llyiahf/vczjk/jn0;->OooO0o0:Llyiahf/vczjk/s48;

    return-void
.end method
