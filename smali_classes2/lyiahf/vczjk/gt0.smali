.class public final Llyiahf/vczjk/gt0;
.super Llyiahf/vczjk/vs0;
.source "SourceFile"


# instance fields
.field public final OooOOOo:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/Iterable;Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)V
    .locals 0

    invoke-direct {p0, p2, p3, p4}, Llyiahf/vczjk/vs0;-><init>(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)V

    iput-object p1, p0, Llyiahf/vczjk/gt0;->OooOOOo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/xr1;)Llyiahf/vczjk/ui7;
    .locals 5

    new-instance v0, Llyiahf/vczjk/us0;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/us0;-><init>(Llyiahf/vczjk/vs0;Llyiahf/vczjk/yo1;)V

    sget-object v1, Llyiahf/vczjk/aj0;->OooOOO0:Llyiahf/vczjk/aj0;

    sget-object v2, Llyiahf/vczjk/as1;->OooOOO0:Llyiahf/vczjk/as1;

    const/4 v3, 0x4

    iget v4, p0, Llyiahf/vczjk/vs0;->OooOOO:I

    invoke-static {v4, v3, v1}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object v1

    iget-object v3, p0, Llyiahf/vczjk/vs0;->OooOOO0:Llyiahf/vczjk/or1;

    invoke-static {p1, v3}, Llyiahf/vczjk/t51;->Oooo(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    new-instance v3, Llyiahf/vczjk/r77;

    invoke-direct {v3, p1, v1}, Llyiahf/vczjk/r77;-><init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/jj0;)V

    invoke-virtual {v3, v2, v3, v0}, Llyiahf/vczjk/o000O000;->Oooooo(Llyiahf/vczjk/as1;Llyiahf/vczjk/o000O000;Llyiahf/vczjk/ze3;)V

    return-object v3
.end method

.method public final OooO0Oo(Llyiahf/vczjk/s77;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 4

    new-instance p2, Llyiahf/vczjk/kf8;

    invoke-direct {p2, p1}, Llyiahf/vczjk/kf8;-><init>(Llyiahf/vczjk/s77;)V

    iget-object v0, p0, Llyiahf/vczjk/gt0;->OooOOOo:Ljava/lang/Object;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/f43;

    new-instance v2, Llyiahf/vczjk/ft0;

    const/4 v3, 0x0

    invoke-direct {v2, v1, p2, v3}, Llyiahf/vczjk/ft0;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/kf8;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    invoke-static {p1, v3, v3, v2, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/vs0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/gt0;

    iget-object v1, p0, Llyiahf/vczjk/gt0;->OooOOOo:Ljava/lang/Object;

    invoke-direct {v0, v1, p1, p2, p3}, Llyiahf/vczjk/gt0;-><init>(Ljava/lang/Iterable;Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)V

    return-object v0
.end method
