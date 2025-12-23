.class public abstract Llyiahf/vczjk/vs0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/fg3;


# instance fields
.field public final OooOOO:I

.field public final OooOOO0:Llyiahf/vczjk/or1;

.field public final OooOOOO:Llyiahf/vczjk/aj0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vs0;->OooOOO0:Llyiahf/vczjk/or1;

    iput p2, p0, Llyiahf/vczjk/vs0;->OooOOO:I

    iput-object p3, p0, Llyiahf/vczjk/vs0;->OooOOOO:Llyiahf/vczjk/aj0;

    return-void
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/xr1;)Llyiahf/vczjk/ui7;
    .locals 5

    const/4 v0, -0x3

    iget v1, p0, Llyiahf/vczjk/vs0;->OooOOO:I

    if-ne v1, v0, :cond_0

    const/4 v1, -0x2

    :cond_0
    sget-object v0, Llyiahf/vczjk/as1;->OooOOOO:Llyiahf/vczjk/as1;

    new-instance v2, Llyiahf/vczjk/us0;

    const/4 v3, 0x0

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/us0;-><init>(Llyiahf/vczjk/vs0;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x4

    iget-object v4, p0, Llyiahf/vczjk/vs0;->OooOOOO:Llyiahf/vczjk/aj0;

    invoke-static {v1, v3, v4}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object v1

    iget-object v3, p0, Llyiahf/vczjk/vs0;->OooOOO0:Llyiahf/vczjk/or1;

    invoke-static {p1, v3}, Llyiahf/vczjk/t51;->Oooo(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    new-instance v3, Llyiahf/vczjk/r77;

    invoke-direct {v3, p1, v1}, Llyiahf/vczjk/r77;-><init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/jj0;)V

    invoke-virtual {v3, v0, v3, v2}, Llyiahf/vczjk/o000O000;->Oooooo(Llyiahf/vczjk/as1;Llyiahf/vczjk/o000O000;Llyiahf/vczjk/ze3;)V

    return-object v3
.end method

.method public OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ts0;

    const/4 v1, 0x0

    invoke-direct {v0, p1, p0, v1}, Llyiahf/vczjk/ts0;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/vs0;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, p2}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/f43;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/vs0;->OooOOO0:Llyiahf/vczjk/or1;

    invoke-interface {p1, v0}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/aj0;->OooOOO0:Llyiahf/vczjk/aj0;

    iget-object v2, p0, Llyiahf/vczjk/vs0;->OooOOOO:Llyiahf/vczjk/aj0;

    iget v3, p0, Llyiahf/vczjk/vs0;->OooOOO:I

    if-eq p3, v1, :cond_0

    goto :goto_2

    :cond_0
    const/4 p3, -0x3

    if-ne v3, p3, :cond_1

    goto :goto_1

    :cond_1
    if-ne p2, p3, :cond_2

    :goto_0
    move p2, v3

    goto :goto_1

    :cond_2
    const/4 p3, -0x2

    if-ne v3, p3, :cond_3

    goto :goto_1

    :cond_3
    if-ne p2, p3, :cond_4

    goto :goto_0

    :cond_4
    add-int/2addr p2, v3

    if-ltz p2, :cond_5

    goto :goto_1

    :cond_5
    const p2, 0x7fffffff

    :goto_1
    move-object p3, v2

    :goto_2
    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_6

    if-ne p2, v3, :cond_6

    if-ne p3, v2, :cond_6

    return-object p0

    :cond_6
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/vs0;->OooO0o0(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/vs0;

    move-result-object p1

    return-object p1
.end method

.method public OooO0OO()Ljava/lang/String;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public abstract OooO0Oo(Llyiahf/vczjk/s77;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
.end method

.method public OooO0o()Llyiahf/vczjk/f43;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public abstract OooO0o0(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/vs0;
.end method

.method public toString()Ljava/lang/String;
    .locals 7

    new-instance v0, Ljava/util/ArrayList;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {p0}, Llyiahf/vczjk/vs0;->OooO0OO()Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_0
    sget-object v1, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    iget-object v2, p0, Llyiahf/vczjk/vs0;->OooOOO0:Llyiahf/vczjk/or1;

    if-eq v2, v1, :cond_1

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "context="

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_1
    const/4 v1, -0x3

    iget v2, p0, Llyiahf/vczjk/vs0;->OooOOO:I

    if-eq v2, v1, :cond_2

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "capacity="

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_2
    sget-object v1, Llyiahf/vczjk/aj0;->OooOOO0:Llyiahf/vczjk/aj0;

    iget-object v2, p0, Llyiahf/vczjk/vs0;->OooOOOO:Llyiahf/vczjk/aj0;

    if-eq v2, v1, :cond_3

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "onBufferOverflow="

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_3
    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x5b

    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    const/4 v3, 0x0

    const/4 v4, 0x0

    const-string v1, ", "

    const/4 v2, 0x0

    const/16 v5, 0x3e

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v0

    const/16 v1, 0x5d

    invoke-static {v6, v0, v1}, Llyiahf/vczjk/ii5;->OooOO0O(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
