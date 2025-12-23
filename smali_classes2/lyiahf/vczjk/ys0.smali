.class public abstract Llyiahf/vczjk/ys0;
.super Llyiahf/vczjk/vs0;
.source "SourceFile"


# instance fields
.field public final OooOOOo:Llyiahf/vczjk/f43;


# direct methods
.method public constructor <init>(ILlyiahf/vczjk/aj0;Llyiahf/vczjk/or1;Llyiahf/vczjk/f43;)V
    .locals 0

    invoke-direct {p0, p3, p1, p2}, Llyiahf/vczjk/vs0;-><init>(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)V

    iput-object p4, p0, Llyiahf/vczjk/ys0;->OooOOOo:Llyiahf/vczjk/f43;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget v1, p0, Llyiahf/vczjk/vs0;->OooOOO:I

    const/4 v2, -0x3

    if-ne v1, v2, :cond_4

    invoke-interface {p2}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v1

    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    new-instance v3, Llyiahf/vczjk/v1;

    const/16 v4, 0x16

    invoke-direct {v3, v4}, Llyiahf/vczjk/v1;-><init>(I)V

    iget-object v4, p0, Llyiahf/vczjk/vs0;->OooOOO0:Llyiahf/vczjk/or1;

    invoke-interface {v4, v2, v3}, Llyiahf/vczjk/or1;->o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    if-nez v2, :cond_0

    invoke-interface {v1, v4}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v2

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    invoke-static {v1, v4, v2}, Llyiahf/vczjk/t51;->OooOoOO(Llyiahf/vczjk/or1;Llyiahf/vczjk/or1;Z)Llyiahf/vczjk/or1;

    move-result-object v2

    :goto_0
    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ys0;->OooOO0(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_5

    return-object p1

    :cond_1
    sget-object v3, Llyiahf/vczjk/vp3;->OooOOOO:Llyiahf/vczjk/vp3;

    invoke-interface {v2, v3}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v4

    invoke-interface {v1, v3}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v1

    invoke-static {v4, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-interface {p2}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v1

    instance-of v3, p1, Llyiahf/vczjk/kf8;

    if-nez v3, :cond_3

    instance-of v3, p1, Llyiahf/vczjk/n26;

    if-eqz v3, :cond_2

    goto :goto_1

    :cond_2
    new-instance v3, Llyiahf/vczjk/nk;

    invoke-direct {v3, p1, v1}, Llyiahf/vczjk/nk;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/or1;)V

    move-object p1, v3

    :cond_3
    :goto_1
    new-instance v1, Llyiahf/vczjk/xs0;

    const/4 v3, 0x0

    invoke-direct {v1, p0, v3}, Llyiahf/vczjk/xs0;-><init>(Llyiahf/vczjk/ys0;Llyiahf/vczjk/yo1;)V

    invoke-static {v2}, Llyiahf/vczjk/jp8;->OoooOo0(Llyiahf/vczjk/or1;)Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2, p1, v3, v1, p2}, Llyiahf/vczjk/ng0;->OooooOo(Llyiahf/vczjk/or1;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_5

    return-object p1

    :cond_4
    invoke-super {p0, p1, p2}, Llyiahf/vczjk/vs0;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_5

    return-object p1

    :cond_5
    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/s77;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 1

    new-instance v0, Llyiahf/vczjk/kf8;

    invoke-direct {v0, p1}, Llyiahf/vczjk/kf8;-><init>(Llyiahf/vczjk/s77;)V

    invoke-virtual {p0, v0, p2}, Llyiahf/vczjk/ys0;->OooOO0(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public abstract OooOO0(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/ys0;->OooOOOo:Llyiahf/vczjk/f43;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " -> "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-super {p0}, Llyiahf/vczjk/vs0;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
