.class public final Llyiahf/vczjk/yg4;
.super Llyiahf/vczjk/yf4;
.source "SourceFile"


# instance fields
.field public final OooOOO:Ljava/lang/Class;

.field public final OooOOOO:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/Class;)V
    .locals 2

    const-string v0, "jClass"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/yg4;->OooOOO:Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance v0, Llyiahf/vczjk/tg4;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/tg4;-><init>(Llyiahf/vczjk/yg4;I)V

    invoke-static {p1, v0}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/yg4;->OooOOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/qt5;)Ljava/util/Collection;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/yg4;->OooOOOO:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wg4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/wg4;->OooO0oO:[Llyiahf/vczjk/th4;

    const/4 v2, 0x1

    aget-object v1, v1, v2

    iget-object v0, v0, Llyiahf/vczjk/wg4;->OooO0Oo:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "getValue(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/jg5;

    sget-object v1, Llyiahf/vczjk/h16;->OooOOO:Llyiahf/vczjk/h16;

    invoke-interface {v0, p1, v1}, Llyiahf/vczjk/jg5;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/yg4;->OooOOO:Ljava/lang/Class;

    return-object v0
.end method

.method public final OooO0oo()Ljava/util/Collection;
    .locals 1

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object v0
.end method

.method public final OooOO0O(I)Llyiahf/vczjk/sa7;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/yg4;->OooOOOO:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wg4;

    iget-object v0, v0, Llyiahf/vczjk/wg4;->OooO0o:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/d1a;

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/d1a;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/be4;

    invoke-virtual {v0}, Llyiahf/vczjk/d1a;->OooO0O0()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/tc7;

    invoke-virtual {v0}, Llyiahf/vczjk/d1a;->OooO0OO()Ljava/lang/Object;

    move-result-object v0

    move-object v7, v0

    check-cast v7, Llyiahf/vczjk/yi5;

    sget-object v0, Llyiahf/vczjk/ue4;->OooOOO:Llyiahf/vczjk/ug3;

    const-string v3, "packageLocalVariable"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "<this>"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Llyiahf/vczjk/sg3;->OooO(Llyiahf/vczjk/ug3;)I

    move-result v3

    if-ge p1, v3, :cond_0

    invoke-virtual {v2, v0, p1}, Llyiahf/vczjk/sg3;->OooO0oo(Llyiahf/vczjk/ug3;I)Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    :cond_0
    move-object p1, v1

    :goto_0
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/xc7;

    if-eqz v4, :cond_1

    new-instance v6, Llyiahf/vczjk/h87;

    invoke-virtual {v2}, Llyiahf/vczjk/tc7;->OooOoOO()Llyiahf/vczjk/nd7;

    move-result-object p1

    const-string v0, "getTypeTable(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v6, p1}, Llyiahf/vczjk/h87;-><init>(Llyiahf/vczjk/nd7;)V

    sget-object v8, Llyiahf/vczjk/xg4;->OooOOO:Llyiahf/vczjk/xg4;

    iget-object v3, p0, Llyiahf/vczjk/yg4;->OooOOO:Ljava/lang/Class;

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/mba;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/sg3;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/zb0;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/co0;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sa7;

    return-object p1

    :cond_1
    return-object v1
.end method

.method public final OooOOO(Llyiahf/vczjk/qt5;)Ljava/util/Collection;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/yg4;->OooOOOO:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wg4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/wg4;->OooO0oO:[Llyiahf/vczjk/th4;

    const/4 v2, 0x1

    aget-object v1, v1, v2

    iget-object v0, v0, Llyiahf/vczjk/wg4;->OooO0Oo:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "getValue(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/jg5;

    sget-object v1, Llyiahf/vczjk/h16;->OooOOO:Llyiahf/vczjk/h16;

    invoke-interface {v0, p1, v1}, Llyiahf/vczjk/jg5;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOO0()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/yg4;->OooOOOO:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wg4;

    iget-object v0, v0, Llyiahf/vczjk/wg4;->OooO0o0:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Class;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/yg4;->OooOOO:Ljava/lang/Class;

    :cond_0
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/yg4;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/yg4;

    iget-object p1, p1, Llyiahf/vczjk/yg4;->OooOOO:Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/yg4;->OooOOO:Ljava/lang/Class;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/yg4;->OooOOO:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "file class "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/yg4;->OooOOO:Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
