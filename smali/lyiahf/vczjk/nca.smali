.class public abstract Llyiahf/vczjk/nca;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooOo0o()Llyiahf/vczjk/gn;

    move-result-object v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO00o(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v0

    const-string v1, "true"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 p1, 0x1

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/nca;->OooOO0o(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    const-string v1, "false"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    const/4 p1, 0x0

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/nca;->OooOO0o(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_2

    sget-object v0, Llyiahf/vczjk/w72;->Oooo000:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_2

    return-object v1

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooOoo0()Ljava/lang/Class;

    move-result-object v0

    iget-object v2, p2, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    const-string v2, "no String-argument constructor/factory method to deserialize from String value (\'%s\')"

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p2, v0, p0, v2, p1}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    throw v1
.end method

.method public OooO0O0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooO0OO()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooO0Oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooO0o()Z
    .locals 1

    instance-of v0, p0, Llyiahf/vczjk/ja4;

    return v0
.end method

.method public OooO0o0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooO0oO()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooO0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooOO0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooOO0O()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooO()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooOO0()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooO0oo()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooO0o()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooO0oO()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooO0Oo()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooO0OO()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public OooOO0o(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooOoo0()Ljava/lang/Class;

    move-result-object v0

    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    const-string v1, "no boolean/Boolean-argument constructor/factory method to deserialize from boolean value (%s)"

    invoke-virtual {p1, v0, p0, v1, p2}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public OooOOO(Llyiahf/vczjk/v72;I)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooOoo0()Ljava/lang/Class;

    move-result-object v0

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    const-string v1, "no int/Int-argument constructor/factory method to deserialize from Number value (%s)"

    invoke-virtual {p1, v0, p0, v1, p2}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public OooOOO0(Llyiahf/vczjk/v72;D)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooOoo0()Ljava/lang/Class;

    move-result-object v0

    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    const-string p3, "no double/Double-argument constructor/factory method to deserialize from Number value (%s)"

    invoke-virtual {p1, v0, p0, p3, p2}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public OooOOOO(Llyiahf/vczjk/v72;J)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooOoo0()Ljava/lang/Class;

    move-result-object v0

    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    const-string p3, "no long/Long-argument constructor/factory method to deserialize from Number value (%s)"

    invoke-virtual {p1, v0, p0, p3, p2}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public OooOOOo(Llyiahf/vczjk/v72;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooOoo0()Ljava/lang/Class;

    move-result-object p2

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "no creator with arguments specified"

    invoke-virtual {p1, p2, p0, v1, v0}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public OooOOo(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooOoo0()Ljava/lang/Class;

    move-result-object p1

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "no array delegate creator specified"

    invoke-virtual {p2, p1, p0, v1, v0}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public OooOOo0(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/nca;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooOoo0()Ljava/lang/Class;

    move-result-object v0

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "no default no-arguments constructor found"

    invoke-virtual {p1, v0, p0, v2, v1}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public OooOo()Llyiahf/vczjk/gn;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public OooOo0()Llyiahf/vczjk/gn;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/nca;->OooOoo0()Ljava/lang/Class;

    move-result-object p1

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "no delegate creator specified"

    invoke-virtual {p2, p1, p0, v1, v0}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public OooOo0O()Llyiahf/vczjk/x64;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public OooOo0o()Llyiahf/vczjk/gn;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public OooOoO(Llyiahf/vczjk/t72;)[Llyiahf/vczjk/ph8;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public OooOoO0()Llyiahf/vczjk/x64;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public OooOoOO()Llyiahf/vczjk/vm;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public abstract OooOoo0()Ljava/lang/Class;
.end method
