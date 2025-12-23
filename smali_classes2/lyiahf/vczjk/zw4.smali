.class public final Llyiahf/vczjk/zw4;
.super Llyiahf/vczjk/uk4;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/q45;

.field public final OooOOOO:Llyiahf/vczjk/le3;

.field public final OooOOOo:Llyiahf/vczjk/o45;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V
    .locals 1

    const-string v0, "storageManager"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zw4;->OooOOO:Llyiahf/vczjk/q45;

    iput-object p2, p0, Llyiahf/vczjk/zw4;->OooOOOO:Llyiahf/vczjk/le3;

    new-instance v0, Llyiahf/vczjk/o45;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Llyiahf/vczjk/zw4;->OooOOOo:Llyiahf/vczjk/o45;

    return-void
.end method


# virtual methods
.method public final OoooOO0()Llyiahf/vczjk/jg5;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zw4;->o00000OO()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v0

    return-object v0
.end method

.method public final o000000()Llyiahf/vczjk/n3a;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zw4;->o00000OO()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    return-object v0
.end method

.method public final o000000o()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zw4;->o00000OO()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v0

    return v0
.end method

.method public final o00000O()Llyiahf/vczjk/iaa;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/zw4;->o00000OO()Llyiahf/vczjk/uk4;

    move-result-object v0

    :goto_0
    instance-of v1, v0, Llyiahf/vczjk/zw4;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/zw4;

    invoke-virtual {v0}, Llyiahf/vczjk/zw4;->o00000OO()Llyiahf/vczjk/uk4;

    move-result-object v0

    goto :goto_0

    :cond_0
    const-string v1, "null cannot be cast to non-null type org.jetbrains.kotlin.types.UnwrappedType"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/iaa;

    return-object v0
.end method

.method public final o00000O0(Llyiahf/vczjk/al4;)Llyiahf/vczjk/uk4;
    .locals 4

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/zw4;

    new-instance v1, Llyiahf/vczjk/o0O000;

    const/16 v2, 0x19

    const/4 v3, 0x0

    invoke-direct {v1, v2, p1, p0, v3}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    iget-object p1, p0, Llyiahf/vczjk/zw4;->OooOOO:Llyiahf/vczjk/q45;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/zw4;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    return-object v0
.end method

.method public final o00000OO()Llyiahf/vczjk/uk4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zw4;->OooOOOo:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/uk4;

    return-object v0
.end method

.method public final o00ooo()Ljava/util/List;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zw4;->o00000OO()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final o0OOO0o()Llyiahf/vczjk/d3a;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zw4;->o00000OO()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object v0

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/zw4;->OooOOOo:Llyiahf/vczjk/o45;

    iget-object v1, v0, Llyiahf/vczjk/n45;->OooOOOO:Ljava/lang/Object;

    sget-object v2, Llyiahf/vczjk/p45;->OooOOO0:Llyiahf/vczjk/p45;

    if-eq v1, v2, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/n45;->OooOOOO:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/p45;->OooOOO:Llyiahf/vczjk/p45;

    if-eq v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/zw4;->o00000OO()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :cond_0
    const-string v0, "<Not computed yet>"

    return-object v0
.end method
