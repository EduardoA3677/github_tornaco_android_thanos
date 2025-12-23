.class public Llyiahf/vczjk/tca;
.super Llyiahf/vczjk/bda;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ko6;
.implements Llyiahf/vczjk/ada;


# instance fields
.field public final OooOo:Z

.field public final OooOo0:I

.field public final OooOo0O:Z

.field public final OooOo0o:Z

.field public final OooOoO:Llyiahf/vczjk/tca;

.field public final OooOoO0:Llyiahf/vczjk/uk4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/co0;Llyiahf/vczjk/tca;ILlyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/uk4;ZZZLlyiahf/vczjk/uk4;Llyiahf/vczjk/sx8;)V
    .locals 6

    const-string v0, "containingDeclaration"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "annotations"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p5, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "outType"

    invoke-static {p6, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "source"

    move-object/from16 v5, p11

    invoke-static {v5, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v0, p0

    move-object v1, p1

    move-object v2, p4

    move-object v3, p5

    move-object v4, p6

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/bda;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/uk4;Llyiahf/vczjk/sx8;)V

    iput p3, p0, Llyiahf/vczjk/tca;->OooOo0:I

    iput-boolean p7, p0, Llyiahf/vczjk/tca;->OooOo0O:Z

    iput-boolean p8, p0, Llyiahf/vczjk/tca;->OooOo0o:Z

    iput-boolean p9, p0, Llyiahf/vczjk/tca;->OooOo:Z

    move-object/from16 v1, p10

    iput-object v1, p0, Llyiahf/vczjk/tca;->OooOoO0:Llyiahf/vczjk/uk4;

    if-nez p2, :cond_0

    move-object v1, p0

    goto :goto_0

    :cond_0
    move-object v1, p2

    :goto_0
    iput-object v1, p0, Llyiahf/vczjk/tca;->OooOoO:Llyiahf/vczjk/tca;

    return-void
.end method


# virtual methods
.method public final bridge synthetic OooO00o()Llyiahf/vczjk/co0;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tca;->o0000O()Llyiahf/vczjk/tca;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic OooO00o()Llyiahf/vczjk/v02;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tca;->o0000O()Llyiahf/vczjk/tca;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/q72;
    .locals 2

    sget-object v0, Llyiahf/vczjk/r72;->OooO0o:Llyiahf/vczjk/q72;

    const-string v1, "LOCAL"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooO0o0(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/x02;
    .locals 1

    const-string v0, "substitutor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/i5a;->OooO00o:Llyiahf/vczjk/g5a;

    invoke-virtual {p1}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result p1

    if-eqz p1, :cond_0

    return-object p0

    :cond_0
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-direct {p1}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw p1
.end method

.method public final bridge synthetic OooOO0o()Llyiahf/vczjk/v02;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tca;->o000OO()Llyiahf/vczjk/co0;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOO0()Ljava/util/Collection;
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/tca;->o000OO()Llyiahf/vczjk/co0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/co0;->OooOOO0()Ljava/util/Collection;

    move-result-object v0

    const-string v1, "getOverriddenDescriptors(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {v0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/co0;

    invoke-interface {v2}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v2

    iget v3, p0, Llyiahf/vczjk/tca;->OooOo0:I

    invoke-interface {v2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/tca;

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    return-object v1
.end method

.method public final bridge synthetic OoooO()Llyiahf/vczjk/ij1;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/z02;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p1, p0, p2}, Llyiahf/vczjk/z02;->OooOo0(Llyiahf/vczjk/tca;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OoooooO()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o0000O()Llyiahf/vczjk/tca;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tca;->OooOoO:Llyiahf/vczjk/tca;

    if-ne v0, p0, :cond_0

    return-object p0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/tca;->o0000O()Llyiahf/vczjk/tca;

    move-result-object v0

    return-object v0
.end method

.method public o0000O0(Llyiahf/vczjk/uf3;Llyiahf/vczjk/qt5;I)Llyiahf/vczjk/tca;
    .locals 12

    new-instance v0, Llyiahf/vczjk/tca;

    invoke-virtual {p0}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v4

    const-string v1, "<get-annotations>(...)"

    invoke-static {v4, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v6

    const-string v1, "getType(...)"

    invoke-static {v6, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/tca;->o0000O0O()Z

    move-result v7

    sget-object v11, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    iget-boolean v9, p0, Llyiahf/vczjk/tca;->OooOo:Z

    iget-object v10, p0, Llyiahf/vczjk/tca;->OooOoO0:Llyiahf/vczjk/uk4;

    const/4 v2, 0x0

    iget-boolean v8, p0, Llyiahf/vczjk/tca;->OooOo0o:Z

    move-object v1, p1

    move-object v5, p2

    move v3, p3

    invoke-direct/range {v0 .. v11}, Llyiahf/vczjk/tca;-><init>(Llyiahf/vczjk/co0;Llyiahf/vczjk/tca;ILlyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/uk4;ZZZLlyiahf/vczjk/uk4;Llyiahf/vczjk/sx8;)V

    return-object v0
.end method

.method public final o0000O0O()Z
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/tca;->OooOo0O:Z

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/tca;->o000OO()Llyiahf/vczjk/co0;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/eo0;

    invoke-interface {v0}, Llyiahf/vczjk/eo0;->getKind()I

    move-result v0

    const/4 v1, 0x2

    if-eq v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final bridge synthetic o0000oO()Llyiahf/vczjk/x02;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tca;->o0000O()Llyiahf/vczjk/tca;

    move-result-object v0

    return-object v0
.end method

.method public final o000OO()Llyiahf/vczjk/co0;
    .locals 2

    invoke-super {p0}, Llyiahf/vczjk/y02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    const-string v1, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.CallableDescriptor"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/co0;

    return-object v0
.end method
