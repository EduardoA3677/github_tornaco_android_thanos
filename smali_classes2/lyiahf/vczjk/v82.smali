.class public final Llyiahf/vczjk/v82;
.super Llyiahf/vczjk/y02;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/m82;
.implements Llyiahf/vczjk/a3a;


# instance fields
.field public final OooOo:Llyiahf/vczjk/jd7;

.field public final OooOo0:Llyiahf/vczjk/q72;

.field public final OooOo00:Llyiahf/vczjk/q45;

.field public OooOo0O:Ljava/util/List;

.field public final OooOo0o:Llyiahf/vczjk/o0O0o;

.field public final OooOoO:Llyiahf/vczjk/h87;

.field public final OooOoO0:Llyiahf/vczjk/rt5;

.field public final OooOoOO:Llyiahf/vczjk/xea;

.field public OooOoo:Llyiahf/vczjk/dp8;

.field public final OooOoo0:Llyiahf/vczjk/ce4;

.field public OooOooO:Llyiahf/vczjk/dp8;

.field public OooOooo:Ljava/util/List;

.field public Oooo000:Llyiahf/vczjk/dp8;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/v82;

    const-string v2, "constructors"

    const-string v3, "getConstructors()Ljava/util/Collection;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/q72;Llyiahf/vczjk/jd7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/ce4;)V
    .locals 2

    const-string v0, "storageManager"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "containingDeclaration"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "visibility"

    invoke-static {p5, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "proto"

    invoke-static {p6, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "nameResolver"

    invoke-static {p7, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "typeTable"

    invoke-static {p8, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "versionRequirementTable"

    invoke-static {p9, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    const-string v1, "storageManager"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "containingDeclaration"

    invoke-static {p2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "visibilityImpl"

    invoke-static {p5, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p2, p3, p4, v0}, Llyiahf/vczjk/y02;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;)V

    iput-object p1, p0, Llyiahf/vczjk/v82;->OooOo00:Llyiahf/vczjk/q45;

    iput-object p5, p0, Llyiahf/vczjk/v82;->OooOo0:Llyiahf/vczjk/q72;

    new-instance p2, Llyiahf/vczjk/o0oOOo;

    const/4 p3, 0x0

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q45;->OooO00o(Llyiahf/vczjk/le3;)Llyiahf/vczjk/o45;

    new-instance p1, Llyiahf/vczjk/o0O0o;

    invoke-direct {p1, p0}, Llyiahf/vczjk/o0O0o;-><init>(Llyiahf/vczjk/v82;)V

    iput-object p1, p0, Llyiahf/vczjk/v82;->OooOo0o:Llyiahf/vczjk/o0O0o;

    iput-object p6, p0, Llyiahf/vczjk/v82;->OooOo:Llyiahf/vczjk/jd7;

    iput-object p7, p0, Llyiahf/vczjk/v82;->OooOoO0:Llyiahf/vczjk/rt5;

    iput-object p8, p0, Llyiahf/vczjk/v82;->OooOoO:Llyiahf/vczjk/h87;

    iput-object p9, p0, Llyiahf/vczjk/v82;->OooOoOO:Llyiahf/vczjk/xea;

    iput-object p10, p0, Llyiahf/vczjk/v82;->OooOoo0:Llyiahf/vczjk/ce4;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/gz0;
    .locals 0

    return-object p0
.end method

.method public final OooO00o()Llyiahf/vczjk/v02;
    .locals 0

    return-object p0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/q72;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v82;->OooOo0:Llyiahf/vczjk/q72;

    return-object v0
.end method

.method public final OooO0o0(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/x02;
    .locals 12

    const-string v0, "substitutor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p1, Llyiahf/vczjk/i5a;->OooO00o:Llyiahf/vczjk/g5a;

    invoke-virtual {v0}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v0

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/v82;

    invoke-virtual {p0}, Llyiahf/vczjk/y02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v3

    const-string v0, "getContainingDeclaration(...)"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v4

    const-string v0, "<get-annotations>(...)"

    invoke-static {v4, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v5

    const-string v0, "getName(...)"

    invoke-static {v5, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/v82;->OooOo00:Llyiahf/vczjk/q45;

    iget-object v8, p0, Llyiahf/vczjk/v82;->OooOoO0:Llyiahf/vczjk/rt5;

    iget-object v9, p0, Llyiahf/vczjk/v82;->OooOoO:Llyiahf/vczjk/h87;

    iget-object v6, p0, Llyiahf/vczjk/v82;->OooOo0:Llyiahf/vczjk/q72;

    iget-object v7, p0, Llyiahf/vczjk/v82;->OooOo:Llyiahf/vczjk/jd7;

    iget-object v10, p0, Llyiahf/vczjk/v82;->OooOoOO:Llyiahf/vczjk/xea;

    iget-object v11, p0, Llyiahf/vczjk/v82;->OooOoo0:Llyiahf/vczjk/ce4;

    invoke-direct/range {v1 .. v11}, Llyiahf/vczjk/v82;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/q72;Llyiahf/vczjk/jd7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/ce4;)V

    invoke-virtual {p0}, Llyiahf/vczjk/v82;->OooOo00()Ljava/util/List;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/v82;->o000OO()Llyiahf/vczjk/dp8;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/i5a;->OooO0oO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/vt6;->OooOOOO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object v2

    invoke-virtual {p0}, Llyiahf/vczjk/v82;->o0000O0O()Llyiahf/vczjk/dp8;

    move-result-object v4

    invoke-virtual {p1, v4, v3}, Llyiahf/vczjk/i5a;->OooO0oO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/vt6;->OooOOOO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-virtual {v1, v0, v2, p1}, Llyiahf/vczjk/v82;->o0000O(Ljava/util/List;Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V

    return-object v1
.end method

.method public final OooOOOo()Llyiahf/vczjk/dp8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v82;->Oooo000:Llyiahf/vczjk/dp8;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const-string v0, "defaultTypeImpl"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOo00()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v82;->OooOo0O:Ljava/util/List;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const-string v0, "declaredTypeParametersImpl"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOo0O()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo0o()Llyiahf/vczjk/n3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v82;->OooOo0o:Llyiahf/vczjk/o0O0o;

    return-object v0
.end method

.method public final OooOooo()Llyiahf/vczjk/pi5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v82;->OooOo:Llyiahf/vczjk/jd7;

    return-object v0
.end method

.method public final Oooo0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0O0()Z
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/v82;->o000OO()Llyiahf/vczjk/dp8;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/oo000o;

    const/4 v2, 0x4

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    const/4 v2, 0x0

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/l5a;->OooO0OO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dt8;)Z

    move-result v0

    return v0
.end method

.method public final OoooO0O()Llyiahf/vczjk/h87;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v82;->OooOoO:Llyiahf/vczjk/h87;

    return-object v0
.end method

.method public final OoooOo0()Llyiahf/vczjk/rt5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v82;->OooOoO0:Llyiahf/vczjk/rt5;

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/z02;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p1, p0, p2}, Llyiahf/vczjk/z02;->OooO00o(Llyiahf/vczjk/v82;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final Ooooo0o()Llyiahf/vczjk/j82;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v82;->OooOoo0:Llyiahf/vczjk/ce4;

    return-object v0
.end method

.method public final o0000O(Ljava/util/List;Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V
    .locals 6

    const-string v0, "underlyingType"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "expandedType"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/v82;->OooOo0O:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/v82;->OooOoo:Llyiahf/vczjk/dp8;

    iput-object p3, p0, Llyiahf/vczjk/v82;->OooOooO:Llyiahf/vczjk/dp8;

    invoke-static {p0}, Llyiahf/vczjk/ht6;->OooOO0o(Llyiahf/vczjk/hz0;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/v82;->OooOooo:Ljava/util/List;

    invoke-virtual {p0}, Llyiahf/vczjk/v82;->o0000O0()Llyiahf/vczjk/by0;

    move-result-object p1

    if-eqz p1, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/by0;->o0OO00O()Llyiahf/vczjk/jg5;

    move-result-object p1

    if-nez p1, :cond_0

    goto :goto_1

    :cond_0
    :goto_0
    move-object v4, p1

    goto :goto_2

    :cond_1
    :goto_1
    sget-object p1, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    goto :goto_0

    :goto_2
    new-instance v5, Llyiahf/vczjk/m5a;

    invoke-direct {v5, p0}, Llyiahf/vczjk/m5a;-><init>(Llyiahf/vczjk/v82;)V

    sget-object p1, Llyiahf/vczjk/l5a;->OooO00o:Llyiahf/vczjk/rq2;

    invoke-static {p0}, Llyiahf/vczjk/uq2;->OooO0o(Llyiahf/vczjk/v02;)Z

    move-result p1

    if-eqz p1, :cond_2

    sget-object p1, Llyiahf/vczjk/tq2;->OooOo0:Llyiahf/vczjk/tq2;

    invoke-virtual {p0}, Llyiahf/vczjk/v82;->toString()Ljava/lang/String;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/String;

    move-result-object p2

    invoke-static {p1, p2}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object p1

    goto :goto_3

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/v82;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v1

    if-eqz v1, :cond_3

    move-object p1, v1

    check-cast p1, Llyiahf/vczjk/o0O0o;

    invoke-virtual {p1}, Llyiahf/vczjk/o0O0o;->OooO0OO()Ljava/util/List;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/l5a;->OooO0Oo(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    sget-object p1, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    const/4 v3, 0x0

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/so8;->Oooo(Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Ljava/util/List;ZLlyiahf/vczjk/jg5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/dp8;

    move-result-object p1

    :goto_3
    iput-object p1, p0, Llyiahf/vczjk/v82;->Oooo000:Llyiahf/vczjk/dp8;

    return-void

    :cond_3
    const/16 p1, 0xc

    invoke-static {p1}, Llyiahf/vczjk/l5a;->OooO00o(I)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final o0000O0()Llyiahf/vczjk/by0;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/v82;->o0000O0O()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/v82;->o0000O0O()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/by0;

    if-eqz v1, :cond_1

    check-cast v0, Llyiahf/vczjk/by0;

    return-object v0

    :cond_1
    :goto_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final o0000O0O()Llyiahf/vczjk/dp8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v82;->OooOooO:Llyiahf/vczjk/dp8;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const-string v0, "expandedType"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final o0000oO()Llyiahf/vczjk/x02;
    .locals 0

    return-object p0
.end method

.method public final o000OO()Llyiahf/vczjk/dp8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v82;->OooOoo:Llyiahf/vczjk/dp8;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const-string v0, "underlyingType"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final oo0o0Oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "typealias "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
