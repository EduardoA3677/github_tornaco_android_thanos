.class public final Llyiahf/vczjk/nf3;
.super Llyiahf/vczjk/oo0o0Oo;
.source "SourceFile"


# static fields
.field public static final OooOo:Llyiahf/vczjk/hy0;

.field public static final OooOoO0:Llyiahf/vczjk/hy0;


# instance fields
.field public final OooOOo:Llyiahf/vczjk/hk0;

.field public final OooOOo0:Llyiahf/vczjk/q45;

.field public final OooOOoo:Llyiahf/vczjk/bg3;

.field public final OooOo0:Llyiahf/vczjk/mf3;

.field public final OooOo00:I

.field public final OooOo0O:Llyiahf/vczjk/pf3;

.field public final OooOo0o:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/hy0;

    sget-object v1, Llyiahf/vczjk/x09;->OooOO0o:Llyiahf/vczjk/hc3;

    const-string v2, "Function"

    invoke-static {v2}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    sput-object v0, Llyiahf/vczjk/nf3;->OooOo:Llyiahf/vczjk/hy0;

    new-instance v0, Llyiahf/vczjk/hy0;

    sget-object v1, Llyiahf/vczjk/x09;->OooO:Llyiahf/vczjk/hc3;

    const-string v2, "KFunction"

    invoke-static {v2}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    sput-object v0, Llyiahf/vczjk/nf3;->OooOoO0:Llyiahf/vczjk/hy0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/hk0;Llyiahf/vczjk/bg3;I)V
    .locals 3

    const-string v0, "containingDeclaration"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p3, p4}, Llyiahf/vczjk/bg3;->OooO00o(I)Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/oo0o0Oo;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/qt5;)V

    iput-object p1, p0, Llyiahf/vczjk/nf3;->OooOOo0:Llyiahf/vczjk/q45;

    iput-object p2, p0, Llyiahf/vczjk/nf3;->OooOOo:Llyiahf/vczjk/hk0;

    iput-object p3, p0, Llyiahf/vczjk/nf3;->OooOOoo:Llyiahf/vczjk/bg3;

    iput p4, p0, Llyiahf/vczjk/nf3;->OooOo00:I

    new-instance p2, Llyiahf/vczjk/mf3;

    invoke-direct {p2, p0}, Llyiahf/vczjk/mf3;-><init>(Llyiahf/vczjk/nf3;)V

    iput-object p2, p0, Llyiahf/vczjk/nf3;->OooOo0:Llyiahf/vczjk/mf3;

    new-instance p2, Llyiahf/vczjk/pf3;

    invoke-direct {p2, p1, p0}, Llyiahf/vczjk/kh3;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/oo0o0Oo;)V

    iput-object p2, p0, Llyiahf/vczjk/nf3;->OooOo0O:Llyiahf/vczjk/pf3;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    new-instance p2, Llyiahf/vczjk/x14;

    const/4 p3, 0x1

    invoke-direct {p2, p3, p4, p3}, Llyiahf/vczjk/v14;-><init>(III)V

    new-instance p3, Ljava/util/ArrayList;

    const/16 p4, 0xa

    invoke-static {p2, p4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result p4

    invoke-direct {p3, p4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {p2}, Llyiahf/vczjk/v14;->OooO00o()Llyiahf/vczjk/w14;

    move-result-object p2

    :goto_0
    iget-boolean p4, p2, Llyiahf/vczjk/w14;->OooOOOO:Z

    if-eqz p4, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/n14;->OooO00o()I

    move-result p4

    sget-object v0, Llyiahf/vczjk/cda;->OooOOO:Llyiahf/vczjk/cda;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "P"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p4

    invoke-static {p4}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p4

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/nf3;->OooOOo0:Llyiahf/vczjk/q45;

    invoke-static {p0, v0, p4, v1, v2}, Llyiahf/vczjk/u4a;->o0000O(Llyiahf/vczjk/oo0o0Oo;Llyiahf/vczjk/cda;Llyiahf/vczjk/qt5;ILlyiahf/vczjk/q45;)Llyiahf/vczjk/u4a;

    move-result-object p4

    invoke-virtual {p1, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    sget-object p4, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p3, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    sget-object p2, Llyiahf/vczjk/cda;->OooOOOO:Llyiahf/vczjk/cda;

    const-string p3, "R"

    invoke-static {p3}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p3

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result p4

    iget-object v0, p0, Llyiahf/vczjk/nf3;->OooOOo0:Llyiahf/vczjk/q45;

    invoke-static {p0, p2, p3, p4, v0}, Llyiahf/vczjk/u4a;->o0000O(Llyiahf/vczjk/oo0o0Oo;Llyiahf/vczjk/cda;Llyiahf/vczjk/qt5;ILlyiahf/vczjk/q45;)Llyiahf/vczjk/u4a;

    move-result-object p2

    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-static {p1}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nf3;->OooOo0o:Ljava/util/List;

    sget-object p1, Llyiahf/vczjk/of3;->OooOOO0:Llyiahf/vczjk/tp3;

    iget-object p2, p0, Llyiahf/vczjk/nf3;->OooOOoo:Llyiahf/vczjk/bg3;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string p1, "functionTypeKind"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/xf3;->OooO0OO:Llyiahf/vczjk/xf3;

    invoke-virtual {p2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    goto :goto_1

    :cond_1
    sget-object p1, Llyiahf/vczjk/ag3;->OooO0OO:Llyiahf/vczjk/ag3;

    invoke-virtual {p2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    goto :goto_1

    :cond_2
    sget-object p1, Llyiahf/vczjk/yf3;->OooO0OO:Llyiahf/vczjk/yf3;

    invoke-virtual {p2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_3

    goto :goto_1

    :cond_3
    sget-object p1, Llyiahf/vczjk/zf3;->OooO0OO:Llyiahf/vczjk/zf3;

    invoke-virtual {p2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    :goto_1
    return-void
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/yk5;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yk5;->OooOOo0:Llyiahf/vczjk/yk5;

    return-object v0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/q72;
    .locals 2

    sget-object v0, Llyiahf/vczjk/r72;->OooO0o0:Llyiahf/vczjk/q72;

    const-string v1, "PUBLIC"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooO0o()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/sx8;
    .locals 1

    sget-object v0, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    return-object v0
.end method

.method public final OooOO0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOO0o()Llyiahf/vczjk/v02;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nf3;->OooOOo:Llyiahf/vczjk/hk0;

    return-object v0
.end method

.method public final OooOOo0()Llyiahf/vczjk/ko;
    .locals 1

    sget-object v0, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    return-object v0
.end method

.method public final OooOo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo00()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nf3;->OooOo0o:Ljava/util/List;

    return-object v0
.end method

.method public final OooOo0O()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo0o()Llyiahf/vczjk/n3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nf3;->OooOo0:Llyiahf/vczjk/mf3;

    return-object v0
.end method

.method public final bridge synthetic OooOoO()Ljava/util/Collection;
    .locals 1

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object v0
.end method

.method public final OooOoo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final bridge synthetic Oooo00o()Ljava/util/Collection;
    .locals 1

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object v0
.end method

.method public final Oooo0O0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0oO(Llyiahf/vczjk/al4;)Llyiahf/vczjk/jg5;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/nf3;->OooOo0O:Llyiahf/vczjk/pf3;

    return-object p1
.end method

.method public final bridge synthetic OoooO0()Llyiahf/vczjk/jg5;
    .locals 1

    sget-object v0, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    return-object v0
.end method

.method public final bridge synthetic OoooO00()Llyiahf/vczjk/ux0;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final getKind()Llyiahf/vczjk/ly0;
    .locals 1

    sget-object v0, Llyiahf/vczjk/ly0;->OooOOO:Llyiahf/vczjk/ly0;

    return-object v0
.end method

.method public final o000000O()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o0ooOOo()Llyiahf/vczjk/fca;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final oo0o0Oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/oo0o0Oo;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    const-string v1, "asString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method
