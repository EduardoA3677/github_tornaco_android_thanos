.class public final Llyiahf/vczjk/nd4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/n1;
.implements Llyiahf/vczjk/cx6;


# static fields
.field public static final synthetic OooOo00:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/o45;

.field public final OooOOO0:Llyiahf/vczjk/dm5;

.field public final OooOOOO:Llyiahf/vczjk/dp8;

.field public final OooOOOo:Llyiahf/vczjk/o45;

.field public final OooOOo:Llyiahf/vczjk/o45;

.field public final OooOOo0:Llyiahf/vczjk/l45;

.field public final OooOOoo:Llyiahf/vczjk/l45;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/nd4;

    const-string v2, "settings"

    const-string v3, "getSettings()Lorg/jetbrains/kotlin/builtins/jvm/JvmBuiltIns$Settings;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const-string v3, "cloneableType"

    const-string v5, "getCloneableType()Lorg/jetbrains/kotlin/types/SimpleType;"

    invoke-static {v1, v3, v5, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v3

    const-string v5, "notConsideredDeprecation"

    const-string v6, "getNotConsideredDeprecation()Lorg/jetbrains/kotlin/descriptors/annotations/Annotations;"

    invoke-static {v1, v5, v6, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v1

    const/4 v2, 0x3

    new-array v2, v2, [Llyiahf/vczjk/th4;

    aput-object v0, v2, v4

    const/4 v0, 0x1

    aput-object v3, v2, v0

    const/4 v0, 0x2

    aput-object v1, v2, v0

    sput-object v2, Llyiahf/vczjk/nd4;->OooOo00:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/dm5;Llyiahf/vczjk/q45;Llyiahf/vczjk/o0oOOo;)V
    .locals 8

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/nd4;->OooOOO0:Llyiahf/vczjk/dm5;

    new-instance v0, Llyiahf/vczjk/o45;

    invoke-direct {v0, p2, p3}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Llyiahf/vczjk/nd4;->OooOOO:Llyiahf/vczjk/o45;

    new-instance p3, Llyiahf/vczjk/hc3;

    const-string v0, "java.io"

    invoke-direct {p3, v0}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/dn2;

    const/4 v0, 0x1

    invoke-direct {v2, p1, p3, v0}, Llyiahf/vczjk/dn2;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;I)V

    new-instance p1, Llyiahf/vczjk/zw4;

    new-instance p3, Llyiahf/vczjk/kd4;

    const/4 v0, 0x1

    invoke-direct {p3, p0, v0}, Llyiahf/vczjk/kd4;-><init>(Llyiahf/vczjk/nd4;I)V

    invoke-direct {p1, p2, p3}, Llyiahf/vczjk/zw4;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v6

    new-instance v1, Llyiahf/vczjk/ey0;

    const-string p1, "Serializable"

    invoke-static {p1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/yk5;->OooOOo0:Llyiahf/vczjk/yk5;

    sget-object v5, Llyiahf/vczjk/ly0;->OooOOO:Llyiahf/vczjk/ly0;

    move-object v7, p2

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/ey0;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/qt5;Llyiahf/vczjk/yk5;Llyiahf/vczjk/ly0;Ljava/util/List;Llyiahf/vczjk/q45;)V

    sget-object p1, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    sget-object p2, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    const/4 p3, 0x0

    invoke-virtual {v1, p1, p2, p3}, Llyiahf/vczjk/ey0;->o00ooo(Llyiahf/vczjk/jg5;Ljava/util/Set;Llyiahf/vczjk/ux0;)V

    invoke-virtual {v1}, Llyiahf/vczjk/oo0o0Oo;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nd4;->OooOOOO:Llyiahf/vczjk/dp8;

    new-instance p1, Llyiahf/vczjk/o0O000;

    const/16 p2, 0x11

    const/4 p3, 0x0

    invoke-direct {p1, p2, p0, v7, p3}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    new-instance p2, Llyiahf/vczjk/o45;

    invoke-direct {p2, v7, p1}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p2, p0, Llyiahf/vczjk/nd4;->OooOOOo:Llyiahf/vczjk/o45;

    new-instance p1, Llyiahf/vczjk/l45;

    new-instance p2, Ljava/util/concurrent/ConcurrentHashMap;

    const/high16 p3, 0x3f800000    # 1.0f

    const/4 v0, 0x2

    const/4 v1, 0x3

    invoke-direct {p2, v1, p3, v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>(IFI)V

    new-instance p3, Llyiahf/vczjk/m5a;

    const/4 v0, 0x4

    invoke-direct {p3, v0}, Llyiahf/vczjk/m5a;-><init>(I)V

    const/4 v0, 0x0

    invoke-direct {p1, v7, p2, p3, v0}, Llyiahf/vczjk/l45;-><init>(Llyiahf/vczjk/q45;Ljava/util/concurrent/ConcurrentHashMap;Llyiahf/vczjk/oe3;I)V

    iput-object p1, p0, Llyiahf/vczjk/nd4;->OooOOo0:Llyiahf/vczjk/l45;

    new-instance p1, Llyiahf/vczjk/kd4;

    const/4 p2, 0x0

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/kd4;-><init>(Llyiahf/vczjk/nd4;I)V

    new-instance p2, Llyiahf/vczjk/o45;

    invoke-direct {p2, v7, p1}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p2, p0, Llyiahf/vczjk/nd4;->OooOOo:Llyiahf/vczjk/o45;

    new-instance p1, Llyiahf/vczjk/ld4;

    const/4 p2, 0x0

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/ld4;-><init>(Llyiahf/vczjk/nd4;I)V

    invoke-virtual {v7, p1}, Llyiahf/vczjk/q45;->OooO0O0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/l45;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nd4;->OooOOoo:Llyiahf/vczjk/l45;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/by0;)Llyiahf/vczjk/nr4;
    .locals 3

    const/4 v0, 0x0

    if-eqz p1, :cond_5

    sget-object v1, Llyiahf/vczjk/w09;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-static {p1, v1}, Llyiahf/vczjk/hk4;->OooO0O0(Llyiahf/vczjk/by0;Llyiahf/vczjk/ic3;)Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/hk4;->Oooo0O0(Llyiahf/vczjk/gz0;)Z

    move-result v1

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/p72;->OooO0oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ic3;->OooO0Oo()Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_0

    :cond_2
    sget-object v1, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    invoke-static {p1}, Llyiahf/vczjk/w64;->OooO0o(Llyiahf/vczjk/ic3;)Llyiahf/vczjk/hy0;

    move-result-object p1

    if-eqz p1, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object p1

    if-nez p1, :cond_3

    goto :goto_0

    :cond_3
    invoke-virtual {p0}, Llyiahf/vczjk/nd4;->OooO0O0()Llyiahf/vczjk/id4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/id4;->OooO00o:Llyiahf/vczjk/dm5;

    sget-object v2, Llyiahf/vczjk/h16;->OooOOO0:Llyiahf/vczjk/h16;

    invoke-static {v1, p1}, Llyiahf/vczjk/l4a;->Oooo00o(Llyiahf/vczjk/dm5;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/by0;

    move-result-object p1

    instance-of v1, p1, Llyiahf/vczjk/nr4;

    if-eqz v1, :cond_4

    check-cast p1, Llyiahf/vczjk/nr4;

    return-object p1

    :cond_4
    :goto_0
    return-object v0

    :cond_5
    const/16 p1, 0x6c

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    throw v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/id4;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/nd4;->OooOOO:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/nd4;->OooOo00:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    invoke-static {v0, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/id4;

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/by0;Llyiahf/vczjk/u82;)Z
    .locals 3

    const-string v0, "classDescriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nd4;->OooO00o(Llyiahf/vczjk/by0;)Llyiahf/vczjk/nr4;

    move-result-object p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/dx6;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-interface {v0, v1}, Llyiahf/vczjk/ko;->OooO0o0(Llyiahf/vczjk/hc3;)Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/nd4;->OooO0O0()Llyiahf/vczjk/id4;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v0, 0x3

    invoke-static {p2, v0}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/nr4;->o00ooo()Llyiahf/vczjk/rr4;

    move-result-object p1

    invoke-virtual {p2}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p2

    const-string v2, "getName(...)"

    invoke-static {p2, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/h16;->OooOOO0:Llyiahf/vczjk/h16;

    invoke-virtual {p1, p2, v2}, Llyiahf/vczjk/rr4;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    instance-of p2, p1, Ljava/util/Collection;

    if-eqz p2, :cond_2

    move-object p2, p1

    check-cast p2, Ljava/util/Collection;

    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result p2

    if-eqz p2, :cond_2

    goto :goto_1

    :cond_2
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/ho8;

    invoke-static {p2, v0}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object p2

    invoke-static {p2, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_3

    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_4
    :goto_1
    const/4 p1, 0x0

    return p1
.end method

.method public final Oooo(Llyiahf/vczjk/by0;)Ljava/util/Collection;
    .locals 1

    const-string v0, "classDescriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/nd4;->OooO0O0()Llyiahf/vczjk/id4;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nd4;->OooO00o(Llyiahf/vczjk/by0;)Llyiahf/vczjk/nr4;

    move-result-object p1

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/nr4;->o00ooo()Llyiahf/vczjk/rr4;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ds4;->OooO00o()Ljava/util/Set;

    move-result-object p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    move-object v0, p1

    :cond_1
    :goto_0
    check-cast v0, Ljava/util/Collection;

    return-object v0
.end method

.method public final Oooo0oO(Llyiahf/vczjk/qt5;Llyiahf/vczjk/by0;)Ljava/util/Collection;
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    const/4 v3, 0x2

    const/4 v4, 0x0

    const/4 v5, 0x1

    const-string v6, "name"

    invoke-static {v1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v6, "classDescriptor"

    invoke-static {v2, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v6, Llyiahf/vczjk/g01;->OooO0o0:Llyiahf/vczjk/qt5;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/qt5;->equals(Ljava/lang/Object;)Z

    move-result v6

    sget-object v7, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sget-object v8, Llyiahf/vczjk/nd4;->OooOo00:[Llyiahf/vczjk/th4;

    if-eqz v6, :cond_4

    instance-of v6, v2, Llyiahf/vczjk/h82;

    if-eqz v6, :cond_4

    sget-object v6, Llyiahf/vczjk/w09;->OooO0oO:Llyiahf/vczjk/ic3;

    invoke-static {v2, v6}, Llyiahf/vczjk/hk4;->OooO0O0(Llyiahf/vczjk/by0;Llyiahf/vczjk/ic3;)Z

    move-result v6

    if-nez v6, :cond_0

    invoke-static {v2}, Llyiahf/vczjk/hk4;->OooOOoo(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/q47;

    move-result-object v6

    if-eqz v6, :cond_4

    :cond_0
    check-cast v2, Llyiahf/vczjk/h82;

    iget-object v3, v2, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-virtual {v3}, Llyiahf/vczjk/zb7;->ooOO()Ljava/util/List;

    move-result-object v3

    const-string v4, "getFunctionList(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v4

    if-eqz v4, :cond_1

    goto :goto_0

    :cond_1
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_3

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/pc7;

    iget-object v6, v2, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    iget-object v6, v6, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/rt5;

    invoke-virtual {v4}, Llyiahf/vczjk/pc7;->Oooo0oO()I

    move-result v4

    invoke-static {v6, v4}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v4

    sget-object v6, Llyiahf/vczjk/g01;->OooO0o0:Llyiahf/vczjk/qt5;

    invoke-virtual {v4, v6}, Llyiahf/vczjk/qt5;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2

    return-object v7

    :cond_3
    :goto_0
    iget-object v3, v0, Llyiahf/vczjk/nd4;->OooOOOo:Llyiahf/vczjk/o45;

    aget-object v4, v8, v5

    invoke-static {v3, v4}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/dp8;

    invoke-virtual {v3}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/h16;->OooOOO0:Llyiahf/vczjk/h16;

    invoke-interface {v3, v1, v4}, Llyiahf/vczjk/jg5;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object v1

    check-cast v1, Ljava/lang/Iterable;

    invoke-static {v1}, Llyiahf/vczjk/d21;->o00000Oo(Ljava/lang/Iterable;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ho8;

    invoke-interface {v1}, Llyiahf/vczjk/rf3;->o0Oo0oo()Llyiahf/vczjk/qf3;

    move-result-object v1

    invoke-interface {v1, v2}, Llyiahf/vczjk/qf3;->OooO0Oo(Llyiahf/vczjk/by0;)Llyiahf/vczjk/qf3;

    sget-object v3, Llyiahf/vczjk/r72;->OooO0o0:Llyiahf/vczjk/q72;

    invoke-interface {v1, v3}, Llyiahf/vczjk/qf3;->o000oOoO(Llyiahf/vczjk/q72;)Llyiahf/vczjk/qf3;

    invoke-virtual {v2}, Llyiahf/vczjk/oo0o0Oo;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v3

    invoke-interface {v1, v3}, Llyiahf/vczjk/qf3;->OooOoO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/qf3;

    invoke-virtual {v2}, Llyiahf/vczjk/oo0o0Oo;->o00000()Llyiahf/vczjk/mp4;

    move-result-object v2

    invoke-interface {v1, v2}, Llyiahf/vczjk/qf3;->Oooo0o(Llyiahf/vczjk/mp4;)Llyiahf/vczjk/qf3;

    invoke-interface {v1}, Llyiahf/vczjk/qf3;->build()Llyiahf/vczjk/rf3;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v1, Llyiahf/vczjk/ho8;

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    return-object v1

    :cond_4
    invoke-virtual {v0}, Llyiahf/vczjk/nd4;->OooO0O0()Llyiahf/vczjk/id4;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/nd4;->OooO00o(Llyiahf/vczjk/by0;)Llyiahf/vczjk/nr4;

    move-result-object v6

    const/4 v10, 0x3

    const-string v11, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ClassDescriptor"

    if-nez v6, :cond_5

    :goto_1
    const/16 v16, 0x0

    goto/16 :goto_c

    :cond_5
    invoke-static {v6}, Llyiahf/vczjk/p72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hc3;

    move-result-object v12

    sget-object v13, Llyiahf/vczjk/uv2;->OooO0o:Llyiahf/vczjk/uv2;

    const-string v14, "builtIns"

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v12, v13}, Llyiahf/vczjk/e86;->OooOOOo(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hk4;)Llyiahf/vczjk/by0;

    move-result-object v12

    if-nez v12, :cond_6

    sget-object v12, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    goto :goto_2

    :cond_6
    sget-object v14, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    invoke-static {v12}, Llyiahf/vczjk/p72;->OooO0oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object v14

    sget-object v15, Llyiahf/vczjk/w64;->OooOO0O:Ljava/util/HashMap;

    invoke-virtual {v15, v14}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/hc3;

    if-nez v14, :cond_7

    invoke-static {v12}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v12

    check-cast v12, Ljava/util/Collection;

    goto :goto_2

    :cond_7
    invoke-virtual {v13, v14}, Llyiahf/vczjk/hk4;->OooOO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/by0;

    move-result-object v13

    new-array v14, v3, [Llyiahf/vczjk/by0;

    aput-object v12, v14, v4

    aput-object v13, v14, v5

    invoke-static {v14}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v12

    :goto_2
    check-cast v12, Ljava/lang/Iterable;

    instance-of v13, v12, Ljava/util/List;

    if-eqz v13, :cond_9

    move-object v13, v12

    check-cast v13, Ljava/util/List;

    invoke-interface {v13}, Ljava/util/List;->isEmpty()Z

    move-result v14

    if-eqz v14, :cond_8

    :goto_3
    const/4 v13, 0x0

    goto :goto_5

    :cond_8
    invoke-interface {v13}, Ljava/util/List;->size()I

    move-result v14

    sub-int/2addr v14, v5

    invoke-interface {v13, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v13

    goto :goto_5

    :cond_9
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v13

    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    move-result v14

    if-nez v14, :cond_a

    goto :goto_3

    :cond_a
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v14

    :goto_4
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    move-result v15

    if-eqz v15, :cond_b

    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v14

    goto :goto_4

    :cond_b
    move-object v13, v14

    :goto_5
    check-cast v13, Llyiahf/vczjk/by0;

    if-nez v13, :cond_c

    goto :goto_1

    :cond_c
    sget v7, Llyiahf/vczjk/dt8;->OooOOOO:I

    new-instance v7, Ljava/util/ArrayList;

    const/16 v14, 0xa

    invoke-static {v12, v14}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v14

    invoke-direct {v7, v14}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v12

    :goto_6
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    move-result v14

    if-eqz v14, :cond_d

    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/by0;

    invoke-static {v14}, Llyiahf/vczjk/p72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hc3;

    move-result-object v14

    invoke-virtual {v7, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_d
    new-instance v12, Llyiahf/vczjk/dt8;

    invoke-direct {v12}, Llyiahf/vczjk/dt8;-><init>()V

    invoke-virtual {v12, v7}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    sget-object v7, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    invoke-static {v2}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object v7

    sget-object v14, Llyiahf/vczjk/w64;->OooOO0:Ljava/util/HashMap;

    invoke-virtual {v14, v7}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v7

    invoke-static {v6}, Llyiahf/vczjk/p72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hc3;

    move-result-object v14

    new-instance v15, Llyiahf/vczjk/o0O000;

    const/16 v16, 0x0

    const/16 v9, 0x12

    invoke-direct {v15, v9, v6, v13, v4}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    iget-object v6, v0, Llyiahf/vczjk/nd4;->OooOOo0:Llyiahf/vczjk/l45;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v9, Llyiahf/vczjk/m45;

    invoke-direct {v9, v14, v15}, Llyiahf/vczjk/m45;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/le3;)V

    invoke-virtual {v6, v9}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    if-eqz v6, :cond_23

    check-cast v6, Llyiahf/vczjk/by0;

    invoke-interface {v6}, Llyiahf/vczjk/by0;->o0OO00O()Llyiahf/vczjk/jg5;

    move-result-object v6

    const-string v9, "getUnsubstitutedMemberScope(...)"

    invoke-static {v6, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v9, Llyiahf/vczjk/h16;->OooOOO0:Llyiahf/vczjk/h16;

    invoke-interface {v6, v1, v9}, Llyiahf/vczjk/jg5;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object v1

    check-cast v1, Ljava/lang/Iterable;

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_17

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    move-object v13, v9

    check-cast v13, Llyiahf/vczjk/ho8;

    invoke-virtual {v13}, Llyiahf/vczjk/tf3;->getKind()I

    move-result v14

    if-eq v14, v5, :cond_e

    goto/16 :goto_b

    :cond_e
    invoke-virtual {v13}, Llyiahf/vczjk/tf3;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v14

    iget-object v14, v14, Llyiahf/vczjk/q72;->OooO00o:Llyiahf/vczjk/oO0Oo0oo;

    iget-boolean v14, v14, Llyiahf/vczjk/oO0Oo0oo;->OooOOO:Z

    if-nez v14, :cond_f

    goto/16 :goto_b

    :cond_f
    invoke-static {v13}, Llyiahf/vczjk/hk4;->OooOooO(Llyiahf/vczjk/rf3;)Z

    move-result v14

    if-eqz v14, :cond_10

    goto/16 :goto_b

    :cond_10
    invoke-virtual {v13}, Llyiahf/vczjk/tf3;->OooOOO0()Ljava/util/Collection;

    move-result-object v14

    check-cast v14, Ljava/lang/Iterable;

    instance-of v15, v14, Ljava/util/Collection;

    if-eqz v15, :cond_11

    move-object v15, v14

    check-cast v15, Ljava/util/Collection;

    invoke-interface {v15}, Ljava/util/Collection;->isEmpty()Z

    move-result v15

    if-eqz v15, :cond_11

    goto :goto_9

    :cond_11
    invoke-interface {v14}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v14

    :goto_8
    invoke-interface {v14}, Ljava/util/Iterator;->hasNext()Z

    move-result v15

    if-eqz v15, :cond_14

    invoke-interface {v14}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/rf3;

    invoke-interface {v15}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v15

    const-string v4, "getContainingDeclaration(...)"

    invoke-static {v15, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v15}, Llyiahf/vczjk/p72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hc3;

    move-result-object v4

    invoke-virtual {v12, v4}, Llyiahf/vczjk/dt8;->contains(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_13

    :cond_12
    const/4 v4, 0x0

    goto :goto_b

    :cond_13
    const/4 v4, 0x0

    goto :goto_8

    :cond_14
    :goto_9
    invoke-virtual {v13}, Llyiahf/vczjk/y02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v4

    invoke-static {v4, v11}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v4, Llyiahf/vczjk/by0;

    invoke-static {v13, v10}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v14

    sget-object v15, Llyiahf/vczjk/qd4;->OooO0o0:Ljava/util/LinkedHashSet;

    invoke-static {v4, v14}, Llyiahf/vczjk/t51;->OoooOoO(Llyiahf/vczjk/by0;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    invoke-interface {v15, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v4

    xor-int/2addr v4, v7

    if-eqz v4, :cond_15

    move v4, v5

    goto :goto_a

    :cond_15
    invoke-static {v13}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    sget-object v13, Llyiahf/vczjk/xj0;->OooOOoo:Llyiahf/vczjk/xj0;

    new-instance v14, Llyiahf/vczjk/ld4;

    invoke-direct {v14, v0, v5}, Llyiahf/vczjk/ld4;-><init>(Llyiahf/vczjk/nd4;I)V

    invoke-static {v4, v13, v14}, Llyiahf/vczjk/jp8;->OooOoo(Ljava/util/List;Llyiahf/vczjk/rv1;Llyiahf/vczjk/oe3;)Ljava/lang/Boolean;

    move-result-object v4

    const-string v13, "ifAny(...)"

    invoke-static {v4, v13}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    :goto_a
    if-nez v4, :cond_12

    move v4, v5

    :goto_b
    if-eqz v4, :cond_16

    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_16
    const/4 v4, 0x0

    goto/16 :goto_7

    :cond_17
    move-object v7, v6

    :goto_c
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_18
    :goto_d
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_22

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/ho8;

    invoke-virtual {v6}, Llyiahf/vczjk/y02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v7

    invoke-static {v7, v11}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v7, Llyiahf/vczjk/by0;

    invoke-static {v7, v2}, Llyiahf/vczjk/r02;->OooOOO(Llyiahf/vczjk/by0;Llyiahf/vczjk/by0;)Llyiahf/vczjk/g19;

    move-result-object v7

    new-instance v9, Llyiahf/vczjk/i5a;

    invoke-direct {v9, v7}, Llyiahf/vczjk/i5a;-><init>(Llyiahf/vczjk/g5a;)V

    invoke-virtual {v6, v9}, Llyiahf/vczjk/tf3;->OooO0o0(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/rf3;

    move-result-object v7

    const-string v9, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.SimpleFunctionDescriptor"

    invoke-static {v7, v9}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v7, Llyiahf/vczjk/ho8;

    invoke-interface {v7}, Llyiahf/vczjk/rf3;->o0Oo0oo()Llyiahf/vczjk/qf3;

    move-result-object v7

    invoke-interface {v7, v2}, Llyiahf/vczjk/qf3;->OooO0Oo(Llyiahf/vczjk/by0;)Llyiahf/vczjk/qf3;

    invoke-interface {v2}, Llyiahf/vczjk/by0;->o00000()Llyiahf/vczjk/mp4;

    move-result-object v9

    invoke-interface {v7, v9}, Llyiahf/vczjk/qf3;->Oooo0o(Llyiahf/vczjk/mp4;)Llyiahf/vczjk/qf3;

    invoke-interface {v7}, Llyiahf/vczjk/qf3;->OooOOo()Llyiahf/vczjk/qf3;

    invoke-virtual {v6}, Llyiahf/vczjk/y02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v9

    invoke-static {v9, v11}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Llyiahf/vczjk/by0;

    invoke-static {v6, v10}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v12

    new-instance v13, Llyiahf/vczjk/hl7;

    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    invoke-static {v9}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v9

    new-instance v14, Llyiahf/vczjk/tg7;

    const/16 v15, 0x11

    invoke-direct {v14, v0, v15}, Llyiahf/vczjk/tg7;-><init>(Ljava/lang/Object;I)V

    new-instance v15, Llyiahf/vczjk/qv1;

    invoke-direct {v15, v12, v13, v3}, Llyiahf/vczjk/qv1;-><init>(Ljava/lang/Object;Ljava/io/Serializable;I)V

    invoke-static {v9, v14, v15}, Llyiahf/vczjk/jp8;->OooOo00(Ljava/util/List;Llyiahf/vczjk/rv1;Llyiahf/vczjk/so8;)Ljava/lang/Object;

    move-result-object v9

    const-string v12, "dfs(...)"

    invoke-static {v9, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Llyiahf/vczjk/md4;

    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    move-result v9

    if-eqz v9, :cond_1e

    if-eq v9, v5, :cond_21

    if-eq v9, v3, :cond_1b

    if-eq v9, v10, :cond_1a

    const/4 v6, 0x4

    if-ne v9, v6, :cond_19

    :goto_e
    move-object/from16 v6, v16

    goto/16 :goto_12

    :cond_19
    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1

    :cond_1a
    iget-object v6, v0, Llyiahf/vczjk/nd4;->OooOOo:Llyiahf/vczjk/o45;

    aget-object v9, v8, v3

    invoke-static {v6, v9}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/ko;

    invoke-interface {v7, v6}, Llyiahf/vczjk/qf3;->OooOOo0(Llyiahf/vczjk/ko;)Llyiahf/vczjk/qf3;

    goto/16 :goto_11

    :cond_1b
    invoke-virtual {v6}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v9

    sget-object v12, Llyiahf/vczjk/od4;->OooO00o:Llyiahf/vczjk/qt5;

    invoke-static {v9, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v12

    iget-object v13, v0, Llyiahf/vczjk/nd4;->OooOOoo:Llyiahf/vczjk/l45;

    if-eqz v12, :cond_1c

    invoke-virtual {v6}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v6

    invoke-virtual {v6}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v6

    new-instance v9, Llyiahf/vczjk/xn6;

    const-string v12, "first"

    invoke-direct {v9, v6, v12}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v13, v9}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/ko;

    goto :goto_f

    :cond_1c
    sget-object v12, Llyiahf/vczjk/od4;->OooO0O0:Llyiahf/vczjk/qt5;

    invoke-static {v9, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_1d

    invoke-virtual {v6}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v6

    invoke-virtual {v6}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v6

    new-instance v9, Llyiahf/vczjk/xn6;

    const-string v12, "last"

    invoke-direct {v9, v6, v12}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v13, v9}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/ko;

    :goto_f
    invoke-interface {v7, v6}, Llyiahf/vczjk/qf3;->OooOOo0(Llyiahf/vczjk/ko;)Llyiahf/vczjk/qf3;

    goto :goto_11

    :cond_1d
    new-instance v1, Ljava/lang/IllegalStateException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Unexpected name: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v6}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1e
    invoke-interface {v2}, Llyiahf/vczjk/by0;->OooO()Llyiahf/vczjk/yk5;

    move-result-object v6

    sget-object v9, Llyiahf/vczjk/yk5;->OooOOO:Llyiahf/vczjk/yk5;

    if-ne v6, v9, :cond_1f

    invoke-interface {v2}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v6

    sget-object v9, Llyiahf/vczjk/ly0;->OooOOOO:Llyiahf/vczjk/ly0;

    if-eq v6, v9, :cond_1f

    move v6, v5

    goto :goto_10

    :cond_1f
    const/4 v6, 0x0

    :goto_10
    if-eqz v6, :cond_20

    goto/16 :goto_e

    :cond_20
    invoke-interface {v7}, Llyiahf/vczjk/qf3;->OooOo0o()Llyiahf/vczjk/qf3;

    :cond_21
    :goto_11
    invoke-interface {v7}, Llyiahf/vczjk/qf3;->build()Llyiahf/vczjk/rf3;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v6, Llyiahf/vczjk/ho8;

    :goto_12
    if-eqz v6, :cond_18

    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto/16 :goto_d

    :cond_22
    return-object v1

    :cond_23
    invoke-static {v10}, Llyiahf/vczjk/l45;->OooO0oO(I)V

    throw v16
.end method

.method public final OoooOO0(Llyiahf/vczjk/by0;)Ljava/util/Collection;
    .locals 14

    const-string v0, "classDescriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ly0;->OooOOO0:Llyiahf/vczjk/ly0;

    sget-object v2, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    if-ne v0, v1, :cond_c

    invoke-virtual {p0}, Llyiahf/vczjk/nd4;->OooO0O0()Llyiahf/vczjk/id4;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nd4;->OooO00o(Llyiahf/vczjk/by0;)Llyiahf/vczjk/nr4;

    move-result-object v0

    if-nez v0, :cond_0

    goto/16 :goto_3

    :cond_0
    invoke-static {v0}, Llyiahf/vczjk/p72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hc3;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/uv2;->OooO0o:Llyiahf/vczjk/uv2;

    invoke-static {v1, v3}, Llyiahf/vczjk/e86;->OooOOOo(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hk4;)Llyiahf/vczjk/by0;

    move-result-object v1

    if-nez v1, :cond_1

    goto/16 :goto_3

    :cond_1
    invoke-static {v1, v0}, Llyiahf/vczjk/r02;->OooOOO(Llyiahf/vczjk/by0;Llyiahf/vczjk/by0;)Llyiahf/vczjk/g19;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/i5a;

    invoke-direct {v3, v2}, Llyiahf/vczjk/i5a;-><init>(Llyiahf/vczjk/g5a;)V

    iget-object v2, v0, Llyiahf/vczjk/nr4;->OooOoo:Llyiahf/vczjk/rr4;

    iget-object v2, v2, Llyiahf/vczjk/rr4;->OooOOo0:Llyiahf/vczjk/o45;

    invoke-virtual {v2}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/List;

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_2
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    const/4 v6, 0x0

    const/4 v7, 0x1

    const/4 v8, 0x3

    if-eqz v5, :cond_8

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    move-object v9, v5

    check-cast v9, Llyiahf/vczjk/ux0;

    move-object v10, v9

    check-cast v10, Llyiahf/vczjk/tf3;

    invoke-virtual {v10}, Llyiahf/vczjk/tf3;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v11

    iget-object v11, v11, Llyiahf/vczjk/q72;->OooO00o:Llyiahf/vczjk/oO0Oo0oo;

    iget-boolean v11, v11, Llyiahf/vczjk/oO0Oo0oo;->OooOOO:Z

    if-eqz v11, :cond_2

    invoke-interface {v1}, Llyiahf/vczjk/by0;->OooOoO()Ljava/util/Collection;

    move-result-object v11

    const-string v12, "getConstructors(...)"

    invoke-static {v11, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Ljava/lang/Iterable;

    instance-of v12, v11, Ljava/util/Collection;

    if-eqz v12, :cond_3

    move-object v12, v11

    check-cast v12, Ljava/util/Collection;

    invoke-interface {v12}, Ljava/util/Collection;->isEmpty()Z

    move-result v12

    if-eqz v12, :cond_3

    goto :goto_1

    :cond_3
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v11

    :cond_4
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    move-result v12

    if-eqz v12, :cond_5

    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/ux0;

    invoke-static {v12}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v9, v3}, Llyiahf/vczjk/ux0;->o0000oOO(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/ux0;

    move-result-object v13

    invoke-static {v12, v13}, Llyiahf/vczjk/ng6;->OooOO0(Llyiahf/vczjk/co0;Llyiahf/vczjk/co0;)I

    move-result v12

    if-ne v12, v7, :cond_4

    goto :goto_0

    :cond_5
    :goto_1
    invoke-virtual {v10}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v11

    invoke-interface {v11}, Ljava/util/List;->size()I

    move-result v11

    if-ne v11, v7, :cond_7

    invoke-virtual {v10}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v7

    const-string v10, "getValueParameters(...)"

    invoke-static {v7, v10}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v7}, Llyiahf/vczjk/d21;->o00000o0(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/tca;

    check-cast v7, Llyiahf/vczjk/bda;

    invoke-virtual {v7}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v7

    invoke-virtual {v7}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v7

    if-eqz v7, :cond_6

    invoke-static {v7}, Llyiahf/vczjk/p72;->OooO0oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object v6

    :cond_6
    invoke-static {p1}, Llyiahf/vczjk/p72;->OooO0oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_7

    goto/16 :goto_0

    :cond_7
    invoke-static {v9}, Llyiahf/vczjk/hk4;->OooOooO(Llyiahf/vczjk/rf3;)Z

    move-result v6

    if-nez v6, :cond_2

    sget-object v6, Llyiahf/vczjk/qd4;->OooO0o:Ljava/util/LinkedHashSet;

    invoke-static {v9, v8}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v7

    invoke-static {v0, v7}, Llyiahf/vczjk/t51;->OoooOoO(Llyiahf/vczjk/by0;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    invoke-interface {v6, v7}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_2

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto/16 :goto_0

    :cond_8
    new-instance v1, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {v4, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_b

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ux0;

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/tf3;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/i5a;->OooO0O0:Llyiahf/vczjk/i5a;

    invoke-virtual {v5, v9}, Llyiahf/vczjk/tf3;->o0000OOO(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/sf3;

    move-result-object v5

    iput-object p1, v5, Llyiahf/vczjk/sf3;->OooOOO:Llyiahf/vczjk/v02;

    invoke-interface {p1}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v9

    invoke-virtual {v5, v9}, Llyiahf/vczjk/sf3;->OooOoO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/qf3;

    iput-boolean v7, v5, Llyiahf/vczjk/sf3;->OooOoOO:Z

    invoke-virtual {v3}, Llyiahf/vczjk/i5a;->OooO0o()Llyiahf/vczjk/g5a;

    move-result-object v9

    if-eqz v9, :cond_a

    iput-object v9, v5, Llyiahf/vczjk/sf3;->OooOOO0:Llyiahf/vczjk/g5a;

    sget-object v9, Llyiahf/vczjk/qd4;->OooO0oO:Ljava/util/LinkedHashSet;

    invoke-static {v4, v8}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v4

    invoke-static {v0, v4}, Llyiahf/vczjk/t51;->OoooOoO(Llyiahf/vczjk/by0;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    invoke-interface {v9, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_9

    iget-object v4, p0, Llyiahf/vczjk/nd4;->OooOOo:Llyiahf/vczjk/o45;

    sget-object v9, Llyiahf/vczjk/nd4;->OooOo00:[Llyiahf/vczjk/th4;

    const/4 v10, 0x2

    aget-object v9, v9, v10

    invoke-static {v4, v9}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ko;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/sf3;->OooOOo0(Llyiahf/vczjk/ko;)Llyiahf/vczjk/qf3;

    :cond_9
    iget-object v4, v5, Llyiahf/vczjk/sf3;->Oooo0O0:Llyiahf/vczjk/tf3;

    invoke-virtual {v4, v5}, Llyiahf/vczjk/tf3;->o0000O(Llyiahf/vczjk/sf3;)Llyiahf/vczjk/tf3;

    move-result-object v4

    const-string v5, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ClassConstructorDescriptor"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v4, Llyiahf/vczjk/ux0;

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_a
    const/16 p1, 0x25

    invoke-static {p1}, Llyiahf/vczjk/sf3;->OooO00o(I)V

    throw v6

    :cond_b
    return-object v1

    :cond_c
    :goto_3
    return-object v2
.end method

.method public final o00ooo(Llyiahf/vczjk/by0;)Ljava/util/Collection;
    .locals 5

    const/4 v0, 0x1

    const/4 v1, 0x0

    const-string v2, "classDescriptor"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/p72;->OooO0oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object p1

    sget-object v2, Llyiahf/vczjk/qd4;->OooO00o:Ljava/util/LinkedHashSet;

    sget-object v2, Llyiahf/vczjk/w09;->OooO0oO:Llyiahf/vczjk/ic3;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/ic3;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_1

    sget-object v3, Llyiahf/vczjk/w09;->Oooooo0:Ljava/util/HashMap;

    invoke-virtual {v3, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-eqz v3, :cond_0

    goto :goto_0

    :cond_0
    move v3, v1

    goto :goto_1

    :cond_1
    :goto_0
    move v3, v0

    :goto_1
    iget-object v4, p0, Llyiahf/vczjk/nd4;->OooOOOO:Llyiahf/vczjk/dp8;

    if-eqz v3, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/nd4;->OooOOOo:Llyiahf/vczjk/o45;

    sget-object v2, Llyiahf/vczjk/nd4;->OooOo00:[Llyiahf/vczjk/th4;

    aget-object v2, v2, v0

    invoke-static {p1, v2}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dp8;

    const/4 v2, 0x2

    new-array v2, v2, [Llyiahf/vczjk/uk4;

    aput-object p1, v2, v1

    aput-object v4, v2, v0

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :cond_2
    invoke-virtual {p1, v2}, Llyiahf/vczjk/ic3;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_5

    sget-object v2, Llyiahf/vczjk/w09;->Oooooo0:Ljava/util/HashMap;

    invoke-virtual {v2, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_3

    goto :goto_2

    :cond_3
    sget-object v0, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    invoke-static {p1}, Llyiahf/vczjk/w64;->OooO0o(Llyiahf/vczjk/ic3;)Llyiahf/vczjk/hy0;

    move-result-object p1

    if-nez p1, :cond_4

    :catch_0
    move v0, v1

    goto :goto_2

    :cond_4
    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object p1, p1, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    invoke-static {p1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    const-class v0, Ljava/io/Serializable;

    invoke-virtual {v0, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    :cond_5
    :goto_2
    if-eqz v0, :cond_6

    invoke-static {v4}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    goto :goto_3

    :cond_6
    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :goto_3
    return-object p1
.end method
